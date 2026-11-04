package engine

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/taotecode/bercert/internal/certutil"
	"github.com/taotecode/bercert/internal/config"
	"github.com/taotecode/bercert/internal/panel"
	"github.com/taotecode/bercert/internal/qiniu"
	"github.com/taotecode/bercert/internal/upyun"
)

const (
	DecisionSkip    = "skip"
	DecisionRenew   = "renew"
	DecisionIssue   = "issue"
	DecisionNoCert  = "no-cert"
	DecisionInvalid = "invalid"
)

type State struct {
	Provider string
	Domain   string
	HTTPS    bool
	CertID   string
	NotAfter time.Time
	Note     string
}

type Action struct {
	Provider   string `json:"provider"`
	Domain     string `json:"domain"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	HTTPS      bool   `json:"https"`
	CurrentID  string `json:"current_cert_id,omitempty"`
	CurrentExp string `json:"current_expires,omitempty"`
	TargetID   int    `json:"target_panel_cert_id,omitempty"`
	TargetExp  string `json:"target_expires,omitempty"`
	NewCertID  string `json:"new_cert_id,omitempty"`
	Applied    bool   `json:"applied"`
	Error      string `json:"error,omitempty"`
}

type Engine struct {
	Cfg          *config.Config
	Panel        *panel.Client
	Qiniu        *qiniu.Client
	Upyun        *upyun.Client
	UpyunConsole *upyun.ConsoleClient
	Now          func() time.Time
	Logf         func(format string, args ...any)

	qiniuCertCache []qiniu.Certificate
	qiniuCacheOK   bool
	upyunCertCache map[string]map[string]upyun.Certificate
}

func New(cfg *config.Config) *Engine {
	e := &Engine{
		Cfg:            cfg,
		Panel:          panel.New(cfg.PanelBaseURL, cfg.PanelAPIKey),
		Now:            time.Now,
		Logf:           func(string, ...any) {},
		upyunCertCache: map[string]map[string]upyun.Certificate{},
	}
	if cfg.QiniuEnabled() {
		e.Qiniu = qiniu.New(cfg.QiniuAK, cfg.QiniuSK)
	}
	if cfg.UpyunEnabled() {
		e.Upyun = upyun.New(cfg.UpyunToken)
	}
	if cfg.UpyunUsername != "" && cfg.UpyunPassword != "" {
		e.UpyunConsole = upyun.NewConsole(cfg.UpyunUsername, cfg.UpyunPassword)
	}
	return e
}

func (e *Engine) Scan(ctx context.Context) ([]Action, error) {
	certs, err := e.Panel.ListCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("list 1panel certificates: %w", err)
	}
	now := e.Now()
	var actions []Action

	if e.Qiniu != nil {
		domains, err := e.Qiniu.ListDomains(ctx)
		if err != nil {
			return nil, fmt.Errorf("list qiniu domains: %w", err)
		}
		for _, d := range domains {
			if !e.Cfg.AllowsDomain(d.Name) {
				continue
			}
			st := e.qiniuState(ctx, d)
			actions = append(actions, e.decide(certs, st, now, false))
		}
	}

	if e.Upyun != nil {
		domains, err := e.Upyun.ListDomains(ctx)
		if err != nil {
			return nil, fmt.Errorf("list upyun domains: %w", err)
		}
		for _, d := range domains {
			if !e.Cfg.AllowsDomain(d.Domain) || strings.HasSuffix(d.Domain, ".test.upcdn.net") {
				continue
			}
			st := e.upyunState(ctx, d.Domain)
			actions = append(actions, e.decide(certs, st, now, false))
		}
	}

	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Provider != actions[j].Provider {
			return actions[i].Provider < actions[j].Provider
		}
		return actions[i].Domain < actions[j].Domain
	})
	return actions, nil
}

func (e *Engine) Apply(ctx context.Context, actions []Action, dryRun, force bool) ([]Action, error) {
	out := make([]Action, 0, len(actions))
	for _, a := range actions {
		if a.Decision == DecisionIssue && !dryRun {
			cert, err := e.issueCertificate(ctx, a.Domain)
			if err != nil {
				a.Error = err.Error()
				out = append(out, a)
				continue
			}
			a.TargetID = cert.ID
			a.TargetExp = cert.ExpireDate.UTC().Format(time.RFC3339)
			a.Decision = DecisionRenew
			a.Reason = fmt.Sprintf("issued certificate #%d from 1Panel", cert.ID)
		}
		if a.Decision != DecisionRenew && !force {
			out = append(out, a)
			continue
		}
		if dryRun {
			a.Reason = "dry-run: " + a.Reason
			out = append(out, a)
			continue
		}
		var err error
		switch a.Provider {
		case "qiniu":
			err = e.applyQiniu(ctx, &a)
		case "upyun":
			err = e.applyUpyun(ctx, &a)
		default:
			err = fmt.Errorf("unknown provider %q", a.Provider)
		}
		if err != nil {
			a.Error = err.Error()
		} else {
			a.Applied = true
		}
		out = append(out, a)
	}
	return out, nil
}

func (e *Engine) decide(certs []panel.Certificate, st State, now time.Time, force bool) Action {
	a := Action{
		Provider:  st.Provider,
		Domain:    st.Domain,
		HTTPS:     st.HTTPS,
		CurrentID: st.CertID,
	}
	if !st.NotAfter.IsZero() {
		a.CurrentExp = st.NotAfter.UTC().Format(time.RFC3339)
	}

	target := panel.Find(certs, st.Domain, now)
	if target == nil {
		if e.Cfg.PanelIssueEnabled {
			a.Decision = DecisionIssue
			a.Reason = "no matching certificate in 1Panel; will request one"
		} else {
			a.Decision = DecisionNoCert
			a.Reason = "no valid certificate in 1Panel covers " + st.Domain
		}
		return a
	}
	leaf, err := certutil.Leaf(target.PEM)
	if err != nil {
		a.Decision = DecisionInvalid
		a.Reason = "target 1Panel certificate unreadable: " + err.Error()
		return a
	}
	a.TargetID = target.ID
	a.TargetExp = leaf.NotAfter.UTC().Format(time.RFC3339)

	switch {
	case force:
		a.Decision = DecisionRenew
		a.Reason = "forced renewal"
	case !st.HTTPS:
		a.Decision = DecisionRenew
		a.Reason = "HTTPS is not enabled or no certificate is bound"
	case st.NotAfter.IsZero():
		a.Decision = DecisionRenew
		a.Reason = "current certificate expiry unknown"
		if st.Note != "" {
			a.Reason += ": " + st.Note
		}
	case now.After(st.NotAfter):
		a.Decision = DecisionRenew
		a.Reason = "current certificate expired " + humanSince(now.Sub(st.NotAfter)) + " ago"
	case st.NotAfter.Before(now.Add(e.Cfg.RenewBefore)):
		a.Decision = DecisionRenew
		a.Reason = fmt.Sprintf("current certificate expires in %d days (threshold %d)", int(st.NotAfter.Sub(now).Hours()/24), int(e.Cfg.RenewBefore.Hours()/24))
	case !leaf.NotAfter.After(st.NotAfter):
		a.Decision = DecisionSkip
		a.Reason = "1Panel certificate is not newer than the bound certificate"
	default:
		a.Decision = DecisionSkip
		a.Reason = "certificate healthy"
	}
	return a
}

func (e *Engine) qiniuState(ctx context.Context, d qiniu.Domain) State {
	det, err := e.Qiniu.GetDomain(ctx, d.Name)
	if err != nil {
		return State{Provider: "qiniu", Domain: d.Name, Note: "cannot read domain: " + err.Error()}
	}
	d = *det
	st := State{Provider: "qiniu", Domain: d.Name, HTTPS: d.Protocol == "https", CertID: d.HTTPS.CertID}
	if st.CertID == "" {
		return st
	}
	cert, err := e.Qiniu.GetCertificate(ctx, st.CertID)
	if err != nil {
		st.Note = "cannot read bound certificate: " + err.Error()
		return st
	}
	st.NotAfter = cert.ExpiresAt()
	return st
}

func (e *Engine) upyunState(ctx context.Context, domain string) State {
	st := State{Provider: "upyun", Domain: domain}
	bindings, err := e.Upyun.Bindings(ctx, domain)
	if err != nil {
		st.Note = "cannot read bindings: " + err.Error()
		return st
	}
	for _, b := range bindings {
		if b.HTTPS {
			st.HTTPS = true
			st.CertID = b.CertID
			st.NotAfter = b.NotAfter
			return st
		}
	}
	return st
}

func (e *Engine) applyQiniu(ctx context.Context, a *Action) error {
	if !e.Cfg.QiniuEnabled() {
		return fmt.Errorf("qiniu credentials not configured")
	}
	certs, err := e.Panel.ListCertificates(ctx)
	if err != nil {
		return err
	}
	target := findTargetByID(certs, a.TargetID)
	if target == nil {
		return fmt.Errorf("1Panel certificate %d disappeared", a.TargetID)
	}
	leaf, err := certutil.Validate(target.PEM, target.PrivateKey, a.Domain, e.Now())
	if err != nil {
		return fmt.Errorf("target certificate invalid: %w", err)
	}

	d, err := e.Qiniu.GetDomain(ctx, a.Domain)
	if err != nil {
		return err
	}

	certID, err := e.qiniuReuseOrUpload(ctx, a.Domain, target, leaf.NotAfter)
	if err != nil {
		return err
	}
	a.NewCertID = certID

	if err := e.Qiniu.BindCertificate(ctx, d, certID, e.Cfg.QiniuForceHTTPS, e.Cfg.QiniuHTTP2, e.Cfg.QiniuTLS); err != nil {
		return err
	}

	after, err := e.Qiniu.GetDomain(ctx, a.Domain)
	if err != nil {
		return fmt.Errorf("bind reported success but verification failed: %w", err)
	}
	if after.HTTPS.CertID != certID {
		return fmt.Errorf("verification failed: domain reports cert %q, expected %q", after.HTTPS.CertID, certID)
	}
	a.HTTPS = true
	a.CurrentID = certID
	a.CurrentExp = leaf.NotAfter.UTC().Format(time.RFC3339)
	a.Reason = "certificate uploaded and bound to qiniu domain"
	return nil
}

func (e *Engine) qiniuReuseOrUpload(ctx context.Context, domain string, target *panel.Certificate, notAfter time.Time) (string, error) {
	if !e.qiniuCacheOK {
		certs, err := e.Qiniu.ListCertificates(ctx)
		if err != nil {
			return "", err
		}
		e.qiniuCertCache = certs
		e.qiniuCacheOK = true
	}
	for _, c := range e.qiniuCertCache {
		if absDur(c.ExpiresAt().Sub(notAfter)) <= time.Second && certutil.Covers(c.DNSNames, domain) {
			return c.ID, nil
		}
	}
	name := fmt.Sprintf("%s-%s", domain, e.Now().Format("20060102"))
	id, err := e.Qiniu.UploadCertificate(ctx, name, target.PrivateKey, target.PEM)
	if err != nil {
		return "", fmt.Errorf("upload certificate: %w", err)
	}
	e.qiniuCertCache = append(e.qiniuCertCache, qiniu.Certificate{
		ID: id, CommonName: domain, DNSNames: []string{domain}, NotAfter: notAfter.Unix(),
	})
	return id, nil
}

func (e *Engine) applyUpyun(ctx context.Context, a *Action) error {
	if e.Upyun == nil && e.UpyunConsole == nil {
		return fmt.Errorf("upyun credentials not configured")
	}
	certs, err := e.Panel.ListCertificates(ctx)
	if err != nil {
		return err
	}
	target := findTargetByID(certs, a.TargetID)
	if target == nil {
		return fmt.Errorf("1Panel certificate %d disappeared", a.TargetID)
	}
	leaf, err := certutil.Validate(target.PEM, target.PrivateKey, a.Domain, e.Now())
	if err != nil {
		return fmt.Errorf("target certificate invalid: %w", err)
	}

	certID, err := e.upyunCert(ctx, a.Domain, target, leaf.NotAfter)
	if err != nil {
		return err
	}
	a.NewCertID = certID

	if e.UpyunConsole != nil {
		if err := e.UpyunConsole.BindCertificate(ctx, a.Domain, certID, true, e.Cfg.UpyunForceHTTPS, e.Cfg.UpyunSourceHTTPS); err != nil {
			return err
		}
	} else if err := e.Upyun.BindCertificate(ctx, a.Domain, certID, true, e.Cfg.UpyunForceHTTPS, e.Cfg.UpyunSourceHTTPS); err != nil {
		return err
	}

	var bindings []upyun.Binding
	if e.Upyun != nil {
		bindings, err = e.Upyun.Bindings(ctx, a.Domain)
	} else {
		bindings, err = e.UpyunConsole.Bindings(ctx, a.Domain)
	}
	if err != nil {
		return fmt.Errorf("bind reported success but verification failed: %w", err)
	}
	ok := slices.ContainsFunc(bindings, func(b upyun.Binding) bool { return b.HTTPS && b.CertID == certID })
	if !ok {
		return fmt.Errorf("verification failed: domain does not report certificate %q as active", certID)
	}
	a.HTTPS = true
	a.CurrentID = certID
	a.CurrentExp = leaf.NotAfter.UTC().Format(time.RFC3339)
	a.Reason = "certificate uploaded and bound to upyun domain"
	return nil
}

func (e *Engine) upyunCert(ctx context.Context, domain string, target *panel.Certificate, notAfter time.Time) (string, error) {
	if e.Upyun != nil {
		list, ok := e.upyunCertCache[domain]
		if !ok {
			var err error
			list, err = e.Upyun.ListCertificates(ctx, domain)
			if err != nil {
				return "", err
			}
			e.upyunCertCache[domain] = list
		}
		for id, c := range list {
			if absDur(c.NotAfter.Sub(notAfter)) <= time.Second && certutil.Covers([]string{c.CommonName}, domain) {
				return id, nil
			}
		}
	}

	name := fmt.Sprintf("%s-%s", domain, e.Now().Format("20060102"))
	var (
		id  string
		err error
	)
	if e.UpyunConsole != nil {
		id, err = e.UpyunConsole.UploadCertificate(ctx, target.PEM, target.PrivateKey, name)
	} else {
		id, err = e.Upyun.UploadCertificate(ctx, target.PEM, target.PrivateKey, name)
	}
	if err != nil {
		return "", fmt.Errorf("upload certificate: %w", err)
	}
	if e.upyunCertCache[domain] == nil {
		e.upyunCertCache[domain] = map[string]upyun.Certificate{}
	}
	e.upyunCertCache[domain][id] = upyun.Certificate{ID: id, CommonName: domain, NotAfter: notAfter}
	return id, nil
}

func findTargetByID(certs []panel.Certificate, id int) *panel.Certificate {
	for i := range certs {
		if certs[i].ID == id {
			return &certs[i]
		}
	}
	return nil
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (e *Engine) issueCertificate(ctx context.Context, domain string) (*panel.Certificate, error) {
	domain = certutil.NormalizeDomain(domain)
	certs, err := e.Panel.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	var existing *panel.Certificate
	for i := range certs {
		c := &certs[i]
		if certutil.NormalizeDomain(c.PrimaryDomain) != domain {
			continue
		}
		if existing == nil || c.ID > existing.ID {
			existing = c
		}
	}
	if existing != nil && existing.Status == "ready" && existing.PEM != "" && existing.PrivateKey != "" {
		leaf, err := certutil.Leaf(existing.PEM)
		if err == nil && certutil.Covers(leaf.DNSNames, domain) && e.Now().Before(leaf.NotAfter) {
			return existing, nil
		}
	}

	id := 0
	if existing != nil {
		id = existing.ID
		e.Logf("1Panel certificate #%d for %s is %q; retrying issuance", id, domain, existing.Status)
	} else {
		acmeID, dnsID, err := e.issueAccounts(ctx)
		if err != nil {
			return nil, err
		}
		id, err = e.Panel.CreateCertificate(ctx, panel.CreateCertificateRequest{
			PrimaryDomain: domain,
			Provider:      e.Cfg.PanelIssueProvider,
			AcmeAccountID: acmeID,
			DNSAccountID:  dnsID,
			AutoRenew:     e.Cfg.PanelCertAutoRenew,
			KeyType:       e.Cfg.PanelKeyType,
			Description:   "managed by bercert",
		})
		if err != nil {
			return nil, fmt.Errorf("create certificate in 1Panel: %w", err)
		}
		e.Logf("1Panel certificate #%d requested for %s", id, domain)
	}

	retries := e.Cfg.PanelIssueRetries
	unlimited := retries <= 0
	var last error
	for attempt := 1; unlimited || attempt <= retries; attempt++ {
		cert, err := e.waitCertificate(ctx, id, e.Cfg.PanelIssueTimeout)
		if err == nil {
			e.Logf("1Panel certificate #%d for %s is ready", id, domain)
			return cert, nil
		}
		last = err
		if !unlimited && attempt == retries {
			break
		}
		e.Logf("1Panel issuance #%d for %s failed (attempt %d): %v; retrying", id, domain, attempt, err)
		if err := e.Panel.ObtainCertificate(ctx, id); err != nil {
			e.Logf("retry trigger for certificate #%d returned: %v", id, err)
		}
		if err := sleepCtx(ctx, e.Cfg.PanelIssueRetryDelay); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("1Panel could not issue %s: %w", domain, last)
}

func (e *Engine) waitCertificate(ctx context.Context, id int, timeout time.Duration) (*panel.Certificate, error) {
	deadline := e.Now().Add(timeout)
	for {
		cert, err := e.Panel.GetCertificate(ctx, id)
		if err != nil {
			return nil, err
		}
		switch cert.Status {
		case "ready":
			if cert.PEM == "" || cert.PrivateKey == "" {
				return nil, fmt.Errorf("certificate #%d is ready but has no PEM/private key", id)
			}
			return cert, nil
		case "error", "applyError":
			return nil, fmt.Errorf("1Panel issuance failed: %s", cert.Message)
		}
		if e.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for certificate #%d (status %q): %s", id, cert.Status, cert.Message)
		}
		if err := sleepCtx(ctx, 5*time.Second); err != nil {
			return nil, err
		}
	}
}

func (e *Engine) issueAccounts(ctx context.Context) (uint, uint, error) {
	acmeID := e.Cfg.PanelAcmeAccountID
	dnsID := e.Cfg.PanelDNSAccountID
	if acmeID == 0 {
		accounts, err := e.Panel.SearchACMEAccounts(ctx)
		if err != nil {
			return 0, 0, err
		}
		if len(accounts) == 0 {
			return 0, 0, fmt.Errorf("1Panel has no ACME account; create one or set PANEL_ACME_ACCOUNT_ID")
		}
		acmeID = accounts[0].ID
	}
	if e.Cfg.PanelIssueProvider == "dnsAccount" && dnsID == 0 {
		accounts, err := e.Panel.SearchDNSAccounts(ctx)
		if err != nil {
			return 0, 0, err
		}
		if len(accounts) == 0 {
			return 0, 0, fmt.Errorf("1Panel has no DNS account; create one or set PANEL_DNS_ACCOUNT_ID")
		}
		dnsID = accounts[0].ID
	}
	return acmeID, dnsID, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func humanSince(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days >= 1 {
		return fmt.Sprintf("%d days", days)
	}
	return d.Round(time.Minute).String()
}
