package config

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	PanelBaseURL string
	PanelAPIKey  string

	PanelIssueEnabled    bool
	PanelAcmeAccountID   uint
	PanelDNSAccountID    uint
	PanelKeyType         string
	PanelIssueProvider   string
	PanelCertAutoRenew   bool
	PanelIssueTimeout    time.Duration
	PanelIssueRetries    int
	PanelIssueRetryDelay time.Duration

	QiniuAK string
	QiniuSK string

	UpyunToken    string
	UpyunUsername string
	UpyunPassword string

	RenewBefore     time.Duration
	VerifyTLS       bool
	TLSProbeTimeout time.Duration
	EdgeWaitTimeout time.Duration

	QiniuForceHTTPS bool
	QiniuHTTP2      bool
	QiniuTLS        string

	UpyunForceHTTPS     bool
	UpyunSourceHTTPS    bool
	UpyunMigrateTimeout time.Duration

	IncludeDomains []string
	ExcludeDomains []string
}

func Load(envFile string) (*Config, error) {
	if envFile != "" {
		if err := loadEnvFile(envFile); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}

	c := &Config{
		PanelBaseURL:         strings.TrimRight(os.Getenv("PANEL_BASE_URL"), "/"),
		PanelAPIKey:          os.Getenv("PANEL_API_KEY"),
		PanelIssueEnabled:    envBool("PANEL_ISSUE_CERT", false),
		PanelAcmeAccountID:   envUint("PANEL_ACME_ACCOUNT_ID"),
		PanelDNSAccountID:    envUint("PANEL_DNS_ACCOUNT_ID"),
		PanelKeyType:         envString("PANEL_KEY_TYPE", "EC256"),
		PanelIssueProvider:   envString("PANEL_ISSUE_PROVIDER", "dnsAccount"),
		PanelCertAutoRenew:   envBool("PANEL_CERT_AUTO_RENEW", true),
		PanelIssueTimeout:    envDuration("PANEL_ISSUE_TIMEOUT", 15*time.Minute),
		PanelIssueRetries:    envInt("PANEL_ISSUE_RETRIES", 3),
		PanelIssueRetryDelay: envDuration("PANEL_ISSUE_RETRY_DELAY", 2*time.Minute),
		QiniuAK:              os.Getenv("QINIU_AK"),
		QiniuSK:              os.Getenv("QINIU_SK"),
		UpyunToken:           os.Getenv("UPYUN_TOKEN"),
		UpyunUsername:        os.Getenv("UPYUN_USERNAME"),
		UpyunPassword:        os.Getenv("UPYUN_PASSWORD"),
		RenewBefore:          30 * 24 * time.Hour,
		VerifyTLS:            envBool("VERIFY_TLS", false),
		TLSProbeTimeout:      envDuration("TLS_PROBE_TIMEOUT", 10*time.Second),
		EdgeWaitTimeout:      envDuration("EDGE_WAIT_TIMEOUT", 10*time.Minute),
		QiniuForceHTTPS:      envBool("QINIU_FORCE_HTTPS", false),
		QiniuHTTP2:           envBool("QINIU_HTTP2", true),
		QiniuTLS:             envString("QINIU_TLS_VERSIONS", "TLSv1.1/TLSv1.2/TLSv1.3"),
		UpyunForceHTTPS:      envBool("UPYUN_FORCE_HTTPS", false),
		UpyunSourceHTTPS:     envBool("UPYUN_SOURCE_HTTPS", false),
		UpyunMigrateTimeout:  envDuration("UPYUN_MIGRATE_TIMEOUT", 10*time.Minute),
		IncludeDomains:       splitList(os.Getenv("INCLUDE_DOMAINS")),
		ExcludeDomains:       splitList(os.Getenv("EXCLUDE_DOMAINS")),
	}

	if v := os.Getenv("RENEW_BEFORE_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("RENEW_BEFORE_DAYS must be a non-negative integer, got %q", v)
		}
		c.RenewBefore = time.Duration(n) * 24 * time.Hour
	}

	if c.PanelBaseURL == "" {
		return nil, fmt.Errorf("PANEL_BASE_URL is required")
	}
	if c.PanelAPIKey == "" {
		return nil, fmt.Errorf("PANEL_API_KEY is required")
	}
	return c, nil
}

func (c *Config) QiniuEnabled() bool { return c.QiniuAK != "" && c.QiniuSK != "" }

func (c *Config) UpyunEnabled() bool {
	return c.UpyunToken != "" || (c.UpyunUsername != "" && c.UpyunPassword != "")
}

func (c *Config) AllowsDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if slices.Contains(c.ExcludeDomains, domain) {
		return false
	}
	if len(c.IncludeDomains) == 0 {
		return true
	}
	return slices.Contains(c.IncludeDomains, domain)
}

func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
	return s.Err()
}

func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envString(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envUint(key string) uint {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0
	}
	return uint(n)
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
