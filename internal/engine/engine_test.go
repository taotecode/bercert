package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/taotecode/bercert/internal/certutil"
	"github.com/taotecode/bercert/internal/config"
	"github.com/taotecode/bercert/internal/panel"
)

func TestDecide(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	certPEM, keyPEM := testCert(t, "cdn.example.com", now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	certs := []panel.Certificate{{
		ID:         7,
		PEM:        certPEM,
		PrivateKey: keyPEM,
		ExpireDate: now.Add(365 * 24 * time.Hour),
	}}
	e := &Engine{Cfg: &config.Config{RenewBefore: 30 * 24 * time.Hour}, Now: func() time.Time { return now }}

	cases := []struct {
		name      string
		state     State
		want      string
		wantCause string
	}{
		{
			name:  "expired bound certificate",
			state: State{Provider: "qiniu", Domain: "cdn.example.com", HTTPS: true, CertID: "old", NotAfter: now.Add(-100 * 24 * time.Hour)},
			want:  DecisionRenew,
		},
		{
			name:  "expiring within threshold",
			state: State{Provider: "qiniu", Domain: "cdn.example.com", HTTPS: true, CertID: "old", NotAfter: now.Add(20 * 24 * time.Hour)},
			want:  DecisionRenew,
		},
		{
			name:  "healthy",
			state: State{Provider: "qiniu", Domain: "cdn.example.com", HTTPS: true, CertID: "old", NotAfter: now.Add(200 * 24 * time.Hour)},
			want:  DecisionSkip,
		},
		{
			name:  "no https",
			state: State{Provider: "upyun", Domain: "cdn.example.com"},
			want:  DecisionRenew,
		},
		{
			name:  "no matching panel cert",
			state: State{Provider: "upyun", Domain: "uncovered.example.net", HTTPS: true, CertID: "old", NotAfter: now.Add(-time.Hour)},
			want:  DecisionNoCert,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := e.decide(certs, c.state, now, false)
			if a.Decision != c.want {
				t.Fatalf("decision = %s (%s), want %s", a.Decision, a.Reason, c.want)
			}
		})
	}
}

func TestDecideIssueWhenEnabled(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	certPEM, keyPEM := testCert(t, "cdn.example.com", now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	certs := []panel.Certificate{{ID: 7, PEM: certPEM, PrivateKey: keyPEM}}
	e := &Engine{Cfg: &config.Config{RenewBefore: 30 * 24 * time.Hour, PanelIssueEnabled: true}, Now: func() time.Time { return now }}

	a := e.decide(certs, State{Provider: "upyun", Domain: "uncovered.example.net"}, now, false)
	if a.Decision != DecisionIssue {
		t.Fatalf("decision = %s (%s), want issue", a.Decision, a.Reason)
	}
}

func TestDecideEdgeCheck(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	certPEM, keyPEM := testCert(t, "cdn.example.com", now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	certs := []panel.Certificate{{ID: 7, PEM: certPEM, PrivateKey: keyPEM}}
	healthy := State{Provider: "upyun", Domain: "cdn.example.com", HTTPS: true, CertID: "old", NotAfter: now.Add(365 * 24 * time.Hour)}

	e := &Engine{
		Cfg: &config.Config{VerifyTLS: true, TLSProbeTimeout: time.Second},
		Now: func() time.Time { return now },
		Probe: func(context.Context, string, time.Duration) (*x509.Certificate, error) {
			return nil, errors.New("remote error: tls: handshake failure")
		},
	}
	a := e.decide(certs, healthy, now, false)
	e.applyEdgeCheck(context.Background(), &a, healthy)
	if a.Decision != DecisionManual {
		t.Fatalf("decision = %s (%s), want edge-error", a.Decision, a.Reason)
	}

	e.Probe = func(context.Context, string, time.Duration) (*x509.Certificate, error) {
		leaf, _ := certutil.Leaf(certPEM)
		return leaf, nil
	}
	a = e.decide(certs, healthy, now, false)
	e.applyEdgeCheck(context.Background(), &a, healthy)
	if a.Decision != DecisionSkip {
		t.Fatalf("decision = %s (%s), want skip", a.Decision, a.Reason)
	}
}

func TestDecideTargetNotNewer(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	certPEM, keyPEM := testCert(t, "cdn.example.com", now.Add(-24*time.Hour), now.Add(60*24*time.Hour))
	certs := []panel.Certificate{{ID: 7, PEM: certPEM, PrivateKey: keyPEM}}
	e := &Engine{Cfg: &config.Config{RenewBefore: 30 * 24 * time.Hour}, Now: func() time.Time { return now }}

	a := e.decide(certs, State{Provider: "qiniu", Domain: "cdn.example.com", HTTPS: true, CertID: "old", NotAfter: now.Add(90 * 24 * time.Hour)}, now, false)
	if a.Decision != DecisionSkip {
		t.Fatalf("expected skip, got %s: %s", a.Decision, a.Reason)
	}
}

func testCert(t *testing.T, dns string, from, to time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dns},
		DNSNames:     []string{dns},
		NotBefore:    from,
		NotAfter:     to,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}
