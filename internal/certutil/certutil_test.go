package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestMatchesName(t *testing.T) {
	cases := []struct {
		pattern, domain string
		want            bool
	}{
		{"cdn.example.com", "cdn.example.com", true},
		{"CDN.Example.COM.", "cdn.example.com", true},
		{"*.example.com", "cdn.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"cdn.example.com", "other.example.com", false},
		{"*.example.com", "a.b.example.com", false},
	}
	for _, c := range cases {
		if got := MatchesName(c.pattern, c.domain); got != c.want {
			t.Errorf("MatchesName(%q,%q)=%v want %v", c.pattern, c.domain, got, c.want)
		}
	}
}

func TestSpecificity(t *testing.T) {
	if Specificity("cdn.example.com", "cdn.example.com") != 1000 {
		t.Fatal("exact match should rank highest")
	}
	if a, b := Specificity("*.example.com", "a.cdn.example.com"), Specificity("*.cdn.example.com", "a.cdn.example.com"); a >= b {
		t.Fatalf("longer wildcard should rank higher: %d vs %d", a, b)
	}
}

func TestParseChainAndPair(t *testing.T) {
	certPEM, keyPEM, leaf := selfSigned(t, []string{"cdn.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	chain, err := ParseChain(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || !chain[0].NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("unexpected chain: %+v", chain)
	}
	if err := CheckPair(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(certPEM, keyPEM, "cdn.example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(certPEM, keyPEM, "other.example.com", time.Now()); err == nil {
		t.Fatal("expected SAN mismatch")
	}
	if _, err := Validate(certPEM, keyPEM, "cdn.example.com", time.Now().Add(91*24*time.Hour)); err == nil {
		t.Fatal("expected expired error")
	}
}

func selfSigned(t *testing.T, dns []string, from, to time.Time) (certPEM, keyPEM string, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dns[0]},
		DNSNames:     dns,
		NotBefore:    from,
		NotAfter:     to,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, leaf
}
