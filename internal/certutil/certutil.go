package certutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// ParseChain returns every certificate in the PEM bundle, leaf first.
func ParseChain(data string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := []byte(data)
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found")
	}
	return chain, nil
}

func Leaf(data string) (*x509.Certificate, error) {
	chain, err := ParseChain(data)
	if err != nil {
		return nil, err
	}
	return chain[0], nil
}

func CheckPair(certPEM, keyPEM string) error {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("certificate and private key do not match: %w", err)
	}
	return nil
}

// Validate ensures the bundle is a usable chain whose leaf covers domain.
func Validate(certPEM, keyPEM, domain string, now time.Time) (*x509.Certificate, error) {
	if err := CheckPair(certPEM, keyPEM); err != nil {
		return nil, err
	}
	leaf, err := Leaf(certPEM)
	if err != nil {
		return nil, err
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate not valid before %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if !Covers(leaf.DNSNames, domain) {
		return nil, fmt.Errorf("certificate SAN %v does not cover %s", leaf.DNSNames, domain)
	}
	return leaf, nil
}

func Covers(dnsNames []string, domain string) bool {
	domain = NormalizeDomain(domain)
	for _, raw := range dnsNames {
		if MatchesName(raw, domain) {
			return true
		}
	}
	return false
}

func MatchesName(pattern, domain string) bool {
	pattern = NormalizeDomain(pattern)
	domain = NormalizeDomain(domain)
	if pattern == domain {
		return true
	}
	suffix, ok := strings.CutPrefix(pattern, "*.")
	if !ok || suffix == "" {
		return false
	}
	rest, ok := strings.CutSuffix(domain, "."+suffix)
	if !ok || rest == "" {
		return false
	}
	return !strings.Contains(rest, ".")
}

func NormalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// ECKeyForUpyun converts a PKCS#8 ECDSA key into the SEC1 form Upyun requires
// ("BEGIN EC PRIVATE KEY"). RSA and already-SEC1 keys are returned unchanged.
func ECKeyForUpyun(keyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return "", fmt.Errorf("no private key PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		return keyPEM, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return keyPEM, nil
	}
	der, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		return "", fmt.Errorf("marshal EC private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// ProbeTLS returns the leaf certificate the domain's edge currently serves.
func ProbeTLS(ctx context.Context, domain string, timeout time.Duration) (*x509.Certificate, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{ServerName: NormalizeDomain(domain), InsecureSkipVerify: true},
	}
	conn, err := d.DialContext(ctx, "tcp", NormalizeDomain(domain)+":443")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("edge returned no certificate")
	}
	return state.PeerCertificates[0], nil
}

// Specificity ranks an exact match above any wildcard and longer wildcards above shorter ones.
func Specificity(pattern, domain string) int {
	pattern = NormalizeDomain(pattern)
	domain = NormalizeDomain(domain)
	if pattern == domain {
		return 1000
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok && MatchesName(pattern, domain) {
		return len(suffix)
	}
	return -1
}
