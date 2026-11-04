package qiniu

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthorizationMatchesSentDate(t *testing.T) {
	fixed := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	c := New("ak", "sk")
	c.Now = func() time.Time { return fixed }

	got := c.authorization("PUT", apiHost, "/domain/test.example.com/cache",
		[]byte(`{"a":1}`), "20260213T120000Z")
	wantData := "PUT /domain/test.example.com/cache\nHost: api.qiniu.com\nContent-Type: application/json\nX-Qiniu-Date: 20260213T120000Z\n\n{\"a\":1}"
	if !strings.HasSuffix(got, ":"+urlsafeHMAC(wantData, "sk")) {
		t.Fatalf("authorization does not sign the expected request representation: %s", got)
	}
	if !strings.HasPrefix(got, "Qiniu ak:") {
		t.Fatalf("unexpected scheme: %s", got)
	}
}

func TestQBoxSignsPathOnly(t *testing.T) {
	c := New("ak", "sk")
	got := c.authorization("GET", fusionHost, "/sslcert?limit=10&marker=", nil, "")
	want := "QBox ak:" + base64.URLEncoding.EncodeToString(hmacSHA1("/sslcert?limit=10&marker=\n", "sk"))
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestListDomainsAndCertificates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/domain":
			_, _ = w.Write([]byte(`{"domains":[{"name":"cdn.example.com","protocol":"https"}]}`))
		case r.URL.Path == "/domain/cdn.example.com":
			_, _ = w.Write([]byte(`{"name":"cdn.example.com","protocol":"https","https":{"certId":"cert123"}}`))
		case r.URL.Path == "/sslcert/cert123":
			_, _ = w.Write([]byte(`{"code":0,"cert":{"certid":"cert123","name":"old","not_after":1764892799}}`))
		case r.URL.Path == "/sslcert":
			_, _ = w.Write([]byte(`{"code":0,"certs":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New("ak", "sk")
	c.APIBase, c.FusionBase = srv.URL, srv.URL

	doms, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(doms) != 1 || doms[0].Name != "cdn.example.com" {
		t.Fatalf("unexpected domains: %+v", doms)
	}
	d, err := c.GetDomain(context.Background(), "cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.HTTPS.CertID != "cert123" {
		t.Fatalf("certId = %q", d.HTTPS.CertID)
	}
	cert, err := c.GetCertificate(context.Background(), "cert123")
	if err != nil {
		t.Fatal(err)
	}
	if cert.ExpiresAt().UTC().Format("2006-01-02") != "2025-12-04" {
		t.Fatalf("expiry = %s", cert.ExpiresAt())
	}
}

func TestUploadAndBind(t *testing.T) {
	var gotAuth string
	var bindBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/sslcert" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"certID":"newcert"}`))
		case r.URL.Path == "/domain/cdn.example.com/httpsconf":
			_ = json.NewDecoder(r.Body).Decode(&bindBody)
			_, _ = w.Write([]byte(`{"code":200}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New("ak", "sk")
	c.APIBase, c.FusionBase = srv.URL, srv.URL

	id, err := c.UploadCertificate(context.Background(), "n", "pri", "ca")
	if err != nil || id != "newcert" {
		t.Fatalf("upload: id=%q err=%v", id, err)
	}
	if !strings.HasPrefix(gotAuth, "QBox ak:") {
		t.Fatalf("cert upload must use QBox, got %s", gotAuth)
	}
	d := &Domain{Name: "cdn.example.com", Protocol: "https"}
	if err := c.BindCertificate(context.Background(), d, "newcert", false, true, "TLSv1.1/TLSv1.2"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotAuth, "Qiniu ak:") {
		t.Fatalf("binding must use Qiniu auth, got %s", gotAuth)
	}
	versions, ok := bindBody["tlsVersions"].([]any)
	if !ok || len(versions) != 2 {
		t.Fatalf("tlsVersions must be a JSON array, got %#v", bindBody["tlsVersions"])
	}
}

func hmacSHA1(data, key string) []byte {
	m := hmac.New(sha1.New, []byte(key))
	m.Write([]byte(data))
	return m.Sum(nil)
}
