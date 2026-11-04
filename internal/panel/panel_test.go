package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssueFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/websites/ssl" && r.Method == http.MethodPost:
			var req CreateCertificateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Provider != "dnsAccount" || req.AcmeAccountID == 0 || req.DNSAccountID == 0 {
				t.Errorf("unexpected create request: %+v", req)
			}
			_, _ = w.Write([]byte(`{"code":200,"data":{"id":7}}`))
		case r.URL.Path == "/api/v2/websites/ssl/obtain":
			_, _ = w.Write([]byte(`{"code":200}`))
		case r.URL.Path == "/api/v2/websites/ssl/7":
			_, _ = w.Write([]byte(`{"code":200,"data":{"id":7,"primaryDomain":"cdn.example.com","status":"ready","pem":"pem","privateKey":"key","expireDate":"2027-01-26T23:59:59Z"}}`))
		case r.URL.Path == "/api/v2/websites/acme/search":
			_, _ = w.Write([]byte(`{"code":200,"data":{"items":[{"id":3,"type":"zerossl"}]}}`))
		case r.URL.Path == "/api/v2/websites/dns/search":
			_, _ = w.Write([]byte(`{"code":200,"data":{"items":[{"id":1,"type":"TencentCloud"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "key")
	id, err := c.CreateCertificate(context.Background(), CreateCertificateRequest{
		PrimaryDomain: "cdn.example.com",
		Provider:      "dnsAccount",
		AcmeAccountID: 3,
		DNSAccountID:  1,
		KeyType:       "EC256",
	})
	if err != nil || id != 7 {
		t.Fatalf("create: id=%d err=%v", id, err)
	}
	if err := c.ObtainCertificate(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	cert, err := c.GetCertificate(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != "ready" || !strings.Contains(cert.PEM, "pem") {
		t.Fatalf("unexpected certificate: %+v", cert)
	}

	acme, err := c.SearchACMEAccounts(context.Background())
	if err != nil || len(acme) != 1 || acme[0].Type != "zerossl" {
		t.Fatalf("acme: %+v err=%v", acme, err)
	}
	dns, err := c.SearchDNSAccounts(context.Background())
	if err != nil || len(dns) != 1 || dns[0].ID != 1 {
		t.Fatalf("dns: %+v err=%v", dns, err)
	}
}
