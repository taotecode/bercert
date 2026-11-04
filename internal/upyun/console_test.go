package upyun

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleUploadAndBind(t *testing.T) {
	var signedIn bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/signin/":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["username"] != "u" || body["password"] != "p" {
				t.Errorf("unexpected login body: %+v", body)
			}
			signedIn = true
			_, _ = w.Write([]byte(`{"data":{"result":true}}`))
		case "/api/https/certificate/":
			if !signedIn {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"result":{"certificate_id":"cert9"}}}`))
		case "/api/https/certificate/manager/":
			_, _ = w.Write([]byte(`{"data":{"result":true}}`))
		case "/api/https/services/manager":
			_, _ = w.Write([]byte(`{"data":{"result":[{"certificate_id":"cert9","https":true,"validity":{"end":1800000000000}}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewConsole("u", "p")
	c.BaseURL = srv.URL

	id, err := c.UploadCertificate(context.Background(), "pem", "key", "name")
	if err != nil || id != "cert9" {
		t.Fatalf("upload: id=%q err=%v", id, err)
	}
	if err := c.BindCertificate(context.Background(), "cdn.example.com", id, true, false, false); err != nil {
		t.Fatal(err)
	}
	bindings, err := c.Bindings(context.Background(), "cdn.example.com")
	if err != nil || len(bindings) != 1 || !bindings[0].HTTPS || bindings[0].CertID != "cert9" {
		t.Fatalf("bindings: %+v err=%v", bindings, err)
	}
}

func TestConsoleMigrateOn21713(t *testing.T) {
	var migrated bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/signin/":
			_, _ = w.Write([]byte(`{"data":{"result":true}}`))
		case "/api/https/certificate/manager/":
			_, _ = w.Write([]byte(`{"data":{"error_code":21713,"message":"migrate required"}}`))
		case "/api/https/migrate/domain":
			migrated = true
			_, _ = w.Write([]byte(`{"data":{"result":true}}`))
		}
	}))
	defer srv.Close()

	c := NewConsole("u", "p")
	c.BaseURL = srv.URL
	if err := c.BindCertificate(context.Background(), "cdn.example.com", "cert9", true, false, false); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected migrate call on 21713")
	}
}
