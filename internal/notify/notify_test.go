package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookChannelsAndDedup(t *testing.T) {
	var feishuBody, wecomBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/feishu":
			_ = json.NewDecoder(r.Body).Decode(&feishuBody)
			_, _ = w.Write([]byte(`{"code":0}`))
		case "/wecom":
			_ = json.NewDecoder(r.Body).Decode(&wecomBody)
			_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	n := New(Config{
		Enabled:       true,
		FeishuWebhook: srv.URL + "/feishu",
		FeishuSecret:  "secret",
		WeComWebhook:  srv.URL + "/wecom",
		StateFile:     t.TempDir() + "/state.json",
	})
	ev := Event{
		Provider:   "upyun",
		Domain:     "cdn.example.com",
		Kind:       "failed",
		Decision:   "manual",
		Reason:     "edge TLS handshake failed",
		CertID:     "cert1",
		CertExpiry: "2027-01-26",
		Prepared:   true,
	}
	sent, err := n.Send(context.Background(), []Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	if sent != 2 {
		t.Fatalf("sent = %d, want 2", sent)
	}

	ftext, _ := feishuBody["msg_type"].(string)
	if ftext != "text" {
		t.Fatalf("feishu payload: %+v", feishuBody)
	}
	content, _ := feishuBody["content"].(map[string]any)
	text, _ := content["text"].(string)
	if !strings.Contains(text, "cdn.example.com") || !strings.Contains(text, "EC PRIVATE KEY") {
		t.Fatalf("feishu text missing domain or instructions: %q", text)
	}
	if feishuBody["sign"] == nil || feishuBody["timestamp"] == nil {
		t.Fatalf("feishu signed payload missing timestamp/sign: %+v", feishuBody)
	}

	wtext, _ := wecomBody["msgtype"].(string)
	if wtext != "text" {
		t.Fatalf("wecom payload: %+v", wecomBody)
	}

	sent, err = n.Send(context.Background(), []Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	if sent != 0 {
		t.Fatalf("duplicate event sent %d notifications, want 0", sent)
	}

	sent, err = n.Send(context.Background(), []Event{{Provider: "upyun", Domain: "cdn.example.com", Decision: "skip", Reason: "healthy"}})
	if err != nil {
		t.Fatal(err)
	}
	if sent != 0 {
		t.Fatalf("healthy event sent %d notifications, want 0", sent)
	}
}

func TestNoChannelsConfigured(t *testing.T) {
	n := New(Config{Enabled: true, StateFile: t.TempDir() + "/state.json"})
	if n.Enabled() {
		t.Fatal("notifier should be disabled without channels")
	}
	if _, err := n.Send(context.Background(), []Event{{Provider: "x", Domain: "example.com", Decision: "manual"}}); err != nil {
		t.Fatal(err)
	}
}

func TestFeishuSign(t *testing.T) {
	got := feishuSign("test-secret", 1700000000)
	if got == "" {
		t.Fatal("empty signature")
	}
}
