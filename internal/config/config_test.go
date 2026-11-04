package config

import (
	"testing"
	"time"
)

func TestRenewBeforeDays(t *testing.T) {
	t.Setenv("PANEL_BASE_URL", "https://panel.example.com")
	t.Setenv("PANEL_API_KEY", "key")
	t.Setenv("RENEW_BEFORE_DAYS", "15")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.RenewBefore != 15*24*time.Hour {
		t.Fatalf("RenewBefore = %s, want 360h", c.RenewBefore)
	}
}

func TestRenewBeforeZero(t *testing.T) {
	t.Setenv("PANEL_BASE_URL", "https://panel.example.com")
	t.Setenv("PANEL_API_KEY", "key")
	t.Setenv("RENEW_BEFORE_DAYS", "0")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.RenewBefore != 0 {
		t.Fatalf("RenewBefore = %s, want 0", c.RenewBefore)
	}
}

func TestRenewBeforeInvalid(t *testing.T) {
	t.Setenv("PANEL_BASE_URL", "https://panel.example.com")
	t.Setenv("PANEL_API_KEY", "key")
	t.Setenv("RENEW_BEFORE_DAYS", "soon")
	if _, err := Load(""); err == nil {
		t.Fatal("expected an error for a non-numeric RENEW_BEFORE_DAYS")
	}
}
