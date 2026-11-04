package main

import (
	"testing"
	"time"
)

func TestNextDaily(t *testing.T) {
	cases := []struct {
		now  time.Time
		at   string
		want time.Time
	}{
		{
			now:  time.Date(2026, 11, 4, 3, 0, 0, 0, time.Local),
			at:   "04:17",
			want: time.Date(2026, 11, 4, 4, 17, 0, 0, time.Local),
		},
		{
			now:  time.Date(2026, 11, 4, 10, 0, 0, 0, time.Local),
			at:   "04:17",
			want: time.Date(2026, 11, 5, 4, 17, 0, 0, time.Local),
		},
		{
			now:  time.Date(2026, 11, 4, 4, 17, 0, 0, time.Local),
			at:   "04:17",
			want: time.Date(2026, 11, 5, 4, 17, 0, 0, time.Local),
		},
	}
	for _, c := range cases {
		if got := nextDaily(c.at, c.now); !got.Equal(c.want) {
			t.Errorf("nextDaily(%q, %s) = %s, want %s", c.at, c.now, got, c.want)
		}
	}
}

func TestParseWindow(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"30", 30 * 24 * time.Hour},
		{"15d", 15 * 24 * time.Hour},
		{"720h", 30 * 24 * time.Hour},
		{"0", 0},
	}
	for _, c := range cases {
		got, err := parseWindow(c.in)
		if err != nil {
			t.Fatalf("parseWindow(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parseWindow(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	if _, err := parseWindow("soon"); err == nil {
		t.Fatal("expected error for invalid window")
	}
}

func TestNextDailyUsesServerLocalTimezone(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 5, 0, 0, time.Local)
	next := nextDaily("04:17", now)
	if next.Location() != time.Local {
		t.Fatalf("location = %s, want %s", next.Location(), time.Local)
	}
}
