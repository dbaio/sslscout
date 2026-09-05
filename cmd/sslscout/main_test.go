package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sslscout/pkg/config"
	"sslscout/pkg/i18n"
	"sslscout/pkg/report"
)

// TestConfigurationPrecedence covers default < file < flag, which is the rule
// of the contract. The environment sits between file and flag.
func TestConfigurationPrecedence(t *testing.T) {
	file := config.Default()
	file.AlertThresholdDays = 30
	file.Concurrency = 5
	file.Retries = 7
	file.TimeoutSeconds = 25
	file.Language = "pt-BR"
	file.DashboardURL = "https://from-file.example.com"

	cases := []struct {
		name        string
		flags       map[string]bool
		opts        options
		alert       int
		critical    int
		concurrency int
		retries     int
		timeout     time.Duration
		lang        i18n.Lang
		dashboard   string
	}{
		{
			name: "no flags, the file wins",
			opts: options{threshold: 15, critical: 7, concurrency: 20, retries: 3, timeout: 10 * time.Second, lang: "en"},
			// values from the file:
			alert: 30, critical: 7, concurrency: 5, retries: 7, timeout: 25 * time.Second, lang: i18n.PtBR,
			dashboard: "https://from-file.example.com",
		},
		{
			name:  "the flag wins over the file",
			flags: map[string]bool{"threshold": true, "concurrency": true, "timeout": true, "lang": true, "dashboard-url": true},
			opts: options{threshold: 45, critical: 7, concurrency: 100, retries: 3, timeout: 2 * time.Second,
				lang: "en", dashboardURL: "https://from-flag.example.com"},
			alert: 45, critical: 7, concurrency: 100, retries: 7, timeout: 2 * time.Second, lang: i18n.EN,
			dashboard: "https://from-flag.example.com",
		},
		{
			name:  "sub-second flag",
			flags: map[string]bool{"timeout": true},
			opts:  options{timeout: 750 * time.Millisecond},
			alert: 30, critical: 7, concurrency: 5, retries: 7, timeout: 750 * time.Millisecond, lang: i18n.PtBR,
			dashboard: "https://from-file.example.com",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := file
			applyFlags(&cfg, c.opts, c.flags)

			if cfg.AlertThresholdDays != c.alert {
				t.Errorf("alert_threshold_days = %d, want %d", cfg.AlertThresholdDays, c.alert)
			}
			if cfg.CriticalThresholdDays != c.critical {
				t.Errorf("critical_threshold_days = %d, want %d", cfg.CriticalThresholdDays, c.critical)
			}
			if cfg.Concurrency != c.concurrency {
				t.Errorf("concurrency = %d, want %d", cfg.Concurrency, c.concurrency)
			}
			if cfg.Retries != c.retries {
				t.Errorf("retries = %d, want %d", cfg.Retries, c.retries)
			}
			if cfg.Timeout() != c.timeout {
				t.Errorf("timeout = %s, want %s", cfg.Timeout(), c.timeout)
			}
			if cfg.Lang() != c.lang {
				t.Errorf("language = %q, want %q", cfg.Lang(), c.lang)
			}
			if cfg.Dashboard() != c.dashboard {
				t.Errorf("dashboard_url = %q, want %q", cfg.Dashboard(), c.dashboard)
			}
		})
	}
}

func TestDefaultPrecedenceWhenThereIsNoFile(t *testing.T) {
	cfg, ok, err := config.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	applyFlags(&cfg, options{}, nil)
	if cfg.AlertThresholdDays != 15 || cfg.Concurrency != 20 || cfg.Timeout() != 10*time.Second {
		t.Errorf("with neither file nor flags the defaults should hold: %+v", cfg)
	}
	if cfg.Lang() != i18n.EN {
		t.Errorf("the default alert language should be English, got %q", cfg.Lang())
	}
}

func TestNoCacheSetsHeaders(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte(`{"schema_version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(`<html></html>`), 0o644); err != nil {
		t.Fatal(err)
	}

	h := noCache(http.FileServer(http.Dir(dir)), "report.json")

	cases := map[string]string{
		"/report.json": "no-store, max-age=0",
		"/":            "no-cache, must-revalidate", // serves index.html
	}
	for path, want := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control = %q, want %q", path, got, want)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, rec.Code)
		}
	}
}

func TestFullVersion(t *testing.T) {
	v := fullVersion()
	if !strings.HasPrefix(v, "sslscout ") || !strings.Contains(v, "go1.") {
		t.Errorf("unexpected version: %q", v)
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, want %d", code, exitOK)
	}
	if !strings.HasPrefix(stdout.String(), "sslscout ") {
		t.Errorf("output = %q", stdout.String())
	}
}

func TestRunInvalidFlags(t *testing.T) {
	cases := [][]string{
		{"-fail-on", "banana"},
		{"-interval", "-5s"},
		{"-concurrency", "0"},
		{"-lang", "klingon"},
		{"-dashboard-url", "sslscout.example.com"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		args = append(args, "-domains", "does-not-exist.txt", "-notify=false")
		if code := run(args, &stdout, &stderr); code != exitError {
			t.Errorf("%v: code = %d, want %d", args, code, exitError)
		}
	}
}

// TestRunEndToEnd runs the binary end to end, offline: two dead targets
// (closed port) and one self-signed TLS target.
func TestRunEndToEnd(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsSrv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	dir := t.TempDir()
	domains := filepath.Join(dir, "domains.txt")
	content := "# test targets\n" + tlsSrv.Listener.Addr().String() + "\n" + dead + " # closed port\n"
	if err := os.WriteFile(domains, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	jsonOut := filepath.Join(dir, "public", "report.json")

	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"alert_threshold_days": 20}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-domains", domains,
		"-config", cfgPath,
		"-out", jsonOut,
		"-retries", "1",
		"-timeout", "3s",
		"-notify=false",
		"-fail-on", "invalid",
	}, &stdout, &stderr)

	if code != exitThreshold {
		t.Errorf("code = %d, want %d (there is an invalid/error result)\nstdout:%s\nstderr:%s",
			code, exitThreshold, stdout.String(), stderr.String())
	}

	data, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("the report was not written: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("invalid report: %v\n%s", err, data)
	}
	if rep.SchemaVersion != 2 {
		t.Errorf("schema_version = %d", rep.SchemaVersion)
	}
	if rep.Summary.Total != 2 {
		t.Errorf("summary.total = %d, want 2", rep.Summary.Total)
	}
	if rep.Summary.Invalid != 1 || rep.Summary.Error != 1 {
		t.Errorf("summary = %+v, want 1 invalid and 1 error", rep.Summary)
	}
	// 20 comes from config.json, 7 is the default: the report reflects what was used.
	if rep.AlertThresholdDays != 20 || rep.CriticalThresholdDays != 7 {
		t.Errorf("thresholds in the report = %d/%d, want 20/7", rep.AlertThresholdDays, rep.CriticalThresholdDays)
	}
	// The invalid result needs the diagnostic metadata.
	for _, r := range rep.Results {
		if r.Status == "invalid" && r.ExpiresAt == nil {
			t.Errorf("invalid result without expires_at: %+v", r)
		}
	}
}

func TestRunFailOnNone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	dir := t.TempDir()
	domains := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(domains, []byte(dead+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-domains", domains,
		"-out", filepath.Join(dir, "report.json"),
		"-retries", "1", "-timeout", "2s", "-notify=false", "-quiet",
	}, &stdout, &stderr)

	if code != exitOK {
		t.Errorf("with -fail-on=none the code should be 0, got %d (%s)", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("-quiet should silence the output: %q", stdout.String())
	}
}
