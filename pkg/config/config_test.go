package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sslscout/pkg/i18n"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefault(t *testing.T) {
	c := Default()
	if c.AlertThresholdDays != 15 || c.CriticalThresholdDays != 7 {
		t.Errorf("default thresholds = %d/%d, want 15/7", c.AlertThresholdDays, c.CriticalThresholdDays)
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("default timeout = %s, want 10s", c.Timeout())
	}
	if c.Concurrency != 20 || c.Retries != 3 {
		t.Errorf("default concurrency/retries = %d/%d, want 20/3", c.Concurrency, c.Retries)
	}
	if c.SMTP.Port != 587 || c.SMTP.TLS != TLSStartTLS {
		t.Errorf("default smtp = %d/%q, want 587/starttls", c.SMTP.Port, c.SMTP.TLS)
	}
	if c.Lang() != i18n.EN {
		t.Errorf("default language = %q, want %q — alerts go out in English unless configured", c.Lang(), i18n.EN)
	}
	if c.Dashboard() != "" {
		t.Errorf("there is no default dashboard URL, got %q", c.Dashboard())
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the default configuration should be valid: %v", err)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, ok, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("a missing file should not be an error: %v", err)
	}
	if ok {
		t.Error("ok should be false when the file does not exist")
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Errorf("should return the defaults, got %+v", cfg)
	}
}

// Regression for bug #3: swallowing the json.Unmarshal error silently turned a
// broken config into a zeroed configuration.
func TestLoadMalformedJSONFailsLoudly(t *testing.T) {
	path := write(t, `{"alert_threshold_days": 30,,,}`)

	cfg, ok, err := Load(path)
	if err == nil {
		t.Fatal("malformed JSON must produce an error, not a zeroed config")
	}
	if ok {
		t.Error("ok should be false")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error should name the file: %v", err)
	}
	if cfg.AlertThresholdDays == 0 {
		t.Error("even on error the returned config must be the default one (never zeroed)")
	}
}

func TestLoadMergesWithDefaults(t *testing.T) {
	// Only two fields declared: everything else must keep its default.
	path := write(t, `{"alert_threshold_days": 30, "slack_webhook_url": "https://hooks.example/abc"}`)

	cfg, ok, err := Load(path)
	if err != nil || !ok {
		t.Fatalf("Load failed: ok=%v err=%v", ok, err)
	}
	if cfg.AlertThresholdDays != 30 {
		t.Errorf("alert_threshold_days = %d, want 30 (from the file)", cfg.AlertThresholdDays)
	}
	if cfg.CriticalThresholdDays != 7 {
		t.Errorf("critical_threshold_days = %d, want 7 (default)", cfg.CriticalThresholdDays)
	}
	if cfg.Concurrency != 20 || cfg.Retries != 3 || cfg.TimeoutSeconds != 10 {
		t.Errorf("fields absent from the file should keep the default: %+v", cfg)
	}
	if cfg.Language != string(i18n.EN) {
		t.Errorf("language = %q, want the default %q", cfg.Language, i18n.EN)
	}
	if cfg.SlackWebhookURL != "https://hooks.example/abc" {
		t.Errorf("slack_webhook_url = %q", cfg.SlackWebhookURL)
	}
	if cfg.SMTP.TLS != TLSStartTLS || cfg.SMTP.Port != 587 {
		t.Errorf("smtp should keep the default: %+v", cfg.SMTP)
	}
}

func TestLoadLanguage(t *testing.T) {
	cfg, _, err := Load(write(t, `{"language": "pt-BR"}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("pt-BR should be accepted: %v", err)
	}
	if cfg.Lang() != i18n.PtBR {
		t.Errorf("Lang() = %q, want %q", cfg.Lang(), i18n.PtBR)
	}
}

func TestApplyEnvOverridesSecrets(t *testing.T) {
	env := map[string]string{
		EnvSlackWebhook: "https://hooks.slack/env",
		EnvTeamsWebhook: "  ", // blank: must not override
		EnvSMTPPassword: "secret-from-env",
		EnvLanguage:     "pt-BR",
		EnvDashboardURL: "https://sslscout.example.com",
	}
	cfg := Default()
	cfg.SlackWebhookURL = "https://hooks.slack/file"
	cfg.TeamsWebhookURL = "https://teams/file"
	cfg.SMTP.Password = "password-from-file"
	cfg.SMTP.Username = "user-from-file"

	cfg.ApplyEnv(func(k string) string { return env[k] })

	if cfg.SlackWebhookURL != "https://hooks.slack/env" {
		t.Errorf("the environment should win over the file: %q", cfg.SlackWebhookURL)
	}
	if cfg.TeamsWebhookURL != "https://teams/file" {
		t.Errorf("a blank variable should not erase the file value: %q", cfg.TeamsWebhookURL)
	}
	if cfg.SMTP.Password != "secret-from-env" {
		t.Errorf("smtp.password = %q", cfg.SMTP.Password)
	}
	if cfg.SMTP.Username != "user-from-file" {
		t.Errorf("smtp.username is unset in the environment and should stay put: %q", cfg.SMTP.Username)
	}
	if cfg.Lang() != i18n.PtBR {
		t.Errorf("SSLSCOUT_LANG should select the catalog: %q", cfg.Lang())
	}
	if cfg.Dashboard() != "https://sslscout.example.com" {
		t.Errorf("SSLSCOUT_DASHBOARD_URL should reach the config: %q", cfg.Dashboard())
	}
}

func TestDashboardURL(t *testing.T) {
	cfg, _, err := Load(write(t, `{"dashboard_url": "  https://sslscout.example.com/  "}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a plain https URL should be accepted: %v", err)
	}
	if cfg.Dashboard() != "https://sslscout.example.com/" {
		t.Errorf("Dashboard() should trim surrounding space: %q", cfg.Dashboard())
	}

	// An empty URL is the default and means "no link in the alerts".
	empty := Default()
	if err := empty.Validate(); err != nil {
		t.Errorf("an absent dashboard_url must not be an error: %v", err)
	}

	// A value that would end up unclickable in an alert is rejected at start-up.
	for _, bad := range []string{
		"sslscout.example.com",       // no scheme
		"/reports/sslscout",          // relative path
		"ftp://sslscout.example.com", // wrong scheme
		"https://",                   // no host
		"://sslscout.example.com",    // unparseable
	} {
		c := Default()
		c.DashboardURL = bad
		err := c.Validate()
		if err == nil {
			t.Errorf("dashboard_url %q should be rejected", bad)
			continue
		}
		if !strings.Contains(err.Error(), "dashboard_url") {
			t.Errorf("the error for %q should name the field: %v", bad, err)
		}
	}
}

func TestTimeoutOverrideWinsOverFile(t *testing.T) {
	cfg := Default()
	cfg.TimeoutSeconds = 30
	if cfg.Timeout() != 30*time.Second {
		t.Fatalf("timeout = %s", cfg.Timeout())
	}
	cfg.TimeoutOverride = 500 * time.Millisecond
	if cfg.Timeout() != 500*time.Millisecond {
		t.Errorf("the -timeout flag should win: %s", cfg.Timeout())
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a sub-second timeout should be valid: %v", err)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name     string
		tweak    func(*Config)
		mentions []string
	}{
		{"zero concurrency", func(c *Config) { c.Concurrency = 0 }, []string{"concurrency"}},
		{"zero retries", func(c *Config) { c.Retries = 0 }, []string{"retries"}},
		{"zero timeout", func(c *Config) { c.TimeoutSeconds = 0 }, []string{"timeout"}},
		{"negative threshold", func(c *Config) { c.AlertThresholdDays = -1 }, []string{"alert_threshold_days"}},
		{"critical above alert", func(c *Config) { c.CriticalThresholdDays = 40 }, []string{"critical_threshold_days"}},
		{"unsupported language", func(c *Config) { c.Language = "klingon" }, []string{"language", "en", "pt-BR"}},
		{"smtp without host", func(c *Config) {
			c.SMTP.Enabled = true
			c.SMTP.From = "a@b.c"
			c.SMTP.To = []string{"d@e.f"}
		}, []string{"smtp.host"}},
		{"smtp without recipient", func(c *Config) {
			c.SMTP.Enabled = true
			c.SMTP.Host = "smtp.example.com"
			c.SMTP.From = "a@b.c"
		}, []string{"smtp.to"}},
		{"invalid smtp tls", func(c *Config) {
			c.SMTP.Enabled = true
			c.SMTP.Host = "smtp.example.com"
			c.SMTP.From = "a@b.c"
			c.SMTP.To = []string{"d@e.f"}
			c.SMTP.TLS = "ssl"
		}, []string{"smtp.tls"}},
		{"several problems at once", func(c *Config) {
			c.Concurrency = 0
			c.Retries = -2
		}, []string{"concurrency", "retries"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			c.tweak(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected a validation error for %+v", cfg)
			}
			for _, want := range c.mentions {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error should mention %q: %v", want, err)
				}
			}
		})
	}

	// An empty language means "use the default" and must not be rejected.
	empty := Default()
	empty.Language = ""
	if err := empty.Validate(); err != nil {
		t.Errorf("an empty language should fall back to the default: %v", err)
	}

	valid := Default()
	valid.SMTP = SMTP{Enabled: true, Host: "smtp.example.com", Port: 465,
		From: "a@b.c", To: []string{"d@e.f"}, TLS: TLSImplicit}
	if err := valid.Validate(); err != nil {
		t.Errorf("a valid SMTP configuration was rejected: %v", err)
	}
}
