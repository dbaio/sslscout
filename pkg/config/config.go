// Package config loads and validates the SSLScout configuration.
//
// Why a package of its own (instead of living inside notifier, as it used to):
// the thresholds, the timeout and the concurrency have nothing to do with
// notifications, and three different consumers read the configuration today
// (cmd, checker and notifier). Keeping everything in notifier.Config would
// force cmd to import notifier just to learn how many days count as "critical".
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"sslscout/pkg/i18n"
)

// TLS modes accepted by the SMTP client.
const (
	TLSStartTLS = "starttls" // port 587: connect in the clear, then upgrade
	TLSImplicit = "implicit" // port 465: TLS from the very first byte
	TLSNone     = "none"     // no encryption (only sane on an internal relay)
)

// SMTP is the configuration of the e-mail channel.
type SMTP struct {
	Enabled  bool     `json:"enabled"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	TLS      string   `json:"tls"`
}

// Config is the content of config.json.
type Config struct {
	AlertThresholdDays    int `json:"alert_threshold_days"`
	CriticalThresholdDays int `json:"critical_threshold_days"`
	TimeoutSeconds        int `json:"timeout_seconds"`
	Concurrency           int `json:"concurrency"`
	Retries               int `json:"retries"`
	// Language selects the catalog used for the notification text: "en"
	// (default) or "pt-BR". It does not affect the CLI output, which is always
	// English, nor the dashboard, which picks its own language in the browser.
	Language string `json:"language"`
	// DashboardURL is where the report is published (the nginx vhost, the
	// GitHub Pages site, whatever serves public/). When set, every alert ends
	// with a line pointing at it, so whoever reads the alert can jump straight
	// to the dashboard. Empty means the line is omitted entirely.
	DashboardURL    string `json:"dashboard_url"`
	SlackWebhookURL string `json:"slack_webhook_url"`
	TeamsWebhookURL string `json:"teams_webhook_url"`
	SMTP            SMTP   `json:"smtp"`

	// TimeoutOverride holds the value of the -timeout flag, which accepts
	// sub-second durations ("500ms") — precision timeout_seconds cannot express.
	// When > 0 it wins over the file field.
	TimeoutOverride time.Duration `json:"-"`
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		AlertThresholdDays:    15,
		CriticalThresholdDays: 7,
		TimeoutSeconds:        10,
		Concurrency:           20,
		Retries:               3,
		Language:              string(i18n.Default),
		SMTP:                  SMTP{Port: 587, TLS: TLSStartTLS},
	}
}

// Timeout returns the effective per-connection timeout.
func (c Config) Timeout() time.Duration {
	if c.TimeoutOverride > 0 {
		return c.TimeoutOverride
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Dashboard returns the configured dashboard URL, trimmed. Empty means no
// dashboard link should be added to the alerts.
func (c Config) Dashboard() string { return strings.TrimSpace(c.DashboardURL) }

// Lang returns the notification language, already normalized. An unsupported
// value never reaches this point: Validate rejects it first.
func (c Config) Lang() i18n.Lang {
	lang, _ := i18n.Parse(c.Language)
	return lang
}

// Load reads the configuration file on top of the defaults. Fields absent from
// the JSON keep their default value — json.Unmarshal performs that merge,
// overwriting only what the file actually declares.
//
// A missing file yields the defaults and ok=false (the caller decides whether
// that is fatal). Any other problem — malformed JSON included — becomes an
// error: a broken config must NEVER silently turn into a zeroed one.
func Load(path string) (cfg Config, ok bool, err error) {
	cfg = Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, false, nil
		}
		return cfg, false, fmt.Errorf("could not read %s: %w", path, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default(), false, fmt.Errorf("invalid configuration in %s: %w", path, err)
	}
	return cfg, true, nil
}

// Environment variables that override the file.
const (
	EnvSlackWebhook = "SSLSCOUT_SLACK_WEBHOOK_URL"
	EnvTeamsWebhook = "SSLSCOUT_TEAMS_WEBHOOK_URL"
	EnvSMTPUsername = "SSLSCOUT_SMTP_USERNAME"
	EnvSMTPPassword = "SSLSCOUT_SMTP_PASSWORD"
	EnvLanguage     = "SSLSCOUT_LANG"
	EnvDashboardURL = "SSLSCOUT_DASHBOARD_URL"
)

// ApplyEnv overrides secrets (and the notification language) from the
// environment. It only overrides when the variable is set and non-empty, so
// exporting an empty variable never erases what the file says by accident.
func (c *Config) ApplyEnv(getenv func(string) string) {
	if getenv == nil {
		getenv = os.Getenv
	}
	set := func(dst *string, key string) {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			*dst = v
		}
	}
	set(&c.SlackWebhookURL, EnvSlackWebhook)
	set(&c.TeamsWebhookURL, EnvTeamsWebhook)
	set(&c.SMTP.Username, EnvSMTPUsername)
	set(&c.SMTP.Password, EnvSMTPPassword)
	set(&c.Language, EnvLanguage)
	set(&c.DashboardURL, EnvDashboardURL)
}

// Validate reports every problem at once instead of dying on the first one.
func (c Config) Validate() error {
	var problems []error

	if c.AlertThresholdDays < 0 {
		problems = append(problems, fmt.Errorf("alert_threshold_days cannot be negative (%d)", c.AlertThresholdDays))
	}
	if c.CriticalThresholdDays < 0 {
		problems = append(problems, fmt.Errorf("critical_threshold_days cannot be negative (%d)", c.CriticalThresholdDays))
	}
	if c.CriticalThresholdDays > c.AlertThresholdDays {
		problems = append(problems, fmt.Errorf("critical_threshold_days (%d) cannot be greater than alert_threshold_days (%d)",
			c.CriticalThresholdDays, c.AlertThresholdDays))
	}
	if c.Timeout() <= 0 {
		problems = append(problems, fmt.Errorf("timeout must be positive (%s)", c.Timeout()))
	}
	if c.Concurrency < 1 {
		problems = append(problems, fmt.Errorf("concurrency must be >= 1 (%d)", c.Concurrency))
	}
	if c.Retries < 1 {
		problems = append(problems, fmt.Errorf("retries must be >= 1 (%d)", c.Retries))
	}
	if _, ok := i18n.Parse(c.Language); !ok {
		problems = append(problems, fmt.Errorf("unsupported language %q (use one of: %s)",
			c.Language, strings.Join(i18n.SupportedNames(), ", ")))
	}
	if err := validateDashboardURL(c.Dashboard()); err != nil {
		problems = append(problems, err)
	}

	if c.SMTP.Enabled {
		if c.SMTP.Host == "" {
			problems = append(problems, errors.New("smtp.host is required when smtp.enabled is true"))
		}
		if c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
			problems = append(problems, fmt.Errorf("invalid smtp.port (%d)", c.SMTP.Port))
		}
		if c.SMTP.From == "" {
			problems = append(problems, errors.New("smtp.from is required when smtp.enabled is true"))
		}
		if len(c.SMTP.To) == 0 {
			problems = append(problems, errors.New("smtp.to needs at least one recipient"))
		}
		switch c.SMTP.TLS {
		case "", TLSStartTLS, TLSImplicit, TLSNone:
		default:
			problems = append(problems, fmt.Errorf("invalid smtp.tls %q (use %q, %q or %q)",
				c.SMTP.TLS, TLSStartTLS, TLSImplicit, TLSNone))
		}
	}

	return errors.Join(problems...)
}

// validateDashboardURL rejects a URL that would end up unclickable in an alert.
// A relative path or a bare hostname is the common mistake, and it is worth
// catching at start-up rather than in an alert nobody can follow.
func validateDashboardURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid dashboard_url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("dashboard_url %q must be an absolute http:// or https:// URL", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("dashboard_url %q has no host", raw)
	}
	return nil
}
