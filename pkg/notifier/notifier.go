// Package notifier groups the problematic results and dispatches the alerts to
// Slack, Microsoft Teams and e-mail.
//
// The alert text is localized through pkg/i18n; the language comes from the
// configuration (config.language / SSLSCOUT_LANG / -lang) and defaults to
// English. Everything the binary prints to the terminal stays in English.
package notifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sslscout/pkg/checker"
	"sslscout/pkg/config"
	"sslscout/pkg/i18n"
)

// HTTPTimeout caps each webhook POST. The default net/http client has no
// timeout at all: one hung webhook used to block the process forever.
const HTTPTimeout = 15 * time.Second

var httpClient = &http.Client{Timeout: HTTPTimeout}

// Group is a block of alerts of the same severity.
type Group struct {
	Status checker.Status
	Title  string
	Lines  []string // plain text, no markup: each channel applies its own
}

// Notify sends the alerts through the configured channels and returns the
// aggregated errors. It does not print and swallow: the caller decides how to
// log and whether this should affect the exit code.
func Notify(cfg config.Config, results []checker.Result) error {
	p := i18n.For(cfg.Lang())

	groups := BuildGroups(p, results)
	if len(groups) == 0 {
		return nil // all good, nothing to report
	}

	subject := Subject(p, groups)
	var problems []error

	if cfg.SlackWebhookURL != "" {
		if err := sendSlack(cfg.SlackWebhookURL, subject, groups); err != nil {
			problems = append(problems, fmt.Errorf("slack: %w", err))
		}
	}
	if cfg.TeamsWebhookURL != "" {
		if err := sendTeams(cfg.TeamsWebhookURL, subject, groups); err != nil {
			problems = append(problems, fmt.Errorf("teams: %w", err))
		}
	}
	if cfg.SMTP.Enabled {
		if err := sendEmail(cfg.SMTP, subject, RenderPlain(subject, groups)); err != nil {
			problems = append(problems, fmt.Errorf("e-mail: %w", err))
		}
	}

	return errors.Join(problems...)
}

// Display order: most serious first.
var groupOrder = []checker.Status{
	checker.StatusError,
	checker.StatusExpired,
	checker.StatusInvalid,
	checker.StatusCritical,
	checker.StatusWarning,
}

// BuildGroups splits the problematic results by severity, rendering every line
// in the language of the given printer.
func BuildGroups(p i18n.Printer, results []checker.Result) []Group {
	byStatus := map[checker.Status][]string{}
	for _, r := range results {
		if r.Status == checker.StatusOK {
			continue
		}
		byStatus[r.Status] = append(byStatus[r.Status], line(p, r))
	}

	var groups []Group
	for _, status := range groupOrder {
		if lines := byStatus[status]; len(lines) > 0 {
			groups = append(groups, Group{
				Status: status,
				Title:  p.GroupTitle(string(status)),
				Lines:  lines,
			})
		}
	}
	return groups
}

func line(p i18n.Printer, r checker.Result) string {
	date := ""
	if r.ExpiresAt != nil {
		date = p.Date(*r.ExpiresAt)
	}

	switch r.Status {
	case checker.StatusError:
		return p.LineError(r.Domain, string(r.ErrorKind), r.Error)
	case checker.StatusExpired:
		return p.LineExpired(r.Domain, -r.DaysRemaining, date)
	case checker.StatusInvalid:
		return p.LineInvalid(r.Domain, string(r.ErrorKind), r.Subject)
	default: // critical / warning
		return p.LineExpiring(r.Domain, r.DaysRemaining, date)
	}
}

// Subject builds the title used as the e-mail subject and the card title.
func Subject(p i18n.Printer, groups []Group) string {
	total := 0
	for _, g := range groups {
		total += len(g.Lines)
	}
	return p.Subject(total)
}

// RenderPlain produces the plain-text version (e-mail).
func RenderPlain(title string, groups []Group) string {
	var b strings.Builder
	b.WriteString(title)
	b.WriteString("\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "\n%s (%d)\n", g.Title, len(g.Lines))
		for _, l := range g.Lines {
			fmt.Fprintf(&b, "  - %s\n", l)
		}
	}
	return b.String()
}

// RenderSlack produces the mrkdwn text (Slack's dialect: *bold*, not **).
func RenderSlack(title string, groups []Group) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🚨 *%s*\n", title)
	for _, g := range groups {
		fmt.Fprintf(&b, "\n%s *%s* (%d)\n", emoji(g.Status), g.Title, len(g.Lines))
		for _, l := range g.Lines {
			fmt.Fprintf(&b, "• %s\n", escapeSlack(l))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func emoji(s checker.Status) string {
	switch s {
	case checker.StatusError:
		return "⚠️"
	case checker.StatusExpired, checker.StatusInvalid:
		return "🔴"
	case checker.StatusCritical:
		return "🟠"
	default:
		return "🟡"
	}
}

// escapeSlack protects the characters Slack reads as markup.
func escapeSlack(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// --- Slack ---

func sendSlack(webhookURL, title string, groups []Group) error {
	payload := map[string]any{
		"text":   RenderSlack(title, groups),
		"mrkdwn": true,
	}
	return postJSON(webhookURL, payload)
}

// --- Microsoft Teams ---
//
// A Teams channel webhook does NOT accept {"text": "..."}: the format is the
// legacy MessageCard
// (https://learn.microsoft.com/outlook/actionable-messages/message-card-reference).

type teamsCard struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	ThemeColor string         `json:"themeColor"`
	Summary    string         `json:"summary"`
	Title      string         `json:"title"`
	Text       string         `json:"text,omitempty"`
	Sections   []teamsSection `json:"sections,omitempty"`
}

type teamsSection struct {
	ActivityTitle string `json:"activityTitle,omitempty"`
	Text          string `json:"text,omitempty"`
	Markdown      bool   `json:"markdown"`
}

func sendTeams(webhookURL, title string, groups []Group) error {
	card := teamsCard{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		ThemeColor: teamsTheme(groups),
		Summary:    title,
		Title:      title,
	}
	for _, g := range groups {
		// In a MessageCard every list item needs its own markdown line.
		var items []string
		for _, l := range g.Lines {
			items = append(items, "- "+escapeMarkdown(l))
		}
		card.Sections = append(card.Sections, teamsSection{
			ActivityTitle: fmt.Sprintf("**%s (%d)**", g.Title, len(g.Lines)),
			Text:          strings.Join(items, "\n\n"),
			Markdown:      true,
		})
	}
	return postJSON(webhookURL, card)
}

func teamsTheme(groups []Group) string {
	worst := -1
	for _, g := range groups {
		if s := g.Status.Severity(); s > worst {
			worst = s
		}
	}
	switch {
	case worst >= checker.StatusInvalid.Severity():
		return "D93025" // red
	case worst >= checker.StatusCritical.Severity():
		return "E8710A" // orange
	default:
		return "F9AB00" // yellow
	}
}

// escapeMarkdown keeps the "*" and "_" of a wildcard CN (e.g. *.badssl.com)
// from turning into italics inside the card.
func escapeMarkdown(s string) string {
	return strings.NewReplacer("*", "\\*", "_", "\\_").Replace(s)
}

// --- HTTP ---

func postJSON(url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not serialize the payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST failed: %w", err)
	}
	defer resp.Body.Close()

	// Reading the response is mandatory: a 200 is not guaranteed, and a 400
	// from Slack usually explains itself in the body ("invalid_payload",
	// "no_service").
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP response %s: %s", resp.Status, excerpt(answer))
	}
	return nil
}

func excerpt(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "(empty body)"
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
