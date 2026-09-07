package notifier

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dbaio/sslscout/pkg/checker"
	"github.com/dbaio/sslscout/pkg/config"
	"github.com/dbaio/sslscout/pkg/i18n"
)

func in(days int) *time.Time {
	t := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC).AddDate(0, 0, days)
	return &t
}

func results() []checker.Result {
	return []checker.Result{
		{Domain: "ok.example.com:443", Status: checker.StatusOK, Valid: true, DaysRemaining: 200, ExpiresAt: in(200)},
		{Domain: "warning.example.com:443", Status: checker.StatusWarning, Valid: true, DaysRemaining: 12, ExpiresAt: in(12)},
		{Domain: "critical.example.com:443", Status: checker.StatusCritical, Valid: true, DaysRemaining: 3, ExpiresAt: in(3)},
		{Domain: "expired.example.com:443", Status: checker.StatusExpired, DaysRemaining: -10, ExpiresAt: in(-10),
			ErrorKind: checker.KindExpired, Error: "x509: certificate has expired"},
		{Domain: "invalid.example.com:443", Status: checker.StatusInvalid, DaysRemaining: 100, Subject: "*.badssl.com",
			ErrorKind: checker.KindHostnameMismatch, Error: "x509: certificate is valid for *.badssl.com"},
		{Domain: "error.example.com:443", Status: checker.StatusError,
			ErrorKind: checker.KindDNS, Error: "lookup error.example.com: no such host"},
	}
}

// captureServer returns a server that keeps the last body it received.
func captureServer(t *testing.T, status int, response string) (*httptest.Server, *[]byte, *http.Header) {
	t.Helper()
	var body []byte
	var headers http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		headers = r.Header.Clone()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)
	return srv, &body, &headers
}

func TestBuildGroups(t *testing.T) {
	groups := BuildGroups(i18n.For(i18n.EN), results())

	if len(groups) != 5 {
		t.Fatalf("expected 5 groups (the ok ones excluded), got %d", len(groups))
	}
	want := []checker.Status{
		checker.StatusError, checker.StatusExpired, checker.StatusInvalid,
		checker.StatusCritical, checker.StatusWarning,
	}
	for i, w := range want {
		if groups[i].Status != w {
			t.Errorf("group[%d] = %q, want %q (most serious first)", i, groups[i].Status, w)
		}
		if len(groups[i].Lines) != 1 {
			t.Errorf("group[%d] should have 1 line, has %d", i, len(groups[i].Lines))
		}
	}
	if !strings.Contains(groups[1].Lines[0], "expired 10 days ago") {
		t.Errorf("the expired line is missing the day count: %q", groups[1].Lines[0])
	}
	if !strings.Contains(groups[4].Lines[0], "expires in 12 days") {
		t.Errorf("the warning line is missing the deadline: %q", groups[4].Lines[0])
	}
	if !strings.Contains(groups[2].Lines[0], "hostname mismatch") {
		t.Errorf("the invalid line should carry a readable error kind: %q", groups[2].Lines[0])
	}

	if BuildGroups(i18n.For(i18n.EN), nil) != nil {
		t.Error("no results should mean no groups")
	}
	onlyOK := []checker.Result{{Domain: "a:443", Status: checker.StatusOK}}
	if BuildGroups(i18n.For(i18n.EN), onlyOK) != nil {
		t.Error("only ok results should not raise alerts")
	}
}

// The whole point of pkg/i18n: the same results render in another language
// without touching the report or the channels.
func TestBuildGroupsInPortuguese(t *testing.T) {
	groups := BuildGroups(i18n.For(i18n.PtBR), results())

	if groups[0].Title != "Falhas de conexão" {
		t.Errorf("group title = %q, want the pt-BR one", groups[0].Title)
	}
	if !strings.Contains(groups[1].Lines[0], "expirado há 10 dias") {
		t.Errorf("expired line = %q", groups[1].Lines[0])
	}
	if !strings.Contains(groups[4].Lines[0], "vence em 12 dias") {
		t.Errorf("warning line = %q", groups[4].Lines[0])
	}
	// pt-BR formats the date as day/month/year.
	if !strings.Contains(groups[4].Lines[0], "16/09/2026") {
		t.Errorf("the date should follow the language: %q", groups[4].Lines[0])
	}
	// The domain itself is never translated.
	if !strings.Contains(groups[0].Lines[0], "error.example.com:443") {
		t.Errorf("the domain should survive translation: %q", groups[0].Lines[0])
	}
}

func TestSubjectFollowsTheLanguage(t *testing.T) {
	en := Subject(i18n.For(i18n.EN), BuildGroups(i18n.For(i18n.EN), results()))
	if en != "SSLScout: 5 certificates need attention" {
		t.Errorf("english subject = %q", en)
	}
	pt := Subject(i18n.For(i18n.PtBR), BuildGroups(i18n.For(i18n.PtBR), results()))
	if !strings.Contains(pt, "5 certificados") {
		t.Errorf("pt-BR subject = %q", pt)
	}
}

func TestNotifyWithoutAlertsDoesNotCallTheWebhook(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()

	cfg := config.Default()
	cfg.SlackWebhookURL = srv.URL
	cfg.TeamsWebhookURL = srv.URL

	if err := Notify(cfg, []checker.Result{{Domain: "a:443", Status: checker.StatusOK}}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if called {
		t.Error("with no alerts no webhook should be called")
	}
}

func TestNotifySlackPayload(t *testing.T) {
	srv, body, headers := captureServer(t, 200, "ok")

	cfg := config.Default()
	cfg.SlackWebhookURL = srv.URL

	if err := Notify(cfg, results()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if ct := headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}

	var payload struct {
		Text   string `json:"text"`
		Mrkdwn bool   `json:"mrkdwn"`
	}
	if err := json.Unmarshal(*body, &payload); err != nil {
		t.Fatalf("the payload is not valid JSON: %v (%s)", err, *body)
	}
	if !payload.Mrkdwn {
		t.Error("mrkdwn should be true")
	}
	for _, want := range []string{
		"5 certificates need attention",
		"*Connection failures*",
		"expired.example.com:443",
		"error.example.com:443",
	} {
		if !strings.Contains(payload.Text, want) {
			t.Errorf("the Slack text does not contain %q:\n%s", want, payload.Text)
		}
	}
	if strings.Contains(payload.Text, "ok.example.com") {
		t.Error("a healthy domain should not show up in the alert")
	}
	if strings.Contains(payload.Text, "**") {
		t.Error("Slack uses *bold*, not the ** of common markdown")
	}
	if strings.Contains(payload.Text, "Learn more") {
		t.Error("with no dashboard_url there must be no dangling link line")
	}
}

const dashboard = "https://sslscout.example.com"

// The dashboard link has to reach all three channels, in the alert language.
func TestNotifyIncludesTheDashboardLink(t *testing.T) {
	t.Run("slack", func(t *testing.T) {
		srv, body, _ := captureServer(t, 200, "ok")
		cfg := config.Default()
		cfg.SlackWebhookURL = srv.URL
		cfg.DashboardURL = dashboard
		if err := Notify(cfg, results()); err != nil {
			t.Fatalf("Notify: %v", err)
		}
		var payload struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(*body, &payload); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(payload.Text, "Learn more at "+dashboard) {
			t.Errorf("the link should close the message:\n%s", payload.Text)
		}
	})

	t.Run("teams", func(t *testing.T) {
		srv, body, _ := captureServer(t, 200, "1")
		cfg := config.Default()
		cfg.TeamsWebhookURL = srv.URL
		cfg.DashboardURL = dashboard
		if err := Notify(cfg, results()); err != nil {
			t.Fatalf("Notify: %v", err)
		}
		var card map[string]any
		if err := json.Unmarshal(*body, &card); err != nil {
			t.Fatal(err)
		}
		sections := card["sections"].([]any)
		// One section per group plus the footer, and the footer comes last.
		if len(sections) != 6 {
			t.Fatalf("expected 5 groups + 1 footer section, got %d", len(sections))
		}
		last := sections[len(sections)-1].(map[string]any)
		if last["text"] != "Learn more at "+dashboard {
			t.Errorf("footer section = %v", last)
		}
		if last["activityTitle"] != nil {
			t.Errorf("the footer section should carry no heading: %v", last["activityTitle"])
		}
	})

	t.Run("email body", func(t *testing.T) {
		p := i18n.For(i18n.EN)
		groups := BuildGroups(p, results())
		text := RenderPlain(Subject(p, groups), groups, Footer(p, dashboard))
		if !strings.HasSuffix(text, "Learn more at "+dashboard+"\n") {
			t.Errorf("the e-mail body should end with the link:\n%s", text)
		}
	})

	t.Run("follows the alert language", func(t *testing.T) {
		srv, body, _ := captureServer(t, 200, "ok")
		cfg := config.Default()
		cfg.SlackWebhookURL = srv.URL
		cfg.DashboardURL = dashboard
		cfg.Language = "pt-BR"
		if err := Notify(cfg, results()); err != nil {
			t.Fatalf("Notify: %v", err)
		}
		var payload struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(*body, &payload); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(payload.Text, "Saiba mais em "+dashboard) {
			t.Errorf("the link line should be translated:\n%s", payload.Text)
		}
	})
}

func TestFooter(t *testing.T) {
	p := i18n.For(i18n.EN)
	if got := Footer(p, ""); got != "" {
		t.Errorf("no URL means no footer, got %q", got)
	}
	if got := Footer(p, "   "); got != "" {
		t.Errorf("a blank URL means no footer, got %q", got)
	}
	if got := Footer(p, "  "+dashboard+"  "); got != "Learn more at "+dashboard {
		t.Errorf("Footer should trim the URL: %q", got)
	}
}

// A "&" in a query string has to survive Slack's mrkdwn escaping, or the link
// arrives broken.
func TestSlackFooterIsEscaped(t *testing.T) {
	p := i18n.For(i18n.EN)
	groups := BuildGroups(p, results())
	url := "https://example.com/r?a=1&b=2"
	text := RenderSlack("Title", groups, Footer(p, url))
	if !strings.Contains(text, "https://example.com/r?a=1&amp;b=2") {
		t.Errorf("the ampersand should be escaped for mrkdwn:\n%s", text)
	}
}

// The configured language must reach the wire, not only BuildGroups.
func TestNotifyUsesTheConfiguredLanguage(t *testing.T) {
	srv, body, _ := captureServer(t, 200, "ok")

	cfg := config.Default()
	cfg.SlackWebhookURL = srv.URL
	cfg.Language = "pt-BR"

	if err := Notify(cfg, results()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	var payload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(*body, &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Text, "Falhas de conexão") {
		t.Errorf("the alert should be in pt-BR:\n%s", payload.Text)
	}
	if strings.Contains(payload.Text, "Connection failures") {
		t.Errorf("English text leaked into a pt-BR alert:\n%s", payload.Text)
	}
}

// Regression for bug #8: Teams does not accept {"text": ...} on a channel webhook.
func TestNotifyTeamsUsesMessageCard(t *testing.T) {
	srv, body, _ := captureServer(t, 200, "1")

	cfg := config.Default()
	cfg.TeamsWebhookURL = srv.URL

	if err := Notify(cfg, results()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var card map[string]any
	if err := json.Unmarshal(*body, &card); err != nil {
		t.Fatalf("the payload is not valid JSON: %v (%s)", err, *body)
	}
	if card["@type"] != "MessageCard" {
		t.Errorf("@type = %v, want MessageCard", card["@type"])
	}
	if card["@context"] != "https://schema.org/extensions" {
		t.Errorf("@context = %v", card["@context"])
	}
	if card["summary"] == nil || card["summary"] == "" {
		t.Error("summary is mandatory in a MessageCard")
	}
	if card["themeColor"] != "D93025" {
		t.Errorf("themeColor = %v, want red for expired/invalid", card["themeColor"])
	}
	sections, ok := card["sections"].([]any)
	if !ok || len(sections) != 5 {
		t.Fatalf("expected 5 sections, got %v", card["sections"])
	}
	first := sections[0].(map[string]any)
	if first["markdown"] != true {
		t.Error("the sections should declare markdown: true")
	}
	if !strings.Contains(first["activityTitle"].(string), "Connection failures") {
		t.Errorf("activityTitle = %v", first["activityTitle"])
	}
}

func TestNotifyTeamsIsOrangeWhenOnlyCritical(t *testing.T) {
	srv, body, _ := captureServer(t, 200, "1")

	cfg := config.Default()
	cfg.TeamsWebhookURL = srv.URL
	res := []checker.Result{
		{Domain: "critical.example.com:443", Status: checker.StatusCritical, DaysRemaining: 2, ExpiresAt: in(2)},
	}
	if err := Notify(cfg, res); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	var card map[string]any
	if err := json.Unmarshal(*body, &card); err != nil {
		t.Fatal(err)
	}
	if card["themeColor"] != "E8710A" {
		t.Errorf("themeColor = %v, want orange", card["themeColor"])
	}
}

// Regression for bug #7: 4xx/5xx used to be reported as "notification sent".
func TestNotifyDetectsHTTPError(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		response string
	}{
		{"400 from Slack", http.StatusBadRequest, "invalid_payload"},
		{"403", http.StatusForbidden, "action_prohibited"},
		{"500", http.StatusInternalServerError, "internal error"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _, _ := captureServer(t, c.status, c.response)

			cfg := config.Default()
			cfg.SlackWebhookURL = srv.URL

			err := Notify(cfg, results())
			if err == nil {
				t.Fatal("an error response from the webhook should become an error")
			}
			if !strings.Contains(err.Error(), "slack") {
				t.Errorf("the error should identify the channel: %v", err)
			}
			if !strings.Contains(err.Error(), c.response) {
				t.Errorf("the error should carry an excerpt of the body (%q): %v", c.response, err)
			}
		})
	}
}

func TestNotifyAggregatesErrorsFromSeveralChannels(t *testing.T) {
	bad, _, _ := captureServer(t, 500, "boom")

	cfg := config.Default()
	cfg.SlackWebhookURL = bad.URL
	cfg.TeamsWebhookURL = bad.URL

	err := Notify(cfg, results())
	if err == nil {
		t.Fatal("expected errors from both channels")
	}
	if !strings.Contains(err.Error(), "slack") || !strings.Contains(err.Error(), "teams") {
		t.Errorf("both channels should appear in the aggregated error: %v", err)
	}
}

func TestNotifyConnectionError(t *testing.T) {
	srv, _, _ := captureServer(t, 200, "ok")
	url := srv.URL
	srv.Close() // nobody is listening any more

	cfg := config.Default()
	cfg.SlackWebhookURL = url

	if err := Notify(cfg, results()); err == nil {
		t.Fatal("a connection failure should become an error")
	}
}

func TestEscapeSlack(t *testing.T) {
	if got := escapeSlack("a < b & c > d"); got != "a &lt; b &amp; c &gt; d" {
		t.Errorf("escapeSlack = %q", got)
	}
}

func TestRenderPlainHasNoMarkup(t *testing.T) {
	p := i18n.For(i18n.EN)
	groups := BuildGroups(p, results())
	text := RenderPlain("Title", groups, "")
	// The text may contain a "*" from a wildcard CN, but never markup of ours.
	if strings.Contains(text, "*Connection") || strings.Contains(text, "**") || strings.Contains(text, "•") {
		t.Errorf("the e-mail body should carry no markup:\n%s", text)
	}
	if !strings.Contains(text, "Expired certificates (1)") {
		t.Errorf("the group heading is missing:\n%s", text)
	}
}

// TestChainLineNamesTheIntermediate: when the chain is what runs out, the alert
// has to say so. Telling the reader that a certificate with 200 days left
// "expires in 4 days" sends them to renew the wrong thing.
func TestChainLineNamesTheIntermediate(t *testing.T) {
	expires := time.Date(2027, 3, 20, 0, 0, 0, 0, time.UTC)
	chainExpires := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	chainDays := 4

	r := checker.Result{
		Domain:             "example.com:443",
		Status:             checker.StatusCritical,
		DaysRemaining:      200,
		ExpiresAt:          &expires,
		ChainExpiresAt:     &chainExpires,
		ChainDaysRemaining: &chainDays,
		ChainSubject:       "Example Intermediate CA",
	}

	got := line(i18n.For(i18n.EN), r)
	for _, want := range []string{"chain", "4 days", "2026-09-08", "Example Intermediate CA"} {
		if !strings.Contains(got, want) {
			t.Errorf("the line %q should mention %q", got, want)
		}
	}
	if strings.Contains(got, "200") {
		t.Errorf("the line %q should not lead with the leaf's deadline", got)
	}
}
