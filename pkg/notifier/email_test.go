package notifier

import (
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"

	"sslscout/pkg/config"
	"sslscout/pkg/i18n"
)

// Regression for bug #9: the old message carried only "To:" and a raw "Subject:".
func TestBuildMessageHeaders(t *testing.T) {
	cfg := config.SMTP{
		From: "alerts@example.com",
		To:   []string{"sre@example.com", "devops@example.com"},
	}
	subject := "SSLScout: 3 certificates need attention 🚨"
	body := "Expired certificates (1)\n  - expired.example.com:443 — expired 10 days ago\n"
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	raw := string(BuildMessage(cfg, subject, body, now))

	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("the message is not a valid e-mail: %v\n%s", err, raw)
	}

	for _, h := range []string{"From", "To", "Date", "Subject", "Mime-Version", "Content-Type", "Message-Id"} {
		if msg.Header.Get(h) == "" {
			t.Errorf("missing header %s:\n%s", h, raw)
		}
	}
	if from := msg.Header.Get("From"); from != cfg.From {
		t.Errorf("From = %q, want %q", from, cfg.From)
	}
	if to := msg.Header.Get("To"); to != "sre@example.com, devops@example.com" {
		t.Errorf("To = %q", to)
	}
	if _, err := msg.Header.Date(); err != nil {
		t.Errorf("Date does not parse: %v", err)
	}
	if ct := msg.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") ||
		!strings.Contains(strings.ToUpper(ct), "UTF-8") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cte := msg.Header.Get("Content-Transfer-Encoding"); cte != "quoted-printable" {
		t.Errorf("Content-Transfer-Encoding = %q", cte)
	}

	// The subject must be encoded (RFC 2047) and decode back.
	rawSubject := msg.Header.Get("Subject")
	if !strings.Contains(rawSubject, "=?") {
		t.Errorf("a subject with emoji/accents should be encoded: %q", rawSubject)
	}
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(rawSubject)
	if err != nil {
		t.Fatalf("the subject does not decode: %v", err)
	}
	if decoded != subject {
		t.Errorf("decoded subject = %q, want %q", decoded, subject)
	}

	// Body in quoted-printable, with CRLF.
	rawBody := raw[strings.Index(raw, "\r\n\r\n")+4:]
	if strings.Contains(rawBody, "—") {
		t.Error("the em dash should be quoted-printable encoded")
	}
	if !strings.HasSuffix(raw, "\r\n") {
		t.Error("the message should end with CRLF")
	}
	for _, l := range strings.Split(raw, "\r\n") {
		if len(l) > 998 {
			t.Errorf("line longer than the RFC 5322 limit: %d bytes", len(l))
		}
	}
}

// A pt-BR alert carries accents in the subject; they must survive the round trip.
func TestBuildMessageEncodesAccentedSubject(t *testing.T) {
	cfg := config.SMTP{From: "alertas@example.com", To: []string{"sre@example.com"}}
	subject := "SSLScout: 3 certificados precisando de atenção"

	raw := string(BuildMessage(cfg, subject, "corpo\n", time.Now()))
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("invalid message: %v", err)
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("the subject does not decode: %v", err)
	}
	if decoded != subject {
		t.Errorf("decoded subject = %q, want %q", decoded, subject)
	}
}

// A long dashboard_url gets soft-wrapped by quoted-printable. Decoding has to
// give it back intact, or the link arrives broken in the mail client.
func TestEmailFooterSurvivesQuotedPrintable(t *testing.T) {
	url := "https://sslscout.internal.example.com/reports/production/certificates?team=sre&view=expiring&sort=days"
	p := i18n.For(i18n.PtBR)
	groups := BuildGroups(p, results())
	subject := Subject(p, groups)
	body := RenderPlain(subject, groups, Footer(p, url))

	raw := string(BuildMessage(config.SMTP{From: "a@b.c", To: []string{"d@e.f"}}, subject, body, time.Now()))

	encoded := raw[strings.Index(raw, "\r\n\r\n")+4:]
	if !strings.Contains(encoded, "=\r\n") {
		t.Error("this body should have been long enough to be soft-wrapped")
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(encoded)))
	if err != nil {
		t.Fatalf("the body does not decode: %v", err)
	}
	if !strings.Contains(string(decoded), "Saiba mais em "+url) {
		t.Errorf("the URL did not survive the round trip:\n%s", decoded)
	}
}

func TestMessageIDUsesTheSenderDomain(t *testing.T) {
	now := time.Now()
	id := messageID("alerts@example.com", now)
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") {
		t.Errorf("malformed Message-ID: %q", id)
	}
	if !strings.HasSuffix(id, "@example.com>") {
		t.Errorf("Message-ID should use the From domain: %q", id)
	}
	if noAt := messageID("sender-without-domain", now); !strings.Contains(noAt, "@") {
		t.Errorf("a Message-ID with no domain in From should use a fallback: %q", noAt)
	}
}
