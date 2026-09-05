package i18n

import (
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Lang
		ok   bool
	}{
		{"", Default, true},
		{"en", EN, true},
		{"EN", EN, true},
		{"  en  ", EN, true},
		{"en-US", EN, true},
		{"pt-BR", PtBR, true},
		{"pt-br", PtBR, true},
		{"pt_BR", PtBR, true},
		{"pt", PtBR, true},
		{"pt-PT", PtBR, true},
		{"klingon", Default, false},
		{"e", Default, false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Parse(%q) = %q/%v, want %q/%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestForFallsBackToDefault(t *testing.T) {
	if p := For("nl"); p.Lang() != Default {
		t.Errorf("unregistered language should fall back to %q, got %q", Default, p.Lang())
	}
	if p := For(PtBR); p.Lang() != PtBR {
		t.Errorf("Lang() = %q, want %q", p.Lang(), PtBR)
	}
}

func TestSupported(t *testing.T) {
	names := SupportedNames()
	if len(names) != len(catalogs) {
		t.Fatalf("SupportedNames() = %v, want one entry per catalog", names)
	}
	found := false
	for _, n := range names {
		if n == string(Default) {
			found = true
		}
	}
	if !found {
		t.Errorf("the default language should be listed as supported: %v", names)
	}
}

func TestPlurals(t *testing.T) {
	en := For(EN)
	if got := en.Days(1); got != "1 day" {
		t.Errorf("Days(1) = %q", got)
	}
	if got := en.Days(3); got != "3 days" {
		t.Errorf("Days(3) = %q", got)
	}
	if got := en.Subject(1); got != "SSLScout: 1 certificate needs attention" {
		t.Errorf("Subject(1) = %q", got)
	}
	if got := en.Subject(4); got != "SSLScout: 4 certificates need attention" {
		t.Errorf("Subject(4) = %q", got)
	}

	pt := For(PtBR)
	if got := pt.Days(1); got != "1 dia" {
		t.Errorf("pt Days(1) = %q", got)
	}
	if got := pt.Days(2); got != "2 dias" {
		t.Errorf("pt Days(2) = %q", got)
	}
}

// Every catalog must cover the same keys as the default one; a missing key
// would silently leak a raw token like "hostname_mismatch" into an alert.
func TestCatalogsAreComplete(t *testing.T) {
	base := catalogs[Default]
	for lang, c := range catalogs {
		for key := range base.groupTitles {
			if c.groupTitles[key] == "" {
				t.Errorf("%s: missing group title for %q", lang, key)
			}
		}
		for key := range base.errorKinds {
			if c.errorKinds[key] == "" {
				t.Errorf("%s: missing error kind label for %q", lang, key)
			}
		}
		if c.subject.one == "" || c.subject.other == "" {
			t.Errorf("%s: incomplete subject plural", lang)
		}
		if c.dateFormat == "" {
			t.Errorf("%s: missing date format", lang)
		}
		for name, s := range map[string]string{
			"lineError":          c.lineError,
			"lineExpired":        c.lineExpired,
			"lineExpiredNoDate":  c.lineExpiredNoDate,
			"lineInvalid":        c.lineInvalid,
			"lineInvalidSubject": c.lineInvalidSubject,
			"lineExpiring":       c.lineExpiring,
			"lineExpiringNoDate": c.lineExpiringNoDate,
		} {
			if s == "" {
				t.Errorf("%s: empty format string %s", lang, name)
			}
		}
	}
}

func TestLines(t *testing.T) {
	en := For(EN)
	if got := en.LineError("a.example.com:443", "dns", "no such host"); got !=
		"a.example.com:443 — check failed (DNS failure): no such host" {
		t.Errorf("LineError = %q", got)
	}
	if got := en.LineExpired("a:443", 10, "2026-01-02"); got != "a:443 — expired 10 days ago, on 2026-01-02" {
		t.Errorf("LineExpired = %q", got)
	}
	if got := en.LineExpired("a:443", 10, ""); got != "a:443 — certificate expired" {
		t.Errorf("LineExpired without date = %q", got)
	}
	if got := en.LineInvalid("a:443", "hostname_mismatch", ""); got != "a:443 — invalid (hostname mismatch)" {
		t.Errorf("LineInvalid = %q", got)
	}
	if got := en.LineInvalid("a:443", "hostname_mismatch", "*.badssl.com"); !strings.Contains(got, `"*.badssl.com"`) {
		t.Errorf("LineInvalid with subject = %q", got)
	}
	if got := en.LineExpiring("a:443", 1, "2026-01-02"); got != "a:443 — expires in 1 day, on 2026-01-02" {
		t.Errorf("LineExpiring = %q", got)
	}
	if got := en.LineExpiring("a:443", 5, ""); got != "a:443 — expires in 5 days" {
		t.Errorf("LineExpiring without date = %q", got)
	}

	pt := For(PtBR)
	if got := pt.LineExpiring("a:443", 12, "2026-01-02"); !strings.Contains(got, "vence em 12 dias") {
		t.Errorf("pt LineExpiring = %q", got)
	}
	if got := pt.GroupTitle("error"); got != "Falhas de conexão" {
		t.Errorf("pt GroupTitle = %q", got)
	}
}

func TestDate(t *testing.T) {
	d := time.Date(2026, 3, 9, 15, 4, 5, 0, time.UTC)
	if got := For(EN).Date(d); got != "2026-03-09" {
		t.Errorf("en Date = %q, want the ISO order", got)
	}
	if got := For(PtBR).Date(d); got != "09/03/2026" {
		t.Errorf("pt-BR Date = %q, want day/month/year", got)
	}
}

func TestUnknownKeysEchoBack(t *testing.T) {
	p := For(EN)
	if got := p.GroupTitle("banana"); got != "banana" {
		t.Errorf("unknown group title should echo back, got %q", got)
	}
	if got := p.ErrorKind("banana"); got != "banana" {
		t.Errorf("unknown error kind should echo back, got %q", got)
	}
}
