// Package i18n holds the message catalogs used to localize the alerts that
// SSLScout sends to Slack, Microsoft Teams and e-mail.
//
// Only the *notifications* are translated. Everything else the binary prints —
// log lines, flag help, error messages — stays in English, because that output
// belongs to operators reading a terminal or a CI log, not to the people who
// receive the alert. The dashboard has its own translation layer, written in
// JavaScript inside public/index.html.
//
// Adding a language means adding one entry to catalogs and one to Supported;
// nothing outside this package needs to change.
package i18n

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Lang is a BCP 47-ish language tag supported by the catalogs below.
type Lang string

const (
	// EN is the default: alerts go out in English unless configured otherwise.
	EN Lang = "en"
	// PtBR is Brazilian Portuguese.
	PtBR Lang = "pt-BR"

	// Default is used when nothing is configured.
	Default = EN
)

// Supported lists every language with a catalog, in a stable order.
func Supported() []Lang {
	langs := make([]Lang, 0, len(catalogs))
	for l := range catalogs {
		langs = append(langs, l)
	}
	sort.Slice(langs, func(i, j int) bool { return langs[i] < langs[j] })
	return langs
}

// SupportedNames is Supported as plain strings, handy for error messages.
func SupportedNames() []string {
	langs := Supported()
	names := make([]string, len(langs))
	for i, l := range langs {
		names[i] = string(l)
	}
	return names
}

// Parse normalizes a user-supplied language name ("PT_br", "pt", "en-US") into
// a supported Lang. An empty name means "use the default", which is not an
// error. Anything else that has no catalog reports ok=false so the caller can
// refuse the configuration instead of silently falling back.
func Parse(name string) (Lang, bool) {
	s := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(name, "_", "-")))
	if s == "" {
		return Default, true
	}
	for l := range catalogs {
		if strings.ToLower(string(l)) == s {
			return l, true
		}
	}
	// A region we do not carry a catalog for still picks the base language:
	// "en-GB" is close enough to "en", "pt-PT" close enough to "pt-BR".
	switch base, _, _ := strings.Cut(s, "-"); base {
	case "en":
		return EN, true
	case "pt":
		return PtBR, true
	}
	return Default, false
}

// Printer renders the localized strings for one language.
type Printer struct {
	lang Lang
	c    catalog
}

// For returns the Printer of a language, falling back to the default catalog
// for a language that was never registered.
func For(lang Lang) Printer {
	if c, ok := catalogs[lang]; ok {
		return Printer{lang: lang, c: c}
	}
	return Printer{lang: Default, c: catalogs[Default]}
}

// Lang reports which catalog this Printer ended up using.
func (p Printer) Lang() Lang { return p.lang }

// Subject is the e-mail subject and the card title: "SSLScout: 3 certificates
// need attention".
func (p Printer) Subject(n int) string { return p.c.subject.format(n) }

// GroupTitle is the heading of a block of alerts, keyed by the checker status
// ("error", "expired", "invalid", "critical", "warning").
func (p Printer) GroupTitle(status string) string {
	if t, ok := p.c.groupTitles[status]; ok {
		return t
	}
	return status
}

// ErrorKind is the human-readable label of a report.json error_kind. An unknown
// kind is echoed back untranslated — better a raw token than a blank.
func (p Printer) ErrorKind(kind string) string {
	if t, ok := p.c.errorKinds[kind]; ok {
		return t
	}
	return kind
}

// MoreInfo is the closing line of an alert, pointing at the hosted dashboard.
// It is only rendered when a dashboard URL is configured.
func (p Printer) MoreInfo(url string) string {
	return fmt.Sprintf(p.c.moreInfo, url)
}

// Days formats a day count with the right plural: "1 day", "3 days".
func (p Printer) Days(n int) string { return p.c.days.format(n) }

// Date formats a date the way readers of this language expect. English keeps
// the unambiguous ISO order; pt-BR uses the local day/month/year.
func (p Printer) Date(t time.Time) string { return t.Format(p.c.dateFormat) }

// LineError describes a domain that could not be checked at all.
func (p Printer) LineError(domain, kind, message string) string {
	return fmt.Sprintf(p.c.lineError, domain, p.ErrorKind(kind), message)
}

// LineExpired describes an expired certificate. days is how many days ago it
// expired (a positive number) and date is the already formatted expiry date.
func (p Printer) LineExpired(domain string, days int, date string) string {
	if date == "" {
		return fmt.Sprintf(p.c.lineExpiredNoDate, domain)
	}
	return fmt.Sprintf(p.c.lineExpired, domain, p.Days(days), date)
}

// LineInvalid describes a certificate that was read but failed verification.
// subject may be empty when the server presented nothing usable.
func (p Printer) LineInvalid(domain, kind, subject string) string {
	if subject == "" {
		return fmt.Sprintf(p.c.lineInvalid, domain, p.ErrorKind(kind))
	}
	return fmt.Sprintf(p.c.lineInvalidSubject, domain, p.ErrorKind(kind), subject)
}

// LineExpiring describes a certificate that is still valid but close to the
// alert or critical threshold.
func (p Printer) LineExpiring(domain string, days int, date string) string {
	if date == "" {
		return fmt.Sprintf(p.c.lineExpiringNoDate, domain, p.Days(days))
	}
	return fmt.Sprintf(p.c.lineExpiring, domain, p.Days(days), date)
}

// plural carries the two forms English and Portuguese need. A language with a
// richer plural system would need a function here instead of two strings.
type plural struct{ one, other string }

func (p plural) format(n int) string {
	if n == 1 || n == -1 {
		return fmt.Sprintf(p.one, n)
	}
	return fmt.Sprintf(p.other, n)
}

type catalog struct {
	subject            plural
	days               plural
	dateFormat         string // a Go reference layout, not a strftime pattern
	moreInfo           string // takes the dashboard URL
	groupTitles        map[string]string
	errorKinds         map[string]string
	lineError          string // domain, kind, message
	lineExpired        string // domain, days, date
	lineExpiredNoDate  string // domain
	lineInvalid        string // domain, kind
	lineInvalidSubject string // domain, kind, subject
	lineExpiring       string // domain, days, date
	lineExpiringNoDate string // domain, days
}

var catalogs = map[Lang]catalog{
	EN: {
		subject: plural{
			one:   "SSLScout: %d certificate needs attention",
			other: "SSLScout: %d certificates need attention",
		},
		days:       plural{one: "%d day", other: "%d days"},
		dateFormat: "2006-01-02",
		moreInfo:   "Learn more at %s",
		groupTitles: map[string]string{
			"error":    "Connection failures",
			"expired":  "Expired certificates",
			"invalid":  "Invalid certificates",
			"critical": "Critical expiry",
			"warning":  "Expiring soon",
		},
		errorKinds: map[string]string{
			"dns":               "DNS failure",
			"timeout":           "timed out",
			"refused":           "connection refused",
			"expired":           "certificate expired",
			"hostname_mismatch": "hostname mismatch",
			"untrusted":         "untrusted chain",
			"not_yet_valid":     "not yet valid",
			"no_certificate":    "no certificate presented",
			"protocol":          "protocol error",
			"other":             "other",
		},
		lineError:          "%s — check failed (%s): %s",
		lineExpired:        "%s — expired %s ago, on %s",
		lineExpiredNoDate:  "%s — certificate expired",
		lineInvalid:        "%s — invalid (%s)",
		lineInvalidSubject: "%s — invalid (%s, certificate for %q)",
		lineExpiring:       "%s — expires in %s, on %s",
		lineExpiringNoDate: "%s — expires in %s",
	},
	PtBR: {
		subject: plural{
			one:   "SSLScout: %d certificado precisando de atenção",
			other: "SSLScout: %d certificados precisando de atenção",
		},
		days:       plural{one: "%d dia", other: "%d dias"},
		dateFormat: "02/01/2006",
		moreInfo:   "Saiba mais em %s",
		groupTitles: map[string]string{
			"error":    "Falhas de conexão",
			"expired":  "Certificados expirados",
			"invalid":  "Certificados inválidos",
			"critical": "Vencimento crítico",
			"warning":  "Vencimento próximo",
		},
		errorKinds: map[string]string{
			"dns":               "falha de DNS",
			"timeout":           "tempo esgotado",
			"refused":           "conexão recusada",
			"expired":           "certificado expirado",
			"hostname_mismatch": "hostname não confere",
			"untrusted":         "cadeia não confiável",
			"not_yet_valid":     "ainda não válido",
			"no_certificate":    "nenhum certificado apresentado",
			"protocol":          "erro de protocolo",
			"other":             "outro",
		},
		lineError:          "%s — falha na checagem (%s): %s",
		lineExpired:        "%s — expirado há %s, em %s",
		lineExpiredNoDate:  "%s — certificado expirado",
		lineInvalid:        "%s — inválido (%s)",
		lineInvalidSubject: "%s — inválido (%s, certificado de %q)",
		lineExpiring:       "%s — vence em %s, em %s",
		lineExpiringNoDate: "%s — vence em %s",
	},
}
