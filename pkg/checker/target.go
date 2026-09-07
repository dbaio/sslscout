package checker

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// DefaultPort is used when the target does not name one explicitly.
const DefaultPort = 443

// scheme describes what a URL scheme in the domain list implies: which port to
// use when none is given, and whether the certificate is behind a STARTTLS
// negotiation.
type scheme struct {
	port     int
	startTLS StartTLS
}

// schemes is the explicit half of the notation. "http" maps to 443 on purpose:
// whoever pastes an http:// URL into the list almost always wants the
// certificate of that host, not port 80 in the clear. "tls" is the escape
// hatch — it forces a direct handshake on any port, overriding the inference
// below.
var schemes = map[string]scheme{
	"http":       {443, StartTLSNone},
	"https":      {443, StartTLSNone},
	"tls":        {443, StartTLSNone},
	"ftps":       {990, StartTLSNone},
	"imaps":      {993, StartTLSNone},
	"ldaps":      {636, StartTLSNone},
	"pop3s":      {995, StartTLSNone},
	"smtps":      {465, StartTLSNone},
	"smtp":       {587, StartTLSSMTP},
	"submission": {587, StartTLSSMTP},
	"imap":       {143, StartTLSIMAP},
	"pop3":       {110, StartTLSPOP3},
	"ldap":       {389, StartTLSLDAP},
	"postgres":   {5432, StartTLSPostgres},
	"postgresql": {5432, StartTLSPostgres},
}

// startTLSByPort is the implicit half: what "mail.example.com:587" means when
// nobody wrote a scheme. Every port here is a cleartext port whose TLS variant
// lives somewhere else (587 upgrades, 465 is implicit; 143 upgrades, 993 is
// implicit), so the inference cannot shadow a service that would have answered
// a direct handshake. When it guesses wrong anyway, "tls://host:port" says so.
var startTLSByPort = map[int]StartTLS{
	25:   StartTLSSMTP,
	587:  StartTLSSMTP,
	2525: StartTLSSMTP,
	143:  StartTLSIMAP,
	110:  StartTLSPOP3,
	389:  StartTLSLDAP,
	5432: StartTLSPostgres,
}

// Target is a normalized check target.
type Target struct {
	Host     string
	Port     int
	StartTLS StartTLS
}

// String returns the canonical "host:port" form (with brackets for IPv6). It
// deliberately drops the negotiation: this is what lands in the "domain" field
// of the report, and that field is part of the v2 contract.
func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// key identifies a target for de-duplication. Unlike String it keeps the
// negotiation, so "smtp://mail:587" and "tls://mail:587" stay two entries —
// they ask the server two different questions.
func (t Target) key() string {
	return string(t.StartTLS) + "|" + t.String()
}

// ParseTarget accepts "domain", "domain:port" and URLs ("https://domain/path",
// "smtp://mail.example.com"), returning a normalized host, port and STARTTLS
// negotiation.
func ParseTarget(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, errors.New("empty target")
	}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return Target{}, fmt.Errorf("invalid URL %q: %w", raw, err)
		}
		known, ok := schemes[strings.ToLower(u.Scheme)]
		port := DefaultPort
		if ok {
			port = known.port
		}
		if p := u.Port(); p != "" {
			port, err = parsePort(p)
			if err != nil {
				return Target{}, fmt.Errorf("target %q: %w", raw, err)
			}
		}
		if ok {
			// An explicit scheme is an instruction, not a hint: it wins over
			// whatever the port would have suggested.
			return newTarget(u.Hostname(), port, known.startTLS, raw)
		}
		return newTarget(u.Hostname(), port, startTLSByPort[port], raw)
	}

	// "host:port" (including "[::1]:443").
	if host, port, err := net.SplitHostPort(s); err == nil {
		p, err := parsePort(port)
		if err != nil {
			return Target{}, fmt.Errorf("target %q: %w", raw, err)
		}
		return newTarget(host, p, startTLSByPort[p], raw)
	}

	// What is left is a bare host or an IPv6 without a port ("::1", "[::1]").
	return newTarget(strings.Trim(s, "[]"), DefaultPort, startTLSByPort[DefaultPort], raw)
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

func newTarget(host string, port int, proto StartTLS, raw string) (Target, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return Target{}, fmt.Errorf("target %q: empty host", raw)
	}
	if strings.ContainsAny(host, " \t/\\@#?") {
		return Target{}, fmt.Errorf("target %q: invalid host %q", raw, host)
	}
	return Target{Host: host, Port: port, StartTLS: proto}, nil
}

// ParseTargetList reads the domain list: one entry per line, "#" starts a
// comment (whole line or trailing), blank lines are skipped and duplicates are
// dropped while the original order is preserved.
//
// It returns the valid targets plus an aggregated error with every problem
// found — it never swallows a read error nor a malformed line.
func ParseTargetList(r io.Reader) ([]Target, error) {
	var (
		targets  []Target
		problems []error
		seen     = map[string]bool{}
		lineNo   int
	)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lineNo++
		text := sc.Text()
		if lineNo == 1 {
			text = strings.TrimPrefix(text, "\ufeff") // BOM from Windows editors
		}
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		target, err := ParseTarget(text)
		if err != nil {
			problems = append(problems, fmt.Errorf("line %d: %w", lineNo, err))
			continue
		}
		key := target.key()
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, target)
	}
	if err := sc.Err(); err != nil {
		problems = append(problems, fmt.Errorf("could not read the list: %w", err))
	}
	return targets, errors.Join(problems...)
}

// LoadTargets reads and validates the domain file.
func LoadTargets(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("domain file: %w", err)
	}
	defer f.Close()

	targets, err := ParseTargetList(f)
	if err != nil {
		return targets, fmt.Errorf("%s: %w", path, err)
	}
	return targets, nil
}
