// Package checker connects to TLS targets, validates the certificate they
// present and classifies the result according to the report.json v2 contract.
package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"time"
)

// Defaults used when Options comes in incomplete.
const (
	DefaultTimeout               = 10 * time.Second
	DefaultRetries               = 3
	DefaultRetryBackoff          = 2 * time.Second
	DefaultAlertThresholdDays    = 15
	DefaultCriticalThresholdDays = 7
)

// Result is one item of "results" in report.json v2.
// The field order here is the order they come out in the JSON.
type Result struct {
	Domain        string     `json:"domain"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Status        Status     `json:"status"`
	Valid         bool       `json:"valid"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	IssuedAt      *time.Time `json:"issued_at,omitempty"`
	DaysRemaining int        `json:"days_remaining"`
	Subject       string     `json:"subject,omitempty"`
	Issuer        string     `json:"issuer,omitempty"`
	SerialNumber  string     `json:"serial_number,omitempty"`
	DNSNames      []string   `json:"dns_names,omitempty"`
	TLSVersion    string     `json:"tls_version,omitempty"`
	CipherSuite   string     `json:"cipher_suite,omitempty"`
	// MetadataInsecure marks that the certificate fields above came from a
	// handshake WITHOUT verification (the golden-rule diagnostic pass), not
	// from the verified connection. They are data to investigate the problem,
	// not proof of anything: an attacker on the path controls what shows up here.
	MetadataInsecure bool      `json:"metadata_insecure,omitempty"`
	CheckedAt        time.Time `json:"checked_at"`
	DurationMS       int64     `json:"duration_ms"`
	Attempts         int       `json:"attempts"`
	Error            string    `json:"error,omitempty"`
	ErrorKind        ErrorKind `json:"error_kind,omitempty"`
}

// Options controls one check.
type Options struct {
	Timeout               time.Duration // timeout of each attempt
	Retries               int           // attempts on transient failures (>= 1)
	RetryBackoff          time.Duration // base of the linear backoff (2s, 4s, ...)
	AlertThresholdDays    int
	CriticalThresholdDays int
	Now                   func() time.Time // injectable in tests
}

func (o Options) normalized() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Retries < 1 {
		o.Retries = DefaultRetries
	}
	if o.RetryBackoff < 0 {
		o.RetryBackoff = 0
	} else if o.RetryBackoff == 0 {
		o.RetryBackoff = DefaultRetryBackoff
	}
	if o.AlertThresholdDays <= 0 {
		o.AlertThresholdDays = DefaultAlertThresholdDays
	}
	if o.CriticalThresholdDays <= 0 {
		o.CriticalThresholdDays = DefaultCriticalThresholdDays
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Check verifies one target ("domain", "domain:port" or a URL) and always
// returns a Result — failures become status/error_kind, never a bare error.
func Check(ctx context.Context, target string, opts Options) Result {
	opts = opts.normalized()
	start := time.Now()

	res := Result{
		Domain:    target,
		CheckedAt: opts.Now().UTC(),
	}

	parsed, err := ParseTarget(target)
	if err != nil {
		res.Status = StatusError
		res.ErrorKind = KindOther
		res.Error = err.Error()
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	res.Domain = parsed.String()
	res.Host = parsed.Host
	res.Port = parsed.Port

	state, failed, attempts := handshake(ctx, parsed, opts)
	res.Attempts = attempts

	if failed == nil {
		res.applyCertificate(state, opts)
		if res.Status == "" { // no certificate presented
			res.Status = StatusError
			res.ErrorKind = KindNoCertificate
			res.Error = "the server presented no certificate"
		}
		res.Valid = res.Status.Valid()
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}

	res.Status = failed.class.status
	res.ErrorKind = failed.class.kind
	res.Error = failed.err.Error()

	// Golden rule: when *verification* fails we reconnect with
	// InsecureSkipVerify only to extract diagnostic metadata. The status stays
	// expired/invalid — the reconnection never validates the domain.
	if failed.class.certErr {
		if state, err := insecureHandshake(ctx, parsed, opts); err == nil {
			res.applyMetadata(state, opts)
			res.refineCertStatus(state, opts)
			// Flag the provenance: this metadata was NOT verified.
			res.MetadataInsecure = true
		}
	}

	res.Valid = res.Status.Valid()
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

type handshakeFailure struct {
	err   error
	class failure
}

// handshake attempts the handshake with full verification, retrying transient
// failures only, with a linear backoff.
func handshake(ctx context.Context, target Target, opts Options) (tls.ConnectionState, *handshakeFailure, int) {
	var (
		state   tls.ConnectionState
		last    *handshakeFailure
		attempt int
	)

	for attempt = 1; attempt <= opts.Retries; attempt++ {
		st, err := dial(ctx, target, opts.Timeout, false)
		if err == nil {
			return st, nil, attempt
		}
		class := classify(err)
		last = &handshakeFailure{err: err, class: class}

		if !class.retryable || attempt == opts.Retries || ctx.Err() != nil {
			break
		}
		wait := time.Duration(attempt) * opts.RetryBackoff
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return state, last, attempt
			case <-t.C:
			}
		}
	}
	if attempt > opts.Retries {
		attempt = opts.Retries
	}
	return state, last, attempt
}

func insecureHandshake(ctx context.Context, target Target, opts Options) (tls.ConnectionState, error) {
	return dial(ctx, target, opts.Timeout, true)
}

func dial(ctx context.Context, target Target, timeout time.Duration, insecure bool) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         target.Host,
			InsecureSkipVerify: insecure, //nolint:gosec // diagnostic path only
			// Monitoring has to see old servers; certificate validation is
			// unchanged, this only widens the handshakes we accept.
			MinVersion: tls.VersionTLS10,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", target.String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, fmt.Errorf("unexpected connection of type %T", conn)
	}
	return tlsConn.ConnectionState(), nil
}

// applyCertificate fills in the metadata and sets the happy-path status.
func (r *Result) applyCertificate(state tls.ConnectionState, opts Options) {
	if len(state.PeerCertificates) == 0 {
		return
	}
	r.applyMetadata(state, opts)

	switch {
	case r.DaysRemaining < 0:
		// Defensive: verification passed, so this is a clock race.
		r.Status = StatusExpired
		r.ErrorKind = KindExpired
	case r.DaysRemaining <= opts.CriticalThresholdDays:
		r.Status = StatusCritical
	case r.DaysRemaining <= opts.AlertThresholdDays:
		r.Status = StatusWarning
	default:
		r.Status = StatusOK
	}
}

// applyMetadata copies the leaf certificate data into the Result.
func (r *Result) applyMetadata(state tls.ConnectionState, opts Options) {
	if len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	now := opts.Now()

	expires := cert.NotAfter.UTC()
	issued := cert.NotBefore.UTC()
	r.ExpiresAt = &expires
	r.IssuedAt = &issued
	r.DaysRemaining = daysRemaining(now, cert.NotAfter)
	r.Subject = subjectName(cert)
	r.Issuer = issuerName(cert)
	if cert.SerialNumber != nil {
		r.SerialNumber = fmt.Sprintf("%x", cert.SerialNumber)
	}
	r.DNSNames = cert.DNSNames
	r.TLSVersion = versionName(state.Version)
	if state.CipherSuite != 0 {
		r.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	}
}

// refineCertStatus uses the diagnostic metadata to tell "expired" apart from
// "not yet valid" — x509 uses the same reason (Expired) for both cases.
func (r *Result) refineCertStatus(state tls.ConnectionState, opts Options) {
	if len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	now := opts.Now()

	switch {
	case now.After(cert.NotAfter):
		r.Status = StatusExpired
		r.ErrorKind = KindExpired
	case now.Before(cert.NotBefore):
		r.Status = StatusInvalid
		r.ErrorKind = KindNotYetValid
	case r.ErrorKind == KindExpired:
		// Classified as expired, yet the leaf is inside its validity window:
		// the problem is in the chain (some intermediate/root out of validity).
		r.Status = StatusInvalid
		r.ErrorKind = KindUntrusted
	}
}

func daysRemaining(now, notAfter time.Time) int {
	return int(math.Floor(notAfter.Sub(now).Hours() / 24))
}

func subjectName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.String()
}

func issuerName(cert *x509.Certificate) string {
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return cert.Issuer.String()
}
