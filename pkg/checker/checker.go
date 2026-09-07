// Package checker connects to TLS targets, validates the certificate they
// present and classifies the result according to the report.json v2 contract.
package checker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
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
	Domain string `json:"domain"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	// StartTLS names the plaintext protocol that was upgraded before the
	// handshake. Absent means implicit TLS. It is reported because the port
	// alone does not say it: "mail.example.com:587" gets the negotiation
	// inferred, and an operator reading the report should see which one.
	StartTLS      StartTLS   `json:"starttls,omitempty"`
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
	// The chain fields appear together, and only when an intermediate the
	// server sent expires BEFORE the leaf. That is the case worth a field:
	// nothing in the leaf's own dates hints at it, and when the intermediate
	// goes, the site goes with it.
	ChainExpiresAt     *time.Time `json:"chain_expires_at,omitempty"`
	ChainDaysRemaining *int       `json:"chain_days_remaining,omitempty"`
	ChainSubject       string     `json:"chain_subject,omitempty"`
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
	parsed, err := ParseTarget(target)
	if err != nil {
		return Result{
			Domain:    target,
			CheckedAt: opts.normalized().Now().UTC(),
			Status:    StatusError,
			ErrorKind: KindOther,
			Error:     err.Error(),
		}
	}
	return CheckTarget(ctx, parsed, opts)
}

// CheckTarget is Check on an already parsed target. Callers that keep a
// []Target should use it: Target.String() is lossy on purpose (it drops the
// STARTTLS negotiation, which is not part of the report contract), so a
// round-trip through the string form would silently check the wrong thing.
func CheckTarget(ctx context.Context, target Target, opts Options) Result {
	opts = opts.normalized()
	start := time.Now()

	res := Result{
		Domain:    target.String(),
		Host:      target.Host,
		Port:      target.Port,
		StartTLS:  target.StartTLS,
		CheckedAt: opts.Now().UTC(),
	}

	state, failed, attempts := handshake(ctx, target, opts)
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
		if state, err := insecureHandshake(ctx, target, opts); err == nil {
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

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target.String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()

	// The same deadline covers the plaintext dialogue. Without it a server that
	// accepts the connection and then says nothing would hang this check for as
	// long as the kernel allows, because the STARTTLS exchange happens outside
	// any context-aware API.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return tls.ConnectionState{}, err
		}
	}

	if target.StartTLS != StartTLSNone {
		if err := startTLS(conn, target.StartTLS); err != nil {
			return tls.ConnectionState{}, err
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: insecure, //nolint:gosec // diagnostic path only
		// Monitoring has to see old servers; certificate validation is
		// unchanged, this only widens the handshakes we accept.
		MinVersion: tls.VersionTLS10,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tlsConn.ConnectionState(), nil
}

// applyCertificate fills in the metadata and sets the happy-path status.
func (r *Result) applyCertificate(state tls.ConnectionState, opts Options) {
	if len(state.PeerCertificates) == 0 {
		return
	}
	r.applyMetadata(state, opts)

	// The thresholds run against the whole chain, not just the leaf: a site
	// whose intermediate dies in three days is in trouble in three days,
	// however far away its own certificate looks.
	switch days := r.EffectiveDaysRemaining(); {
	case days < 0:
		// Defensive: verification passed, so this is a clock race.
		r.Status = StatusExpired
		r.ErrorKind = KindExpired
	case days <= opts.CriticalThresholdDays:
		r.Status = StatusCritical
	case days <= opts.AlertThresholdDays:
		r.Status = StatusWarning
	default:
		r.Status = StatusOK
	}
}

// EffectiveDaysRemaining is the deadline that actually matters: the leaf's,
// unless an intermediate in the chain expires first.
func (r Result) EffectiveDaysRemaining() int {
	if r.ChainDaysRemaining != nil && *r.ChainDaysRemaining < r.DaysRemaining {
		return *r.ChainDaysRemaining
	}
	return r.DaysRemaining
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
	r.applyChain(state, opts)
}

// applyChain records the earliest expiry among the intermediates the server
// sent, and only when it falls before the leaf's.
//
// This is the failure that took half the web down when AddTrust and DST Root X3
// went: every leaf was months from expiring, and every leaf was useless. A
// checker that reads PeerCertificates[0] and stops cannot see it coming.
func (r *Result) applyChain(state tls.ConnectionState, opts Options) {
	if len(state.PeerCertificates) < 2 {
		return
	}
	leaf := state.PeerCertificates[0]

	var earliest *x509.Certificate
	for _, cert := range state.PeerCertificates[1:] {
		// A self-signed certificate this far down the chain is the root, which
		// servers send out of habit. Ignore it: trust comes from the local
		// store, and the copy that counts is the one there, with its own dates.
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			continue
		}
		if !cert.NotAfter.Before(leaf.NotAfter) {
			continue
		}
		if earliest == nil || cert.NotAfter.Before(earliest.NotAfter) {
			earliest = cert
		}
	}
	if earliest == nil {
		return
	}

	expires := earliest.NotAfter.UTC()
	days := daysRemaining(opts.Now(), earliest.NotAfter)
	r.ChainExpiresAt = &expires
	r.ChainDaysRemaining = &days
	r.ChainSubject = subjectName(earliest)
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
