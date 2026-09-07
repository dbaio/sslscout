package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

// Status is the final state of a target. Closed vocabulary (v2 contract).
type Status string

const (
	StatusOK       Status = "ok"
	StatusWarning  Status = "warning"
	StatusCritical Status = "critical"
	StatusExpired  Status = "expired"
	StatusInvalid  Status = "invalid"
	StatusError    Status = "error"
)

// ErrorKind classifies the cause of a failure. Closed vocabulary (v2 contract).
type ErrorKind string

const (
	KindDNS              ErrorKind = "dns"
	KindTimeout          ErrorKind = "timeout"
	KindRefused          ErrorKind = "refused"
	KindExpired          ErrorKind = "expired"
	KindHostnameMismatch ErrorKind = "hostname_mismatch"
	KindUntrusted        ErrorKind = "untrusted"
	KindNotYetValid      ErrorKind = "not_yet_valid"
	KindNoCertificate    ErrorKind = "no_certificate"
	KindProtocol         ErrorKind = "protocol"
	KindOther            ErrorKind = "other"
)

// Severity orders the statuses from least to most serious. It is the same scale
// used by -fail-on (none < warning < critical < invalid < error) and by the
// report ordering; "expired" sits between "invalid" and "error" because an
// expired certificate is a confirmed failure, while "error" may hide anything.
func (s Status) Severity() int {
	switch s {
	case StatusOK:
		return 0
	case StatusWarning:
		return 1
	case StatusCritical:
		return 2
	case StatusInvalid:
		return 3
	case StatusExpired:
		return 4
	case StatusError:
		return 5
	default:
		return -1
	}
}

// Valid reports whether the certificate was verified successfully (even if it
// is close to expiring).
func (s Status) Valid() bool {
	return s == StatusOK || s == StatusWarning || s == StatusCritical
}

// SeverityFromName translates the name used in -fail-on into a minimum
// severity. "none" returns a value above every status, i.e. it never fires.
func SeverityFromName(name string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "none", "":
		return 1 << 30, true
	case "warning":
		return StatusWarning.Severity(), true
	case "critical":
		return StatusCritical.Severity(), true
	case "invalid":
		return StatusInvalid.Severity(), true
	case "expired":
		return StatusExpired.Severity(), true
	case "error":
		return StatusError.Severity(), true
	default:
		return 0, false
	}
}

// failure is the internal classification of a connection/handshake error.
type failure struct {
	kind      ErrorKind
	status    Status
	retryable bool // worth retrying? only transient failures are
	certErr   bool // certificate verification failed (we have a cert to inspect)
}

// classify decides the error_kind, the status and — the central point — whether
// the error is transient. Certificate verification errors are permanent:
// retrying them only burns seconds per broken domain.
func classify(err error) failure {
	if err == nil {
		return failure{}
	}

	// --- Certificate errors: permanent, and worth diagnostic metadata ---
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return failure{kind: KindHostnameMismatch, status: StatusInvalid, certErr: true}
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return failure{kind: KindUntrusted, status: StatusInvalid, certErr: true}
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		f := failure{kind: KindUntrusted, status: StatusInvalid, certErr: true}
		switch invalidErr.Reason {
		case x509.Expired:
			// x509 uses "Expired" both for expired and for not-yet-valid; the
			// diagnostic pass refines it later by looking at NotBefore/NotAfter.
			f.kind, f.status = KindExpired, StatusExpired
		case x509.NameMismatch:
			f.kind = KindHostnameMismatch
		}
		return f
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return failure{kind: KindUntrusted, status: StatusInvalid, certErr: true}
	}
	// Safety net: any x509 error that escapes the types above.
	msg := err.Error()
	if strings.Contains(msg, "x509:") {
		return failure{kind: KindUntrusted, status: StatusInvalid, certErr: true}
	}

	// --- Plaintext negotiation ---
	// The server answered, and the answer was a refusal: no upgrade, wrong
	// banner, SSL disabled. Retrying replays the same conversation, so this is
	// permanent. An I/O failure during the same dialogue is NOT wrapped in this
	// type, and falls through to the network cases below where it belongs.
	var upgradeErr *startTLSError
	if errors.As(err, &upgradeErr) {
		return failure{kind: KindProtocol, status: StatusError}
	}

	// --- Network failures ---
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// NXDOMAIN is permanent; a resolver SERVFAIL/timeout is not.
		return failure{kind: KindDNS, status: StatusError, retryable: !dnsErr.IsNotFound}
	}

	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return failure{kind: KindTimeout, status: StatusError, retryable: true}
	}
	if errors.Is(err, context.Canceled) {
		return failure{kind: KindOther, status: StatusError}
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(msg, "connection refused") {
		return failure{kind: KindRefused, status: StatusError, retryable: true}
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") {
		return failure{kind: KindOther, status: StatusError, retryable: true}
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		strings.Contains(msg, "unreachable") {
		return failure{kind: KindOther, status: StatusError, retryable: true}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return failure{kind: KindProtocol, status: StatusError, retryable: true}
	}

	var headerErr tls.RecordHeaderError
	if errors.As(err, &headerErr) {
		// The server does not speak TLS on this port: retrying changes nothing.
		return failure{kind: KindProtocol, status: StatusError}
	}
	if strings.Contains(msg, "tls: ") {
		return failure{kind: KindProtocol, status: StatusError}
	}

	// Unknown: treated as transient (the conservative behaviour).
	return failure{kind: KindOther, status: StatusError, retryable: true}
}

// versionName translates the negotiated TLS version into the contract format
// ("TLS 1.3"). Hand-written so it does not depend on the toolchain version.
func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionSSL30: //nolint:staticcheck // only to label ancient servers
		return "SSL 3.0"
	case 0:
		return ""
	default:
		return "unknown"
	}
}
