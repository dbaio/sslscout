package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestClassify(t *testing.T) {
	emptyCert := &x509.Certificate{}

	cases := []struct {
		name      string
		err       error
		kind      ErrorKind
		status    Status
		retryable bool
		certErr   bool
	}{
		{
			name: "an expired certificate is never retried",
			err: &tls.CertificateVerificationError{
				Err: x509.CertificateInvalidError{Cert: emptyCert, Reason: x509.Expired},
			},
			kind: KindExpired, status: StatusExpired, retryable: false, certErr: true,
		},
		{
			name: "a hostname mismatch is never retried",
			err: &tls.CertificateVerificationError{
				Err: x509.HostnameError{Certificate: emptyCert, Host: "wrong.example.com"},
			},
			kind: KindHostnameMismatch, status: StatusInvalid, retryable: false, certErr: true,
		},
		{
			name: "an untrusted chain is never retried",
			err: &tls.CertificateVerificationError{
				Err: x509.UnknownAuthorityError{Cert: emptyCert},
			},
			kind: KindUntrusted, status: StatusInvalid, retryable: false, certErr: true,
		},
		{
			name: "a generic x509 reason becomes untrusted",
			err: &tls.CertificateVerificationError{
				Err: x509.CertificateInvalidError{Cert: emptyCert, Reason: x509.CANotAuthorizedForThisName},
			},
			kind: KindUntrusted, status: StatusInvalid, retryable: false, certErr: true,
		},
		{
			name: "an x509 error recognizable only by its text",
			err:  errors.New("tls: failed to verify certificate: x509: something new"),
			kind: KindUntrusted, status: StatusInvalid, retryable: false, certErr: true,
		},
		{
			name: "NXDOMAIN is permanent",
			err:  &net.DNSError{Err: "no such host", Name: "nonexistent.example", IsNotFound: true},
			kind: KindDNS, status: StatusError, retryable: false,
		},
		{
			name: "a temporary DNS failure is transient",
			err:  &net.DNSError{Err: "server misbehaving", Name: "x.example", IsTemporary: true},
			kind: KindDNS, status: StatusError, retryable: true,
		},
		{
			name: "a context deadline is a timeout",
			err:  context.DeadlineExceeded,
			kind: KindTimeout, status: StatusError, retryable: true,
		},
		{
			name: "a network timeout is transient",
			err:  &net.OpError{Op: "dial", Err: timeoutError()},
			kind: KindTimeout, status: StatusError, retryable: true,
		},
		{
			name: "a refused connection is transient",
			err:  &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
			kind: KindRefused, status: StatusError, retryable: true,
		},
		{
			name: "a connection reset is transient",
			err:  &net.OpError{Op: "read", Err: syscall.ECONNRESET},
			kind: KindOther, status: StatusError, retryable: true,
		},
		{
			name: "an EOF during the handshake is transient",
			err:  io.EOF,
			kind: KindProtocol, status: StatusError, retryable: true,
		},
		{
			name: "a server that does not speak TLS is permanent",
			err:  tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			kind: KindProtocol, status: StatusError, retryable: false,
		},
		{
			name: "a cancellation is not retried",
			err:  context.Canceled,
			kind: KindOther, status: StatusError, retryable: false,
		},
		{
			name: "an unknown error is treated as transient",
			err:  errors.New("something odd happened"),
			kind: KindOther, status: StatusError, retryable: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := classify(c.err)
			if f.kind != c.kind {
				t.Errorf("kind = %q, want %q", f.kind, c.kind)
			}
			if f.status != c.status {
				t.Errorf("status = %q, want %q", f.status, c.status)
			}
			if f.retryable != c.retryable {
				t.Errorf("retryable = %v, want %v", f.retryable, c.retryable)
			}
			if f.certErr != c.certErr {
				t.Errorf("certErr = %v, want %v", f.certErr, c.certErr)
			}
		})
	}
}

// timeoutError returns an error implementing net.Error with Timeout() == true.
func timeoutError() error { return errTimeout{} }

type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

func TestSeverityIsOrdered(t *testing.T) {
	order := []Status{StatusOK, StatusWarning, StatusCritical, StatusInvalid, StatusExpired, StatusError}
	for i := 1; i < len(order); i++ {
		if order[i-1].Severity() >= order[i].Severity() {
			t.Errorf("%q should be less serious than %q", order[i-1], order[i])
		}
	}
	for _, s := range []Status{StatusOK, StatusWarning, StatusCritical} {
		if !s.Valid() {
			t.Errorf("%q should count as valid", s)
		}
	}
	for _, s := range []Status{StatusExpired, StatusInvalid, StatusError} {
		if s.Valid() {
			t.Errorf("%q should not count as valid", s)
		}
	}
}

func TestSeverityFromName(t *testing.T) {
	cases := []struct {
		name      string
		fires     []Status
		doesNot   []Status
		validName bool
	}{
		{name: "none", doesNot: []Status{StatusError, StatusExpired, StatusOK}, validName: true},
		{name: "warning", fires: []Status{StatusWarning, StatusCritical, StatusError}, doesNot: []Status{StatusOK}, validName: true},
		{name: "invalid", fires: []Status{StatusInvalid, StatusExpired, StatusError}, doesNot: []Status{StatusCritical, StatusWarning, StatusOK}, validName: true},
		{name: "error", fires: []Status{StatusError}, doesNot: []Status{StatusExpired, StatusInvalid}, validName: true},
		{name: "ERROR", fires: []Status{StatusError}, validName: true},
		{name: "banana", validName: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			threshold, ok := SeverityFromName(c.name)
			if ok != c.validName {
				t.Fatalf("SeverityFromName(%q) ok = %v, want %v", c.name, ok, c.validName)
			}
			if !ok {
				return
			}
			for _, s := range c.fires {
				if s.Severity() < threshold {
					t.Errorf("-fail-on=%s should fire for %q", c.name, s)
				}
			}
			for _, s := range c.doesNot {
				if s.Severity() >= threshold {
					t.Errorf("-fail-on=%s should not fire for %q", c.name, s)
				}
			}
		})
	}
}

func TestVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS13: "TLS 1.3",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS10: "TLS 1.0",
		0:                "",
		0x9999:           "unknown",
	}
	for v, want := range cases {
		if got := versionName(v); got != want {
			t.Errorf("versionName(%#x) = %q, want %q", v, got, want)
		}
	}
}
