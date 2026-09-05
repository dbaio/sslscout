package checker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func testOptions(now time.Time) Options {
	return Options{
		Timeout:               3 * time.Second,
		Retries:               3,
		RetryBackoff:          time.Millisecond, // tests do not sleep for 2s
		AlertThresholdDays:    15,
		CriticalThresholdDays: 7,
		Now:                   func() time.Time { return now },
	}
}

// certificate generates a leaf certificate signed by a test CA, so that subject
// and issuer are distinguishable.
func certificate(t *testing.T, notBefore, notAfter time.Time, names ...string) *x509.Certificate {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SSLScout Test CA"},
		NotBefore:             notBefore.Add(-24 * time.Hour),
		NotAfter:              notAfter.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("could not create the CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("could not re-read the CA: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x0a1b2c3d),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("could not create the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not re-read the certificate: %v", err)
	}
	return cert
}

func TestStatusByRemainingDays(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		expires time.Time
		status  Status
		days    int
		valid   bool
		noCert  bool
	}{
		{name: "plenty of time", expires: now.Add(90 * 24 * time.Hour), status: StatusOK, days: 90, valid: true},
		{name: "exactly at the warning threshold", expires: now.Add(15 * 24 * time.Hour), status: StatusWarning, days: 15, valid: true},
		{name: "inside the warning window", expires: now.Add(10 * 24 * time.Hour), status: StatusWarning, days: 10, valid: true},
		{name: "exactly at the critical threshold", expires: now.Add(7 * 24 * time.Hour), status: StatusCritical, days: 7, valid: true},
		{name: "expires today", expires: now.Add(6 * time.Hour), status: StatusCritical, days: 0, valid: true},
		{name: "expired yesterday", expires: now.Add(-30 * time.Hour), status: StatusExpired, days: -2, valid: false},
		{name: "no certificate", noCert: true, status: "", days: 0, valid: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
			if !c.noCert {
				state.PeerCertificates = []*x509.Certificate{
					certificate(t, now.Add(-24*time.Hour), c.expires, "example.test"),
				}
			}

			var r Result
			r.applyCertificate(state, testOptions(now))

			if r.Status != c.status {
				t.Errorf("status = %q, want %q", r.Status, c.status)
			}
			if r.DaysRemaining != c.days {
				t.Errorf("days_remaining = %d, want %d", r.DaysRemaining, c.days)
			}
			if r.Status.Valid() != c.valid {
				t.Errorf("valid = %v, want %v", r.Status.Valid(), c.valid)
			}
			if c.noCert {
				return
			}
			if r.Subject != "example.test" || r.Issuer != "SSLScout Test CA" {
				t.Errorf("subject/issuer = %q/%q", r.Subject, r.Issuer)
			}
			if r.SerialNumber != "a1b2c3d" {
				t.Errorf("serial_number = %q, want the hexadecimal 'a1b2c3d'", r.SerialNumber)
			}
			if r.TLSVersion != "TLS 1.3" || r.CipherSuite != "TLS_AES_128_GCM_SHA256" {
				t.Errorf("tls/cipher = %q/%q", r.TLSVersion, r.CipherSuite)
			}
			if r.ExpiresAt == nil || r.IssuedAt == nil {
				t.Fatal("expires_at and issued_at should be filled in")
			}
		})
	}
}

// TestCheckSelfSignedCertificate exercises a real handshake: the httptest
// certificate is not trusted, so the status must be "invalid" — but the
// metadata must come from the diagnostic reconnection (the golden rule).
func TestCheckSelfSignedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	res := Check(context.Background(), srv.Listener.Addr().String(), testOptions(time.Now()))

	if res.Status != StatusInvalid {
		t.Errorf("status = %q, want %q (error: %s)", res.Status, StatusInvalid, res.Error)
	}
	if res.ErrorKind != KindUntrusted {
		t.Errorf("error_kind = %q, want %q", res.ErrorKind, KindUntrusted)
	}
	if res.Valid {
		t.Error("valid should be false: the insecure reconnection is diagnostic only")
	}
	// The central point of fix #1: a permanent error is not retried.
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 — a certificate error must not be retried", res.Attempts)
	}
	// And the central point of fix #2: the metadata must not be lost.
	if res.ExpiresAt == nil || res.IssuedAt == nil {
		t.Fatal("expires_at/issued_at should come from the diagnostic handshake")
	}
	if res.Subject == "" || res.Issuer == "" || res.SerialNumber == "" {
		t.Errorf("incomplete metadata: subject=%q issuer=%q serial=%q",
			res.Subject, res.Issuer, res.SerialNumber)
	}
	if res.TLSVersion == "" || res.CipherSuite == "" {
		t.Errorf("empty tls_version/cipher_suite: %q/%q", res.TLSVersion, res.CipherSuite)
	}
	if len(res.DNSNames) == 0 {
		t.Error("dns_names should come from the diagnostic certificate")
	}
	if res.Host == "" || res.Port == 0 || res.Domain != res.Host+":"+strconv.Itoa(res.Port) {
		t.Errorf("inconsistent domain/host/port: %q %q %d", res.Domain, res.Host, res.Port)
	}
	if !res.MetadataInsecure {
		t.Error("metadata_insecure should flag that these fields were not verified")
	}
}

// TestCheckServerWithoutTLS: dialing TLS against a plain HTTP server is a
// permanent protocol error and must not be retried.
func TestCheckServerWithoutTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	res := Check(context.Background(), srv.Listener.Addr().String(), testOptions(time.Now()))

	if res.Status != StatusError {
		t.Errorf("status = %q, want %q", res.Status, StatusError)
	}
	if res.ErrorKind != KindProtocol {
		t.Errorf("error_kind = %q, want %q", res.ErrorKind, KindProtocol)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", res.Attempts)
	}
	if res.ExpiresAt != nil {
		t.Error("without a handshake there is no certificate metadata")
	}
}

// TestCheckConnectionRefused: a transient failure, where retrying does pay off.
func TestCheckConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open the port: %v", err)
	}
	address := ln.Addr().String()
	ln.Close() // the port now refuses connections

	opts := testOptions(time.Now())
	opts.Retries = 2
	res := Check(context.Background(), address, opts)

	if res.Status != StatusError {
		t.Fatalf("status = %q, want %q (error: %s)", res.Status, StatusError, res.Error)
	}
	if res.ErrorKind != KindRefused && res.ErrorKind != KindTimeout {
		t.Errorf("error_kind = %q, want refused", res.ErrorKind)
	}
	if res.Attempts != 2 {
		t.Errorf("attempts = %d, want 2 — a transient failure must be retried", res.Attempts)
	}
}

func TestCheckCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := Check(ctx, "example.com", testOptions(time.Now()))
	if res.Status != StatusError {
		t.Errorf("status = %q, want %q", res.Status, StatusError)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 with a cancelled context", res.Attempts)
	}
}

func TestCheckInvalidTarget(t *testing.T) {
	res := Check(context.Background(), "example.com:banana", testOptions(time.Now()))
	if res.Status != StatusError || res.ErrorKind != KindOther {
		t.Errorf("status/kind = %q/%q, want error/other", res.Status, res.ErrorKind)
	}
	if res.Error == "" {
		t.Error("the parsing error should show up in the report")
	}
}

func TestRefineCertStatusNotYetValid(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	cert := certificate(t, now.Add(48*time.Hour), now.Add(90*24*time.Hour), "future.test")
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	r := Result{Status: StatusExpired, ErrorKind: KindExpired}
	r.refineCertStatus(state, testOptions(now))

	if r.Status != StatusInvalid || r.ErrorKind != KindNotYetValid {
		t.Errorf("status/kind = %q/%q, want invalid/not_yet_valid", r.Status, r.ErrorKind)
	}
}
