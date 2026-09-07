package checker

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// script is the server half of a negotiation: it plays a canned dialogue and
// reports what went wrong, if anything.
type script func(t *testing.T, conn net.Conn)

func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Errorf("the server could not read the command: %v", err)
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}

func smtpServer(greeting, ehlo, starttls string) script {
	return func(t *testing.T, conn net.Conn) {
		t.Helper()
		r := bufio.NewReader(conn)
		io.WriteString(conn, greeting)
		if !strings.HasPrefix(greeting, "220") {
			return
		}
		if cmd := readLine(t, r); !strings.HasPrefix(cmd, "EHLO") {
			t.Errorf("the client sent %q, want EHLO", cmd)
			return
		}
		io.WriteString(conn, ehlo)
		if !strings.HasPrefix(ehlo, "250") {
			return
		}
		if cmd := readLine(t, r); cmd != "STARTTLS" {
			t.Errorf("the client sent %q, want STARTTLS", cmd)
			return
		}
		io.WriteString(conn, starttls)
	}
}

func TestStartTLSNegotiation(t *testing.T) {
	cases := []struct {
		name    string
		proto   StartTLS
		server  script
		wantErr bool
	}{
		{
			name:   "smtp accepts",
			proto:  StartTLSSMTP,
			server: smtpServer("220 mail.test ESMTP ready\r\n", "250-mail.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n", "220 2.0.0 Ready to start TLS\r\n"),
		},
		{
			name:    "smtp refuses the connection in the greeting",
			proto:   StartTLSSMTP,
			server:  smtpServer("554 no service here\r\n", "", ""),
			wantErr: true,
		},
		{
			name:    "smtp without the STARTTLS extension",
			proto:   StartTLSSMTP,
			server:  smtpServer("220 mail.test ESMTP ready\r\n", "250 mail.test\r\n", "502 5.5.1 unknown command\r\n"),
			wantErr: true,
		},
		{
			name:  "imap accepts after an untagged line",
			proto: StartTLSIMAP,
			server: func(t *testing.T, conn net.Conn) {
				r := bufio.NewReader(conn)
				io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
				if cmd := readLine(t, r); !strings.HasSuffix(cmd, "STARTTLS") {
					t.Errorf("the client sent %q, want STARTTLS", cmd)
					return
				}
				io.WriteString(conn, "* BYE nothing to see\r\na001 OK Begin TLS negotiation now\r\n")
			},
		},
		{
			name:  "imap refuses",
			proto: StartTLSIMAP,
			server: func(t *testing.T, conn net.Conn) {
				r := bufio.NewReader(conn)
				io.WriteString(conn, "* OK ready\r\n")
				readLine(t, r)
				io.WriteString(conn, "a001 BAD unsupported\r\n")
			},
			wantErr: true,
		},
		{
			name:  "pop3 accepts",
			proto: StartTLSPOP3,
			server: func(t *testing.T, conn net.Conn) {
				r := bufio.NewReader(conn)
				io.WriteString(conn, "+OK POP3 ready\r\n")
				if cmd := readLine(t, r); cmd != "STLS" {
					t.Errorf("the client sent %q, want STLS", cmd)
					return
				}
				io.WriteString(conn, "+OK Begin TLS\r\n")
			},
		},
		{
			name:  "pop3 refuses",
			proto: StartTLSPOP3,
			server: func(t *testing.T, conn net.Conn) {
				r := bufio.NewReader(conn)
				io.WriteString(conn, "+OK POP3 ready\r\n")
				readLine(t, r)
				io.WriteString(conn, "-ERR STLS not supported\r\n")
			},
			wantErr: true,
		},
		{
			name:  "ldap accepts",
			proto: StartTLSLDAP,
			server: func(t *testing.T, conn net.Conn) {
				request := make([]byte, len(ldapStartTLSRequest))
				if _, err := io.ReadFull(conn, request); err != nil {
					t.Errorf("the server could not read the request: %v", err)
					return
				}
				if string(request) != string(ldapStartTLSRequest) {
					t.Errorf("unexpected StartTLS request: % x", request)
					return
				}
				// ExtendedResponse with resultCode success (0).
				conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
			},
		},
		{
			name:  "ldap refuses with a resultCode",
			proto: StartTLSLDAP,
			server: func(t *testing.T, conn net.Conn) {
				io.ReadFull(conn, make([]byte, len(ldapStartTLSRequest)))
				// resultCode 53 (unwillingToPerform), what a server without a
				// certificate configured answers.
				conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x35, 0x04, 0x00, 0x04, 0x00})
			},
			wantErr: true,
		},
		{
			name:  "postgres accepts",
			proto: StartTLSPostgres,
			server: func(t *testing.T, conn net.Conn) {
				request := make([]byte, len(pgSSLRequest))
				if _, err := io.ReadFull(conn, request); err != nil {
					t.Errorf("the server could not read the request: %v", err)
					return
				}
				if string(request) != string(pgSSLRequest) {
					t.Errorf("unexpected SSLRequest: % x", request)
					return
				}
				conn.Write([]byte{'S'})
			},
		},
		{
			name:  "postgres with ssl off",
			proto: StartTLSPostgres,
			server: func(t *testing.T, conn net.Conn) {
				io.ReadFull(conn, make([]byte, len(pgSSLRequest)))
				conn.Write([]byte{'N'})
			},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, server := net.Pipe()
			deadline := time.Now().Add(5 * time.Second)
			client.SetDeadline(deadline)
			server.SetDeadline(deadline)

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				c.server(t, server)
			}()

			err := startTLS(client, c.proto)
			client.Close()
			<-done

			if c.wantErr && err == nil {
				t.Fatalf("startTLS(%s) should have failed", c.proto)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("startTLS(%s) returned an unexpected error: %v", c.proto, err)
			}
			if !c.wantErr {
				return
			}
			// A refusal is permanent: retrying replays the same conversation.
			if class := classify(err); class.kind != KindProtocol || class.retryable {
				t.Errorf("classify(%v) = %+v, want a non-retryable protocol error", err, class)
			}
		})
	}
}

// TestCheckOverSTARTTLS drives the whole path against a listener that speaks
// SMTP and only then presents a certificate: dial, negotiation, handshake, and
// the diagnostic reconnection that also has to negotiate again.
func TestCheckOverSTARTTLS(t *testing.T) {
	cert, key := selfSigned(t, "smtp.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(conn)
				io.WriteString(conn, "220 smtp.test ESMTP\r\n")
				if _, err := r.ReadString('\n'); err != nil { // EHLO
					return
				}
				io.WriteString(conn, "250-smtp.test\r\n250 STARTTLS\r\n")
				if _, err := r.ReadString('\n'); err != nil { // STARTTLS
					return
				}
				io.WriteString(conn, "220 ready\r\n")
				tlsConn := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
				})
				tlsConn.Handshake()
			}()
		}
	}()

	_, port, _ := net.SplitHostPort(listener.Addr().String())
	target, err := ParseTarget("smtp://smtp.test:" + port)
	if err != nil {
		t.Fatalf("could not parse the target: %v", err)
	}
	// The listener is on 127.0.0.1 and the certificate is for smtp.test; the
	// name is what the SNI and the verification use, so point the host at the
	// loopback while keeping the port.
	target.Host = "127.0.0.1"

	res := CheckTarget(context.Background(), target, testOptions(time.Now()))

	// Self-signed, so verification fails — but the metadata must still arrive,
	// which is only possible if the negotiation worked on both connections.
	if res.Status != StatusInvalid {
		t.Fatalf("status = %q (%s), want %q", res.Status, res.Error, StatusInvalid)
	}
	if res.Subject != "smtp.test" {
		t.Errorf("subject = %q, want %q", res.Subject, "smtp.test")
	}
	if !res.MetadataInsecure {
		t.Error("metadata_insecure should be set: the data came from the diagnostic pass")
	}
	if res.StartTLS != StartTLSSMTP {
		t.Errorf("starttls = %q, want %q", res.StartTLS, StartTLSSMTP)
	}
}

// TestStartTLSFromTarget pins the notation down: the scheme is an instruction,
// the port is a hint, and "tls://" overrules the hint.
func TestStartTLSFromTarget(t *testing.T) {
	cases := []struct {
		input string
		port  int
		proto StartTLS
	}{
		{"example.com", 443, StartTLSNone},
		{"https://example.com", 443, StartTLSNone},
		{"mail.example.com:465", 465, StartTLSNone},
		{"smtps://mail.example.com", 465, StartTLSNone},
		{"mail.example.com:993", 993, StartTLSNone},
		{"mail.example.com:587", 587, StartTLSSMTP},
		{"mail.example.com:25", 25, StartTLSSMTP},
		{"smtp://mail.example.com", 587, StartTLSSMTP},
		{"smtp://mail.example.com:2525", 2525, StartTLSSMTP},
		{"mail.example.com:143", 143, StartTLSIMAP},
		{"imap://mail.example.com", 143, StartTLSIMAP},
		{"mail.example.com:110", 110, StartTLSPOP3},
		{"ldap.example.com:389", 389, StartTLSLDAP},
		{"ldap://ldap.example.com", 389, StartTLSLDAP},
		{"ldaps://ldap.example.com", 636, StartTLSNone},
		{"db.example.com:5432", 5432, StartTLSPostgres},
		{"postgres://db.example.com", 5432, StartTLSPostgres},
		{"postgresql://db.example.com", 5432, StartTLSPostgres},
		// The escape hatch: a service wrapped in implicit TLS on a port the
		// inference would have claimed.
		{"tls://mail.example.com:587", 587, StartTLSNone},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			target, err := ParseTarget(c.input)
			if err != nil {
				t.Fatalf("ParseTarget(%q) failed: %v", c.input, err)
			}
			if target.Port != c.port || target.StartTLS != c.proto {
				t.Errorf("ParseTarget(%q) = port %d / starttls %q, want port %d / starttls %q",
					c.input, target.Port, target.StartTLS, c.port, c.proto)
			}
		})
	}
}

// TestParseTargetListKeepsNegotiationApart guards the de-duplication: the same
// host and port asked two different questions are two entries.
func TestParseTargetListKeepsNegotiationApart(t *testing.T) {
	targets, err := ParseTargetList(strings.NewReader("smtp://mail.example.com:587\ntls://mail.example.com:587\nmail.example.com:587\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets (%v), want 2 — the third line repeats the first", len(targets), targets)
	}
	if targets[0].StartTLS != StartTLSSMTP || targets[1].StartTLS != StartTLSNone {
		t.Errorf("negotiations = %q/%q, want %q/%q",
			targets[0].StartTLS, targets[1].StartTLS, StartTLSSMTP, StartTLSNone)
	}
}

// selfSigned builds a certificate that is its own issuer, which is what the
// chain code has to recognize as a root and what a test server needs to serve.
func selfSigned(t *testing.T, name string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: name},
		Issuer:                pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{name},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not re-read the certificate: %v", err)
	}
	return cert, key
}
