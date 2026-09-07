package checker

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// StartTLS names the plaintext protocol spoken before the TLS upgrade. The
// empty value means implicit TLS: the handshake owns the connection from the
// first byte, which is what happens on 443, 465, 636, 993 and 995.
//
// This is the difference between "the certificate is on port 443" and "the
// certificate is on port 587, but only after the server agrees to show it".
// A submission port, an LDAP directory or a PostgreSQL instance answers a
// direct TLS handshake with garbage or with silence, so a checker that only
// knows how to dial TLS reports a protocol error on services that are
// perfectly healthy.
type StartTLS string

// Supported negotiations. There is no "auto": guessing the protocol from the
// banner would mean reading it, and half of these speak first only after we do.
const (
	StartTLSNone     StartTLS = ""
	StartTLSSMTP     StartTLS = "smtp"
	StartTLSIMAP     StartTLS = "imap"
	StartTLSPOP3     StartTLS = "pop3"
	StartTLSLDAP     StartTLS = "ldap"
	StartTLSPostgres StartTLS = "postgres"
)

// startTLSMaxRead caps the plaintext phase. A server that answers a greeting
// with an endless stream is either broken or hostile, and either way it must
// not be able to grow our memory before the handshake even starts.
const startTLSMaxRead = 64 << 10

// startTLSError marks a refusal at the protocol level — the server spoke, and
// what it said was "no". It is kept apart from an I/O failure on purpose: a
// timeout during the dialogue is still a timeout, and classify() should read it
// as one.
type startTLSError struct {
	proto StartTLS
	stage string
	err   error
}

func (e *startTLSError) Error() string {
	return fmt.Sprintf("%s STARTTLS (%s): %v", e.proto, e.stage, e.err)
}

func (e *startTLSError) Unwrap() error { return e.err }

func refused(proto StartTLS, stage string, format string, a ...any) error {
	return &startTLSError{proto: proto, stage: stage, err: fmt.Errorf(format, a...)}
}

// startTLS runs the plaintext dialogue that turns conn into a TLS connection.
// It returns once the server has agreed and the next byte we owe it is the
// ClientHello.
func startTLS(conn net.Conn, proto StartTLS) error {
	switch proto {
	case StartTLSSMTP:
		return startTLSSMTP(conn)
	case StartTLSIMAP:
		return startTLSIMAP(conn)
	case StartTLSPOP3:
		return startTLSPOP3(conn)
	case StartTLSLDAP:
		return startTLSLDAP(conn)
	case StartTLSPostgres:
		return startTLSPostgres(conn)
	default:
		return refused(proto, "setup", "unsupported STARTTLS protocol %q", string(proto))
	}
}

// --- Line-oriented protocols (SMTP, IMAP, POP3) ---

// textConn is the line reader for the three text protocols.
//
// The reader is buffered while the TLS handshake later reads the raw conn, and
// that is safe here for a reason worth stating: every one of these servers goes
// quiet the moment it accepts the upgrade — it is waiting for our ClientHello.
// Anything it sent early would be a protocol violation, and RFC 3207 is
// explicit that such data must be discarded rather than acted on.
type textConn struct {
	r    *bufio.Reader
	conn net.Conn
}

func newTextConn(conn net.Conn) *textConn {
	return &textConn{r: bufio.NewReader(io.LimitReader(conn, startTLSMaxRead)), conn: conn}
}

func (t *textConn) readLine() (string, error) {
	line, err := t.r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line == "" {
			return "", io.ErrUnexpectedEOF
		}
		if !errors.Is(err, io.EOF) {
			return "", err
		}
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (t *textConn) writeLine(s string) error {
	_, err := t.conn.Write([]byte(s + "\r\n"))
	return err
}

// smtpReply reads one reply, joining the continuation lines ("250-" before the
// final "250 ").
func (t *textConn) smtpReply() (int, string, error) {
	var text strings.Builder
	for {
		line, err := t.readLine()
		if err != nil {
			return 0, "", err
		}
		if text.Len() > 0 {
			text.WriteByte(' ')
		}
		text.WriteString(line)

		if len(line) >= 4 && line[3] == '-' {
			continue // continuation, the reply is not over
		}
		if len(line) < 3 {
			return 0, text.String(), refused(StartTLSSMTP, "reply", "malformed reply %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, text.String(), refused(StartTLSSMTP, "reply", "malformed reply %q", line)
		}
		return code, text.String(), nil
	}
}

func startTLSSMTP(conn net.Conn) error {
	t := newTextConn(conn)

	code, text, err := t.smtpReply()
	if err != nil {
		return err
	}
	if code != 220 {
		return refused(StartTLSSMTP, "greeting", "the server answered %q", text)
	}

	// EHLO and not HELO: RFC 3207 only offers STARTTLS to the extended dialect,
	// so a server that rejects EHLO has nothing to upgrade anyway.
	if err := t.writeLine("EHLO sslscout"); err != nil {
		return err
	}
	if code, text, err = t.smtpReply(); err != nil {
		return err
	} else if code != 250 {
		return refused(StartTLSSMTP, "EHLO", "the server answered %q", text)
	}

	if err := t.writeLine("STARTTLS"); err != nil {
		return err
	}
	if code, text, err = t.smtpReply(); err != nil {
		return err
	} else if code != 220 {
		return refused(StartTLSSMTP, "STARTTLS", "the server answered %q", text)
	}
	return nil
}

func startTLSIMAP(conn net.Conn) error {
	t := newTextConn(conn)

	line, err := t.readLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "* OK") {
		return refused(StartTLSIMAP, "greeting", "the server answered %q", line)
	}

	const tag = "a001"
	if err := t.writeLine(tag + " STARTTLS"); err != nil {
		return err
	}
	for {
		line, err := t.readLine()
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "* ") {
			continue // untagged status update, the tagged answer is still coming
		}
		if !strings.HasPrefix(line, tag+" OK") {
			return refused(StartTLSIMAP, "STARTTLS", "the server answered %q", line)
		}
		return nil
	}
}

func startTLSPOP3(conn net.Conn) error {
	t := newTextConn(conn)

	line, err := t.readLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "+OK") {
		return refused(StartTLSPOP3, "greeting", "the server answered %q", line)
	}

	if err := t.writeLine("STLS"); err != nil {
		return err
	}
	if line, err = t.readLine(); err != nil {
		return err
	} else if !strings.HasPrefix(line, "+OK") {
		return refused(StartTLSPOP3, "STLS", "the server answered %q", line)
	}
	return nil
}

// --- LDAP ---

// ldapStartTLSRequest is a complete LDAPv3 ExtendedRequest carrying the StartTLS
// OID 1.3.6.1.4.1.1466.20037 (RFC 4511 section 4.14). Nothing in it depends on
// the target, so it is a constant and this file carries no BER encoder:
//
//	30 1d          SEQUENCE, 29 bytes
//	   02 01 01    messageID INTEGER 1
//	   77 18       [APPLICATION 23] ExtendedRequest, 24 bytes
//	      80 16    [0] requestName, 22 bytes
//	         "1.3.6.1.4.1.1466.20037"
var ldapStartTLSRequest = []byte{
	0x30, 0x1d,
	0x02, 0x01, 0x01,
	0x77, 0x18,
	0x80, 0x16,
	'1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.',
	'1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
}

// readBERHeader reads one tag plus its definite length. Indefinite lengths are
// rejected: LDAP forbids them, and accepting one would mean reading until EOF.
// A malformed length comes back as a refusal rather than as a bare error, so it
// is classified as a protocol problem and never retried.
func readBERHeader(r *bufio.Reader) (tag byte, length int, err error) {
	tag, err = r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	first, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	if first < 0x80 {
		return tag, int(first), nil
	}

	n := int(first & 0x7f)
	if n == 0 || n > 4 {
		return 0, 0, refused(StartTLSLDAP, "response", "malformed BER length")
	}
	for i := 0; i < n; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		length = length<<8 | int(b)
	}
	if length < 0 || length > startTLSMaxRead {
		return 0, 0, refused(StartTLSLDAP, "response", "BER length out of range")
	}
	return tag, length, nil
}

func startTLSLDAP(conn net.Conn) error {
	if _, err := conn.Write(ldapStartTLSRequest); err != nil {
		return err
	}
	r := bufio.NewReader(io.LimitReader(conn, startTLSMaxRead))

	// LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp ExtendedResponse }
	tag, _, err := readBERHeader(r)
	if err != nil {
		return err
	}
	if tag != 0x30 {
		return refused(StartTLSLDAP, "response", "the answer is not an LDAPMessage")
	}

	tag, length, err := readBERHeader(r)
	if err != nil {
		return err
	}
	if tag != 0x02 {
		return refused(StartTLSLDAP, "response", "the answer carries no messageID")
	}
	if _, err := r.Discard(length); err != nil {
		return err
	}

	// ExtendedResponse ::= [APPLICATION 24] { resultCode ENUMERATED, ... }
	tag, _, err = readBERHeader(r)
	if err != nil {
		return err
	}
	if tag != 0x78 {
		return refused(StartTLSLDAP, "response", "the server did not answer the StartTLS request")
	}
	tag, length, err = readBERHeader(r)
	if err != nil {
		return err
	}
	if tag != 0x0a || length != 1 {
		return refused(StartTLSLDAP, "response", "the answer carries no resultCode")
	}
	code, err := r.ReadByte()
	if err != nil {
		return err
	}
	if code != 0 {
		return refused(StartTLSLDAP, "StartTLS", "the server refused with LDAP resultCode %d", code)
	}
	return nil
}

// --- PostgreSQL ---

// pgSSLRequest is the fixed SSLRequest packet: a four-byte length of 8 followed
// by the magic request code 80877103 (0x04d2162f). PostgreSQL answers it with a
// single byte, before any authentication — which is exactly what a certificate
// check wants, since it needs no credentials at all.
var pgSSLRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

func startTLSPostgres(conn net.Conn) error {
	if _, err := conn.Write(pgSSLRequest); err != nil {
		return err
	}
	var answer [1]byte
	if _, err := io.ReadFull(conn, answer[:]); err != nil {
		return err
	}
	switch answer[0] {
	case 'S':
		return nil
	case 'N':
		return refused(StartTLSPostgres, "SSLRequest", "the server has SSL disabled")
	case 'E':
		return refused(StartTLSPostgres, "SSLRequest", "the server rejected the request with an error")
	default:
		return refused(StartTLSPostgres, "SSLRequest", "unexpected answer %q", string(answer[0]))
	}
}
