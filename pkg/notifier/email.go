package notifier

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/dbaio/sslscout/pkg/config"
)

// SMTPTimeout caps the whole conversation with the SMTP server.
const SMTPTimeout = 30 * time.Second

// BuildMessage assembles a complete RFC 5322 message. The old version sent only
// a raw "To:" and "Subject:" — without From/Date/MIME the server rejects the
// mail or it lands in spam, and a subject with accents and emoji arrived
// mangled.
func BuildMessage(cfg config.SMTP, subject, body string, now time.Time) []byte {
	var b strings.Builder

	b.WriteString("From: " + cfg.From + "\r\n")
	b.WriteString("To: " + strings.Join(cfg.To, ", ") + "\r\n")
	b.WriteString("Date: " + now.Format(time.RFC1123Z) + "\r\n")
	// RFC 2047: the subject carries emoji (and accents in some languages), so
	// it has to go out encoded.
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Message-ID: " + messageID(cfg.From, now) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("X-Mailer: SSLScout\r\n")
	b.WriteString("\r\n")

	// quoted-printable keeps the text readable and survives 7-bit servers.
	var qp strings.Builder
	w := quotedprintable.NewWriter(&qp)
	_, _ = w.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	_ = w.Close()
	b.WriteString(qp.String())
	if !strings.HasSuffix(qp.String(), "\r\n") {
		b.WriteString("\r\n")
	}

	return []byte(b.String())
}

func messageID(from string, now time.Time) string {
	domain := "sslscout.local"
	if i := strings.LastIndex(from, "@"); i >= 0 && i+1 < len(from) {
		domain = strings.Trim(from[i+1:], "<> ")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		// Without entropy the timestamp still gives a reasonably unique ID.
		return fmt.Sprintf("<%d.sslscout@%s>", now.UnixNano(), domain)
	}
	return fmt.Sprintf("<%d.%s.sslscout@%s>", now.Unix(), hex.EncodeToString(random[:]), domain)
}

// sendEmail delivers the message speaking SMTP by hand, because smtp.SendMail
// covers neither implicit TLS (port 465) nor the unauthenticated case.
func sendEmail(cfg config.SMTP, subject, body string) error {
	msg := BuildMessage(cfg, subject, body, time.Now())
	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	conn, err := dialSMTP(cfg, address)
	if err != nil {
		return err
	}
	// A single deadline for the whole session avoids hanging on a mute server.
	if err := conn.SetDeadline(time.Now().Add(SMTPTimeout)); err != nil {
		conn.Close()
		return fmt.Errorf("could not set the connection deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("could not start the SMTP session: %w", err)
	}
	defer client.Close()

	if cfg.TLS == config.TLSStartTLS || cfg.TLS == "" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("the server %s does not offer STARTTLS (use tls: \"none\" or \"implicit\")", cfg.Host)
		}
		if err := client.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
	}

	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("sender %q refused: %w", cfg.From, err)
	}
	for _, to := range cfg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("recipient %q refused: %w", to, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("could not start the message body: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		w.Close()
		return fmt.Errorf("could not write the message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("the server refused the message: %w", err)
	}
	return client.Quit()
}

func dialSMTP(cfg config.SMTP, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: SMTPTimeout}

	if cfg.TLS == config.TLSImplicit {
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName: cfg.Host,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return nil, fmt.Errorf("could not connect to %s over implicit TLS: %w", address, err)
		}
		return conn, nil
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("could not connect to %s: %w", address, err)
	}
	return conn, nil
}
