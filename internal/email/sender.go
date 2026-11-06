package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
	"time"

	"yourapp/internal/config"
)

type Sender struct {
	cfg config.EmailConfig
}

func NewSender(cfg config.EmailConfig) *Sender {
	return &Sender{cfg: cfg}
}

func (s *Sender) Send(ctx context.Context, to, subject, text, html string) error {
	if !s.cfg.Enabled() {
		return fmt.Errorf("email is not configured")
	}

	body := html
	contentType := "text/html"
	if strings.TrimSpace(body) == "" {
		body = text
		contentType = "text/plain"
	}

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", s.cfg.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: %s; charset=\"UTF-8\"\r\n", contentType))
	msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	encoder := quotedprintable.NewWriter(&msg)
	if _, err := encoder.Write([]byte(body)); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if s.cfg.Secure {
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if !s.cfg.Secure {
		if available, _ := client.Extension("STARTTLS"); available {
			if err := client.StartTLS(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return err
			}
		}
	}
	if s.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(s.cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(msg.String())); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
