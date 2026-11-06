package email

import (
	"context"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"yourapp/internal/config"
	"yourapp/internal/i18n"
)

func TestSendDeliversSMTPMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			result <- "accept failed"
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		protocol := textproto.NewConn(connection)
		_ = protocol.PrintfLine("220 localhost ESMTP")
		message := ""
		for {
			line, err := protocol.ReadLine()
			if err != nil {
				result <- "read failed"
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
				_ = protocol.PrintfLine("250 OK")
			case line == "DATA":
				_ = protocol.PrintfLine("354 Send message")
				raw, err := io.ReadAll(protocol.DotReader())
				if err != nil {
					result <- "data failed"
					return
				}
				message = string(raw)
				_ = protocol.PrintfLine("250 Queued")
			case line == "QUIT":
				_ = protocol.PrintfLine("221 Bye")
				result <- message
				return
			default:
				result <- "unexpected SMTP command"
				return
			}
		}
	}()
	host, rawPort, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	sender := NewSender(config.EmailConfig{Host: host, Port: port, From: "test@example.com"})
	content := i18n.NotificationEmail("de", "server_down", "Challenges-1", "Hetzner-HEL-1", "Fri, 06 Nov 2026 18:42:33 UTC", "https://example.com/notifications")
	subject := "Vestri Benachrichtigung: St\u00f6rung"
	if err := sender.Send(context.Background(), "recipient@example.com", subject, content.Text, content.HTML); err != nil {
		t.Fatal(err)
	}
	message := <-result
	parsed, err := mail.ReadMessage(strings.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	decodedSubject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil || decodedSubject != subject {
		t.Fatalf("subject did not survive SMTP transport: %q, %v", decodedSubject, err)
	}
	if parsed.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatal("missing safe transfer encoding")
	}
	encodedBody, err := io.ReadAll(parsed.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(encodedBody), "\r\n", "\n"), "\n") {
		if len(line) > 76 {
			t.Fatalf("encoded body line exceeds MIME limit: %d", len(line))
		}
	}
	decodedBody, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(string(encodedBody))))
	if err != nil {
		t.Fatal(err)
	}
	actualHTML := strings.ReplaceAll(string(decodedBody), "\r\n", "\n")
	expectedHTML := strings.ReplaceAll(content.HTML, "\r\n", "\n")
	if actualHTML != expectedHTML && actualHTML != expectedHTML+"\n" {
		t.Fatal("notification HTML was changed during SMTP transport")
	}
	nodeCell := `<td style="padding:8px 10px;width:120px;color:#4e5d86;border-bottom:1px solid #d8e2fb;">Node</td>`
	if !strings.Contains(string(decodedBody), nodeCell) {
		t.Fatal("Node divider CSS was corrupted during transport")
	}
}

func TestSendHonorsContextForStalledSMTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(io.Discard, connection)
	}()
	host, rawPort, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	sender := NewSender(config.EmailConfig{Host: host, Port: port, From: "test@example.com"})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := sender.Send(ctx, "recipient@example.com", "test", "message", ""); err == nil {
		t.Fatal("expected canceled SMTP send")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("SMTP send ignored context timeout")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP connection remained open")
	}
}
