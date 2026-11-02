package email

import (
	"context"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"yourapp/internal/config"
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
	if err := sender.Send(context.Background(), "recipient@example.com", "Vestri notification", "message", "<p>Notification</p>"); err != nil {
		t.Fatal(err)
	}
	message := <-result
	if !strings.Contains(message, "Subject: Vestri notification") || !strings.Contains(message, "<p>Notification</p>") {
		t.Fatalf("unexpected delivered message: %s", message)
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
