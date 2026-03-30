package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRotatingFileWriterTruncatesOnStartup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "server.log")
	if err := os.WriteFile(logPath, []byte("old log entry\n"), 0o644); err != nil {
		t.Fatalf("seed log file: %v", err)
	}

	writer, err := NewRotatingFileWriter(logPath, 1024, 1)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	t.Cleanup(func() {
		_ = writer.Close()
	})

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if len(content) != 0 {
		t.Fatalf("expected log file to be empty after startup, got %q", string(content))
	}
}

func TestRotatingFileWriterStillRotatesAfterStartupTruncate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "server.log")
	writer, err := NewRotatingFileWriter(logPath, 10, 1)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}
	t.Cleanup(func() {
		_ = writer.Close()
	})

	first := []byte("12345678")
	second := []byte("abcdefgh")
	if _, err := writer.Write(first); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	if _, err := writer.Write(second); err != nil {
		t.Fatalf("write second chunk: %v", err)
	}

	active, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read active log: %v", err)
	}
	if string(active) != string(second) {
		t.Fatalf("expected active log %q, got %q", string(second), string(active))
	}

	backup, err := os.ReadFile(logPath + ".1")
	if err != nil {
		t.Fatalf("read backup log: %v", err)
	}
	if string(backup) != string(first) {
		t.Fatalf("expected backup log %q, got %q", string(first), string(backup))
	}
}
