package server

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestIsGameServerLogFileName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "latest.log", want: true},
		{name: "2026-11-02-1.log.gz", want: true},
		{name: "latest.gz"},
		{name: "../latest.log.gz"},
		{name: `..\latest.log.gz`},
		{name: "folder/latest.log"},
		{name: ".."},
	}
	for _, test := range tests {
		if got := isGameServerLogFileName(test.name); got != test.want {
			t.Errorf("isGameServerLogFileName(%q) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestIsCompressedServerLogPath(t *testing.T) {
	if !isCompressedServerLogPath("server", "server/data/logs/latest.log.gz") {
		t.Fatal("expected compressed log under data/logs to be readable")
	}
	for _, filePath := range []string{
		"server/data/plugins/latest.log.gz",
		"server/data/logs/archive/latest.log.gz",
		"server/data/logs/latest.gz",
	} {
		if isCompressedServerLogPath("server", filePath) {
			t.Errorf("unexpected compressed log path acceptance: %q", filePath)
		}
	}
}

func TestDecompressServerLog(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("first line\nsecond line\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := decompressServerLog(compressed.Bytes())
	if err != nil {
		t.Fatalf("decompressServerLog() error = %v", err)
	}
	if string(got) != "first line\nsecond line\n" {
		t.Fatalf("decompressed content = %q", got)
	}
	if _, err := decompressServerLog([]byte("not gzip")); err == nil {
		t.Fatal("invalid gzip data was accepted")
	}
}

func TestDecompressServerLogEnforcesExpandedSizeLimit(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(strings.Repeat("x", int(maxDecompressedServerLogBytes+1)))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decompressServerLog(compressed.Bytes()); err != errServerLogTooLarge {
		t.Fatalf("decompressServerLog() error = %v, want %v", err, errServerLogTooLarge)
	}
}