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

func TestResolveGameServerLogPath(t *testing.T) {
	locations := []gameServerTemplateLogLocation{
		{Directory: "data/logs", Patterns: []string{"*.log", "*.log.gz"}},
		{Directory: "data", Patterns: []string{"factorio-current.log", "factorio-previous.log"}},
	}
	tests := []struct {
		path string
		want string
	}{
		{path: "data/logs/latest.log", want: "data/logs/latest.log"},
		{path: "data/logs/2026-11-02-1.log.gz", want: "data/logs/2026-11-02-1.log.gz"},
		{path: "data/factorio-current.log", want: "data/factorio-current.log"},
		{path: "data/logs/../factorio-previous.log", want: "data/factorio-previous.log"},
		{path: "data/logs/latest.gz"},
		{path: "data/server.properties"},
		{path: "data/other.log"},
		{path: "data/logs/archive/latest.log"},
		{path: "../data/logs/latest.log"},
		{path: `data\logs\latest.log`},
		{path: ""},
	}
	for _, test := range tests {
		got, ok := resolveGameServerLogPath(locations, test.path)
		if ok != (test.want != "") || got != test.want {
			t.Errorf("resolveGameServerLogPath(%q) = %q, %v; want %q", test.path, got, ok, test.want)
		}
	}
}

func TestGameServerTemplatesDefineLogLocations(t *testing.T) {
	for id, want := range map[string]string{
		vanillaTemplateID:    "data/logs",
		curseForgeTemplateID: "data/logs",
		"factorio":           "data",
	} {
		tpl, err := gameServerTemplateByID(id)
		if err != nil || tpl == nil {
			t.Fatalf("template %s: %v", id, err)
		}
		if len(tpl.LogLocations) == 0 || tpl.LogLocations[0].Directory != want {
			t.Errorf("template %s log locations = %#v, want directory %s", id, tpl.LogLocations, want)
		}
	}
}

func TestIsCompressedServerLogPath(t *testing.T) {
	if !isCompressedServerLogPath(defaultGameServerLogLocations, "server", "server/data/logs/latest.log.gz") {
		t.Fatal("expected compressed log under data/logs to be readable")
	}
	for _, filePath := range []string{
		"server/data/plugins/latest.log.gz",
		"server/data/logs/archive/latest.log.gz",
		"server/data/logs/latest.gz",
		"other/data/logs/latest.log.gz",
	} {
		if isCompressedServerLogPath(defaultGameServerLogLocations, "server", filePath) {
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