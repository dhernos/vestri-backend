package server

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestIsAllowedSatisfactoryBlueprintURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "blueprint library", url: "https://satisfactoryblueprints.com/blueprint/06e29a92-aef9-4af6-9f24-333a694686e1", want: true},
		{name: "calculator page", url: "https://satisfactory-calculator.com/en/blueprints", want: true},
		{name: "verified calculator file host", url: "https://static.satisfactory-calculator.com/data/blueprintsData/a.sbp", want: true},
		{name: "untrusted suffix domain", url: "https://satisfactory-calculator.com.attacker.example/file", want: false},
		{name: "non-https", url: "http://satisfactoryblueprints.com/blueprint/example", want: false},
		{name: "custom port", url: "https://satisfactoryblueprints.com:8443/blueprint/example", want: false},
		{name: "userinfo", url: "https://attacker@example.com/blueprint/example", want: false},
		{name: "unapproved host", url: "https://example.com/file.sbp", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := url.Parse(test.url)
			if err != nil {
				t.Fatalf("url.Parse() error = %v", err)
			}
			if got := isAllowedSatisfactoryBlueprintURL(parsed); got != test.want {
				t.Fatalf("isAllowedSatisfactoryBlueprintURL() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSatisfactoryBlueprintDownloadForPageDirectURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantURL      string
		wantFilename string
		wantErr      bool
	}{
		{
			name:         "satisfactory blueprints detail",
			input:        "https://satisfactoryblueprints.com/blueprint/06e29a92-aef9-4af6-9f24-333a694686e1",
			wantURL:      "https://satisfactoryblueprints.com/blueprint/download/06e29a92-aef9-4af6-9f24-333a694686e1",
			wantFilename: "blueprint-06e29a92-aef9-4af6-9f24-333a694686e1.sbp",
		},
		{
			name:         "satisfactory blueprints direct file",
			input:        "https://satisfactoryblueprints.com/blueprint/download/06e29a92-aef9-4af6-9f24-333a694686e1",
			wantURL:      "https://satisfactoryblueprints.com/blueprint/download/06e29a92-aef9-4af6-9f24-333a694686e1",
			wantFilename: "blueprint-06e29a92-aef9-4af6-9f24-333a694686e1.sbp",
		},
		{
			name:         "satisfactory blueprint config file",
			input:        "https://satisfactoryblueprints.com/blueprint/config/06e29a92-aef9-4af6-9f24-333a694686e1",
			wantURL:      "https://satisfactoryblueprints.com/blueprint/config/06e29a92-aef9-4af6-9f24-333a694686e1",
			wantFilename: "blueprint-06e29a92-aef9-4af6-9f24-333a694686e1.sbpcfg",
		},
		{
			name:         "calculator direct file",
			input:        "https://satisfactory-calculator.com/en/blueprints/index/download/id/12911/name/blueprint",
			wantURL:      "https://satisfactory-calculator.com/en/blueprints/index/download/id/12911/name/blueprint",
			wantFilename: "blueprint-12911.sbp",
		},
		{
			name:         "calculator direct config file",
			input:        "https://satisfactory-calculator.com/en/blueprints/index/download-cfg/id/12911/name/blueprint",
			wantURL:      "https://satisfactory-calculator.com/en/blueprints/index/download-cfg/id/12911/name/blueprint",
			wantFilename: "blueprint-12911.sbpcfg",
		},
		{
			name:         "calculator CDN direct file",
			input:        "https://static.satisfactory-calculator.com/data/blueprintsData/0/a/test.sbp?version=1",
			wantURL:      "https://static.satisfactory-calculator.com/data/blueprintsData/0/a/test.sbp?version=1",
			wantFilename: "test.sbp",
		},
		{
			name:    "homepage is not a blueprint file",
			input:   "https://satisfactoryblueprints.com/",
			wantErr: true,
		},
		{
			name:    "unapproved host",
			input:   "https://attacker.example/blueprint/download/06e29a92-aef9-4af6-9f24-333a694686e1",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			gotURL, gotFilename, err := satisfactoryBlueprintDownloadForPage(context.Background(), test.input, newSatisfactoryBlueprintHTTPClient())
			if test.wantErr {
				if err == nil {
					t.Fatal("expected URL validation error")
				}
				return
			}
			if err != nil {
				t.Fatalf("satisfactoryBlueprintDownloadForPage() error = %v", err)
			}
			if gotURL.String() != test.wantURL {
				t.Errorf("download URL = %q, want %q", gotURL.String(), test.wantURL)
			}
			if gotFilename != test.wantFilename {
				t.Errorf("filename = %q, want %q", gotFilename, test.wantFilename)
			}
		})
	}
}

func TestSatisfactoryBlueprintFilenamePrefersResponseTitle(t *testing.T) {
	t.Parallel()

	got := satisfactoryBlueprintFilename(`attachment; filename="Hovering Train Node.sbp"`, "blueprint-06e29a92.sbp")
	if got != "Hovering Train Node.sbp" {
		t.Fatalf("filename = %q, want source title", got)
	}
	got = satisfactoryBlueprintFilename(`attachment; filename="not-a-blueprint.html"`, "blueprint-12911.sbp")
	if got != "blueprint-12911.sbp" {
		t.Fatalf("invalid response filename = %q, want fallback", got)
	}
}

func TestSatisfactoryBlueprintFilenameUsesRedirectHeader(t *testing.T) {
	t.Parallel()

	redirect := &http.Response{Header: http.Header{"Content-Disposition": {`attachment; filename="Smelter Manifold.sbp"`}}}
	final := &http.Response{
		Header:  make(http.Header),
		Request: &http.Request{Response: redirect},
	}
	got := satisfactoryBlueprintResponseFilename(final, "blueprint-12911.sbp")
	if got != "Smelter Manifold.sbp" {
		t.Fatalf("filename = %q, want redirect response title", got)
	}
}

func TestSatisfactoryServerNameFromSettings(t *testing.T) {
	t.Parallel()

	got := satisfactoryServerNameFromSettings("[/Script/FactoryGame.FGServerSettings]\nServerName=FICSIT Central\n")
	if got != "FICSIT Central" {
		t.Fatalf("configured server name = %q", got)
	}
	if !safeSatisfactoryDirectoryName(got) || safeSatisfactoryDirectoryName("../escape") {
		t.Fatal("server-name path validation failed")
	}
}

func TestSatisfactorySessionSaveExists(t *testing.T) {
	t.Parallel()

	if satisfactorySessionSaveExists([]satisfactoryWorkerEntry{
		{Name: "new session", Type: "dir"},
		{Name: "readme.txt", Type: "file"},
	}) {
		t.Fatal("session should not be ready without a save file")
	}
	if !satisfactorySessionSaveExists([]satisfactoryWorkerEntry{
		{Name: "factory_autosave_0.sav", Type: "file"},
	}) {
		t.Fatal("session should be ready when a save file exists")
	}
}

func TestSafeSatisfactoryBlueprintName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{name: "Factory.sbp", want: true},
		{name: "Factory.SBPCFG", want: true},
		{name: "../outside.sbp", want: false},
		{name: "folder\\outside.sbp", want: false},
		{name: "server.jar", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, got := safeSatisfactoryBlueprintName(test.name)
			if got != test.want {
				t.Fatalf("safeSatisfactoryBlueprintName() valid = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSatisfactoryBlueprintLibraryPathIsNodeScoped(t *testing.T) {
	t.Parallel()

	first := satisfactoryBlueprintLibraryPath("node-1")
	second := satisfactoryBlueprintLibraryPath("node-2")
	if first != "satisfactory-blueprints/node-1" {
		t.Fatalf("first node library path = %q", first)
	}
	if second != "satisfactory-blueprints/node-2" || first == second {
		t.Fatalf("node libraries are not isolated: first=%q second=%q", first, second)
	}
}