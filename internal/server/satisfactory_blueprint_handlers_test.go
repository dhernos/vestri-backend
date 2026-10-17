package server

import (
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