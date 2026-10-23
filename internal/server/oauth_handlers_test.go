package server

import "testing"

func TestSanitizeReturnToRejectsBackslashAndControls(t *testing.T) {
	for _, value := range []string{
		`/\evil.example`,
		"/safe\r\nLocation: https://evil.example",
	} {
		if got := sanitizeReturnTo(value); got != "/" {
			t.Errorf("sanitizeReturnTo(%q) = %q, want /", value, got)
		}
	}

	if got := sanitizeReturnTo("/en/dashboard?tab=servers"); got != "/en/dashboard?tab=servers" {
		t.Errorf("sanitizeReturnTo preserved path = %q", got)
	}
}

func TestSelectVerifiedGitHubEmailRequiresPrimaryVerifiedAddress(t *testing.T) {
	emails := []gitHubEmail{
		{Email: "unverified@example.test", Primary: false, Verified: false},
		{Email: "verified-secondary@example.test", Primary: false, Verified: true},
		{Email: "primary-unverified@example.test", Primary: true, Verified: false},
	}
	if got := selectVerifiedGitHubEmail(emails); got != "" {
		t.Errorf("selectVerifiedGitHubEmail without verified primary = %q, want empty", got)
	}

	emails = append(emails, gitHubEmail{
		Email:    "PRIMARY@example.test",
		Primary:  true,
		Verified: true,
	})
	if got := selectVerifiedGitHubEmail(emails); got != "primary@example.test" {
		t.Errorf("selectVerifiedGitHubEmail = %q, want primary@example.test", got)
	}
}

func TestOAuthStateMatchesInitiatingBrowserState(t *testing.T) {
	if !oauthStateMatches("expected", "expected") {
		t.Fatal("matching state cookie should be accepted")
	}
	for _, pair := range [][2]string{
		{"", "expected"},
		{"expected", ""},
		{"other", "expected"},
	} {
		if oauthStateMatches(pair[0], pair[1]) {
			t.Errorf("oauthStateMatches(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}

func TestCanonicalizeEmail(t *testing.T) {
	if got := canonicalizeEmail("  Person@Example.Test "); got != "person@example.test" {
		t.Errorf("canonicalizeEmail() = %q, want person@example.test", got)
	}
}
