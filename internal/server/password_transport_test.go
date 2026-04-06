package server

import "testing"

func TestNormalizeTransportPasswordClientSHA256V1(t *testing.T) {
	input := "v1$sha256$080A6D9358D1D0D3C26E1F54D4D34BF58CF89BF6D4BD4587F822D6B28C2E92D8"

	normalized, clientHashed, err := normalizeTransportPassword(input, "client-sha256-v1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !clientHashed {
		t.Fatalf("expected clientHashed=true")
	}
	if normalized != "080a6d9358d1d0d3c26e1f54d4d34bf58cf89bf6d4bd4587f822d6b28c2e92d8" {
		t.Fatalf("unexpected normalized value: %q", normalized)
	}
}

func TestNormalizeTransportPasswordClientSHA256V1InvalidFormat(t *testing.T) {
	_, _, err := normalizeTransportPassword("v1$sha256$xyz", "client-sha256-v1")
	if err == nil {
		t.Fatalf("expected error for invalid client hash")
	}
}

func TestValidatePasswordForStorageKeepsLegacyRules(t *testing.T) {
	_, err := validatePasswordForStorage("short", "")
	if err == nil {
		t.Fatalf("expected validation error for weak plaintext password")
	}
}
