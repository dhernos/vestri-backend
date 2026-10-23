package server

import "strings"

func canonicalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
