package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashString returns a hex-encoded SHA-256 hash for token/code storage.
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
