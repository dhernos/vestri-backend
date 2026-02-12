package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const encryptedNodeAPIKeyPrefix = "enc:v1:"

var errNodeAPIKeyCipherMissing = errors.New("node api key encryption key is not configured")

type nodeAPIKeyCipher struct {
	key []byte
}

func newNodeAPIKeyCipher(raw string) (*nodeAPIKeyCipher, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	key, err := parseNodeAPIKeyCipherKey(trimmed)
	if err != nil {
		return nil, err
	}
	return &nodeAPIKeyCipher{key: key}, nil
}

func parseNodeAPIKeyCipherKey(raw string) ([]byte, error) {
	if len(raw) == 64 {
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("NODE_API_KEY_ENCRYPTION_KEY must be 32-byte raw, 64-char hex, or base64")
}

func (c *nodeAPIKeyCipher) Encrypt(value string) (string, error) {
	if c == nil {
		return "", errNodeAPIKeyCipherMissing
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(value), nil)
	payload := append(nonce, ciphertext...)
	return encryptedNodeAPIKeyPrefix + base64.RawStdEncoding.EncodeToString(payload), nil
}

func (c *nodeAPIKeyCipher) Decrypt(value string) (plaintext string, encrypted bool, err error) {
	if !strings.HasPrefix(value, encryptedNodeAPIKeyPrefix) {
		return value, false, nil
	}
	if c == nil {
		return "", true, errNodeAPIKeyCipherMissing
	}

	raw := strings.TrimPrefix(value, encryptedNodeAPIKeyPrefix)
	payload, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return "", true, err
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", true, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", true, err
	}
	if len(payload) < gcm.NonceSize() {
		return "", true, errors.New("invalid encrypted API key payload")
	}

	nonce := payload[:gcm.NonceSize()]
	ciphertext := payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", true, err
	}
	return string(plain), true, nil
}
