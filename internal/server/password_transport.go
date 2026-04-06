package server

import (
	"errors"
	"strings"
)

const (
	clientPasswordFormatSHA256V1 = "client-sha256-v1"
	clientPasswordHashPrefix     = "v1$sha256$"
	clientPasswordHashHexLength  = 64
)

func normalizeTransportPassword(password, format string) (string, bool, error) {
	trimmedFormat := strings.TrimSpace(format)
	if password == "" {
		return "", false, errors.New("password is required")
	}
	if trimmedFormat == "" {
		return password, false, nil
	}

	switch trimmedFormat {
	case clientPasswordFormatSHA256V1:
		if !strings.HasPrefix(password, clientPasswordHashPrefix) {
			return "", true, errors.New("invalid password hash format")
		}
		hexPart := password[len(clientPasswordHashPrefix):]
		if len(hexPart) != clientPasswordHashHexLength {
			return "", true, errors.New("invalid password hash format")
		}
		for _, r := range hexPart {
			switch {
			case r >= '0' && r <= '9':
			case r >= 'a' && r <= 'f':
			case r >= 'A' && r <= 'F':
			default:
				return "", true, errors.New("invalid password hash format")
			}
		}
		// Bcrypt rejects inputs >72 bytes; use only the canonical SHA-256 hex payload.
		return strings.ToLower(hexPart), true, nil
	default:
		return "", false, errors.New("unsupported password format")
	}
}

func validatePasswordForStorage(password, format string) (string, error) {
	normalized, isClientHashed, err := normalizeTransportPassword(password, format)
	if err != nil {
		return "", err
	}
	if !isClientHashed {
		if err := validatePassword(normalized); err != nil {
			return "", err
		}
	}
	return normalized, nil
}
