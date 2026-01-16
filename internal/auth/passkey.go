package auth

import (
	"bytes"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type PasskeyCredential struct {
	ID              string
	UserID          string
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	Transports      []string
	AAGUID          []byte
	SignCount       uint32
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Label           *string
}

// WebAuthnUser wraps a user and its credentials to satisfy the webauthn.User interface.
type WebAuthnUser struct {
	User         *User
	Credentials  []webauthn.Credential
	DisplayLabel string
}

func NewWebAuthnUser(user *User, creds []webauthn.Credential) *WebAuthnUser {
	name := user.Email
	if user.Name != nil && strings.TrimSpace(*user.Name) != "" {
		name = *user.Name
	}
	return &WebAuthnUser{
		User:         user,
		Credentials:  creds,
		DisplayLabel: name,
	}
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	id, err := uuid.Parse(u.User.ID)
	if err != nil {
		// fall back to raw bytes of string if parse fails
		return []byte(u.User.ID)
	}
	var buf [16]byte
	copy(buf[:], id[:])
	return buf[:]
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.Email
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.DisplayLabel != "" {
		return u.DisplayLabel
	}
	return u.User.Email
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	if u.User.Image != nil {
		return *u.User.Image
	}
	return ""
}

func (p PasskeyCredential) ToWebAuthnCredential() webauthn.Credential {
	return webauthn.Credential{
		ID:              p.CredentialID,
		PublicKey:       p.PublicKey,
		AttestationType: p.AttestationType,
		Transport:       transportsToProtocol(p.Transports),
		Authenticator: webauthn.Authenticator{
			AAGUID:    p.AAGUID,
			SignCount: p.SignCount,
		},
	}
}

func transportsToProtocol(values []string) []protocol.AuthenticatorTransport {
	out := make([]protocol.AuthenticatorTransport, 0, len(values))
	for _, v := range values {
		val := strings.TrimSpace(v)
		if val == "" {
			continue
		}
		out = append(out, protocol.AuthenticatorTransport(val))
	}
	return out
}

func ProtocolTransportsToStrings(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

func IsCredentialIDMatch(a, b []byte) bool {
	return bytes.Equal(a, b)
}
