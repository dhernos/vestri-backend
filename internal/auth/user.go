package auth

import "time"

type User struct {
	ID                   string
	Name                 *string
	Email                string
	EmailVerified        *time.Time
	PasswordHash         *string
	Image                *string
	Theme                string
	TwoFactorSecret      *string
	TwoFactorEnabled     bool
	TwoFactorMethod      *string
	TwoFactorEmailCode   *string
	TwoFactorCodeExpires *time.Time
	PasswordResetToken   *string
	PasswordResetExpires *time.Time
	Role                 string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type VerificationToken struct {
	ID      string
	Token   string
	Expires time.Time
	UserID  string
}
