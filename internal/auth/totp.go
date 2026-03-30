package auth

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/pquerna/otp/totp"
)

type TOTPVerifier interface {
	Verify(secret, code string) bool
	Generate(email string) (secret string, otpauthURL string, qrDataURL string, err error)
}

type TOTPService struct {
	Issuer string
}

func NewTOTPService(issuer string) *TOTPService {
	return &TOTPService{Issuer: issuer}
}

func (t *TOTPService) Verify(secret, code string) bool {
	return totp.Validate(code, secret)
}

func (t *TOTPService) Generate(email string) (string, string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.Issuer,
		AccountName: email,
	})
	if err != nil {
		return "", "", "", err
	}

	secret := key.Secret()
	otpauth := key.URL()

	img, err := key.Image(200, 200)
	if err != nil {
		return secret, otpauth, "", err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return secret, otpauth, "", err
	}
	qr := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	return secret, otpauth, qr, nil
}
