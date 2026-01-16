package i18n

import (
	"strconv"
	"strings"
)

type EmailContent struct {
	Subject string
	Text    string
	HTML    string
}

type emailStrings struct {
	VerificationSubject string
	VerificationText    string
	VerificationHTML    string

	PasswordResetSubject string
	PasswordResetText    string
	PasswordResetHTML    string

	OAuthNoticeSubject string
	OAuthNoticeText    string
	OAuthNoticeHTML    string

	TwoFactorSubject string
	TwoFactorText    string
	TwoFactorHTML    string

	SignInSubject string
	SignInText    string
	SignInHTML    string

	UnknownLocation string
	UnknownDevice   string
}

var emailTranslations = map[string]emailStrings{
	"en": {
		VerificationSubject: "Verify your email",
		VerificationText:    "Your verification code is {code}. It is valid for {minutes} minutes.",
		VerificationHTML: "<p>Verify your email</p>" +
			"<p>Use the code below to verify your email address.</p>" +
			"<p><strong>{code}</strong></p>" +
			"<p>The code expires in {minutes} minutes.</p>" +
			"<p>If you did not request this, you can ignore this email.</p>",

		PasswordResetSubject: "Reset your password",
		PasswordResetText:    "Reset your password: {link}\nThe link expires in {hours} hour(s).\nIf you did not request this, ignore this email.",
		PasswordResetHTML: "<p>Password reset</p>" +
			"<p>Click the button to reset your password.</p>" +
			"<p><a href=\"{link}\">Reset password</a></p>" +
			"<p>The link expires in {hours} hour(s).</p>" +
			"<p>If you did not request this, ignore this email.</p>",

		OAuthNoticeSubject: "Account uses external sign-in",
		OAuthNoticeText:    "This account uses an external sign-in method. Please sign in using that method to access your account.",
		OAuthNoticeHTML: "<p>This account uses an external sign-in method.</p>" +
			"<p>Please sign in using that method to access your account.</p>",

		TwoFactorSubject: "Your 2FA code",
		TwoFactorText:    "Your 2FA code is {code} (valid for {minutes} minutes).",
		TwoFactorHTML:    "<p>Your 2FA code is <strong>{code}</strong> (valid for {minutes} minutes).</p>",

		SignInSubject: "New sign-in to your account",
		SignInText: "Hi {email},\n\nA new sign-in occurred on {time}.\n\n" +
			"IP: {ip}\nLocation: {location}\nDevice: {device}\n\n" +
			"If this wasn't you, please reset your password and revoke other sessions.",
		SignInHTML: "<p>Hi {email},</p>" +
			"<p>A new sign-in occurred on <strong>{time}</strong>.</p>" +
			"<ul><li><strong>IP:</strong> {ip}</li>" +
			"<li><strong>Location:</strong> {location}</li>" +
			"<li><strong>Device:</strong> {device}</li></ul>" +
			"<p>If this wasn't you, please reset your password and revoke other sessions.</p>",

		UnknownLocation: "Unknown location",
		UnknownDevice:   "Unknown device",
	},
	"de": {
		VerificationSubject: "E-Mail verifizieren",
		VerificationText:    "Ihr Verifizierungscode ist {code}. Er ist {minutes} Minuten g\u00fcltig.",
		VerificationHTML: "<p>E-Mail verifizieren</p>" +
			"<p>Verwenden Sie den untenstehenden Code, um Ihre E-Mail zu verifizieren.</p>" +
			"<p><strong>{code}</strong></p>" +
			"<p>Der Code ist in {minutes} Minuten abgelaufen.</p>" +
			"<p>Wenn Sie dies nicht angefordert haben, k\u00f6nnen Sie diese E-Mail ignorieren.</p>",

		PasswordResetSubject: "Passwort zur\u00fccksetzen",
		PasswordResetText:    "Setzen Sie Ihr Passwort zur\u00fcck: {link}\nDer Link ist {hours} Stunde(n) g\u00fcltig.\nWenn Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail.",
		PasswordResetHTML: "<p>Passwort zur\u00fccksetzen</p>" +
			"<p>Klicken Sie auf den Button, um Ihr Passwort zur\u00fcckzusetzen.</p>" +
			"<p><a href=\"{link}\">Passwort zur\u00fccksetzen</a></p>" +
			"<p>Der Link ist {hours} Stunde(n) g\u00fcltig.</p>" +
			"<p>Wenn Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail.</p>",

		OAuthNoticeSubject: "Konto nutzt externe Anmeldung",
		OAuthNoticeText:    "Dieses Konto verwendet eine externe Anmeldemethode. Bitte melden Sie sich mit dieser Methode an, um auf Ihr Konto zuzugreifen.",
		OAuthNoticeHTML: "<p>Dieses Konto verwendet eine externe Anmeldemethode.</p>" +
			"<p>Bitte melden Sie sich mit dieser Methode an, um auf Ihr Konto zuzugreifen.</p>",

		TwoFactorSubject: "Ihr 2FA-Code",
		TwoFactorText:    "Ihr 2FA-Code ist {code} (g\u00fcltig f\u00fcr {minutes} Minuten).",
		TwoFactorHTML:    "<p>Ihr 2FA-Code ist <strong>{code}</strong> (g\u00fcltig f\u00fcr {minutes} Minuten).</p>",

		SignInSubject: "Neue Anmeldung in Ihrem Konto",
		SignInText: "Hallo {email},\n\nEine neue Anmeldung erfolgte am {time}.\n\n" +
			"IP: {ip}\nOrt: {location}\nGer\u00e4t: {device}\n\n" +
			"Wenn Sie das nicht waren, setzen Sie bitte Ihr Passwort zur\u00fcck und beenden Sie andere Sitzungen.",
		SignInHTML: "<p>Hallo {email},</p>" +
			"<p>Eine neue Anmeldung erfolgte am <strong>{time}</strong>.</p>" +
			"<ul><li><strong>IP:</strong> {ip}</li>" +
			"<li><strong>Ort:</strong> {location}</li>" +
			"<li><strong>Ger\u00e4t:</strong> {device}</li></ul>" +
			"<p>Wenn Sie das nicht waren, setzen Sie bitte Ihr Passwort zur\u00fcck und beenden Sie andere Sitzungen.</p>",

		UnknownLocation: "Unbekannter Ort",
		UnknownDevice:   "Unbekanntes Ger\u00e4t",
	},
}

func emailStringsForLocale(locale string) emailStrings {
	key := NormalizeLocale(locale)
	if val, ok := emailTranslations[key]; ok {
		return val
	}
	return emailTranslations[DefaultLocale]
}

func renderTemplate(tmpl string, values map[string]string) string {
	if tmpl == "" || len(values) == 0 {
		return tmpl
	}

	replacements := make([]string, 0, len(values)*2)
	for key, value := range values {
		replacements = append(replacements, "{"+key+"}", value)
	}
	return strings.NewReplacer(replacements...).Replace(tmpl)
}

func VerificationEmail(locale, code string, minutes int) EmailContent {
	templates := emailStringsForLocale(locale)
	values := map[string]string{
		"code":    code,
		"minutes": strconv.Itoa(minutes),
	}
	return EmailContent{
		Subject: templates.VerificationSubject,
		Text:    renderTemplate(templates.VerificationText, values),
		HTML:    renderTemplate(templates.VerificationHTML, values),
	}
}

func PasswordResetEmail(locale, link string, hours int) EmailContent {
	templates := emailStringsForLocale(locale)
	values := map[string]string{
		"link":  link,
		"hours": strconv.Itoa(hours),
	}
	return EmailContent{
		Subject: templates.PasswordResetSubject,
		Text:    renderTemplate(templates.PasswordResetText, values),
		HTML:    renderTemplate(templates.PasswordResetHTML, values),
	}
}

func OAuthNoticeEmail(locale string) EmailContent {
	templates := emailStringsForLocale(locale)
	return EmailContent{
		Subject: templates.OAuthNoticeSubject,
		Text:    templates.OAuthNoticeText,
		HTML:    templates.OAuthNoticeHTML,
	}
}

func TwoFactorEmail(locale, code string, minutes int) EmailContent {
	templates := emailStringsForLocale(locale)
	values := map[string]string{
		"code":    code,
		"minutes": strconv.Itoa(minutes),
	}
	return EmailContent{
		Subject: templates.TwoFactorSubject,
		Text:    renderTemplate(templates.TwoFactorText, values),
		HTML:    renderTemplate(templates.TwoFactorHTML, values),
	}
}

func SignInAlertEmail(locale, email, loginTime, ip, location, device string) EmailContent {
	templates := emailStringsForLocale(locale)
	if strings.TrimSpace(location) == "" {
		location = templates.UnknownLocation
	}
	if strings.TrimSpace(device) == "" {
		device = templates.UnknownDevice
	}
	values := map[string]string{
		"email":    email,
		"time":     loginTime,
		"ip":       ip,
		"location": location,
		"device":   device,
	}
	return EmailContent{
		Subject: templates.SignInSubject,
		Text:    renderTemplate(templates.SignInText, values),
		HTML:    renderTemplate(templates.SignInHTML, values),
	}
}
