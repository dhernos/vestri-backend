package i18n

import (
	"html"
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

	NodeInviteSubject string
	NodeInviteText    string
	NodeInviteHTML    string

	UnknownLocation string
	UnknownDevice   string
}

var emailTranslations = map[string]emailStrings{
	"en": {
		VerificationSubject: "Verify your email",
		VerificationText:    "Your verification code is {code}. It is valid for {minutes} minutes.",
		VerificationHTML: "<p style=\"margin:0 0 12px;\">Use the code below to verify your email address.</p>" +
			"<div style=\"margin:0 0 12px;padding:12px 18px;border:1px solid #c7d7ff;border-radius:10px;background:#f5f8ff;display:inline-block;font-size:28px;letter-spacing:6px;font-weight:700;\">{code}</div>" +
			"<p style=\"margin:0 0 8px;\">The code expires in {minutes} minutes.</p>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">If you did not request this, you can ignore this email.</p>",

		PasswordResetSubject: "Reset your password",
		PasswordResetText:    "Reset your password: {link}\nThe link expires in {hours} hour(s).\nIf you did not request this, ignore this email.",
		PasswordResetHTML: "<p style=\"margin:0 0 12px;\">Click the button below to reset your password.</p>" +
			"<p style=\"margin:0 0 16px;\"><a href=\"{link}\" style=\"display:inline-block;background:#4f6cf6;color:#f9fbff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600;\">Reset password</a></p>" +
			"<p style=\"margin:0 0 8px;\">The link expires in {hours} hour(s).</p>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">If you did not request this, ignore this email.</p>",

		OAuthNoticeSubject: "Account uses external sign-in",
		OAuthNoticeText:    "This account uses an external sign-in method. Please sign in using that method to access your account.",
		OAuthNoticeHTML: "<p style=\"margin:0 0 10px;\">This account uses an external sign-in method.</p>" +
			"<p style=\"margin:0;\">Please sign in using that method to access your account.</p>",

		TwoFactorSubject: "Your 2FA code",
		TwoFactorText:    "Your 2FA code is {code} (valid for {minutes} minutes).",
		TwoFactorHTML: "<p style=\"margin:0 0 12px;\">Use this code to continue.</p>" +
			"<div style=\"margin:0 0 12px;padding:12px 18px;border:1px solid #c7d7ff;border-radius:10px;background:#f5f8ff;display:inline-block;font-size:28px;letter-spacing:6px;font-weight:700;\">{code}</div>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">Valid for {minutes} minutes.</p>",

		SignInSubject: "New sign-in to your account",
		SignInText: "Hi {email},\n\nA new sign-in occurred on {time}.\n\n" +
			"IP: {ip}\nLocation: {location}\nDevice: {device}\n\n" +
			"If this wasn't you, please reset your password and revoke other sessions.",
		SignInHTML: "<p style=\"margin:0 0 12px;\">Hi {email},</p>" +
			"<p style=\"margin:0 0 12px;\">A new sign-in occurred on <strong>{time}</strong>.</p>" +
			"<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%;border:1px solid #d8e2fb;border-radius:8px;margin:0 0 12px;\"><tr><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;width:120px;color:#4e5d86;\">IP</td><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;\">{ip}</td></tr><tr><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;width:120px;color:#4e5d86;\">Location</td><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;\">{location}</td></tr><tr><td style=\"padding:8px 10px;width:120px;color:#4e5d86;\">Device</td><td style=\"padding:8px 10px;\">{device}</td></tr></table>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">If this wasn't you, please reset your password and revoke other sessions.</p>",

		NodeInviteSubject: "You were invited to a node",
		NodeInviteText: "You were invited to node \"{node}\" by {inviter}.\n" +
			"Role: {permission}\n" +
			"Expires: {expires}\n\n" +
			"Open your nodes page to accept: {link}",
		NodeInviteHTML: "<p style=\"margin:0 0 12px;\">You were invited to node <strong>{node}</strong> by {inviter}.</p>" +
			"<p style=\"margin:0 0 4px;\"><strong>Role:</strong> {permission}</p>" +
			"<p style=\"margin:0 0 12px;\"><strong>Expires:</strong> {expires}</p>" +
			"<p style=\"margin:0;\"><a href=\"{link}\" style=\"display:inline-block;background:#4f6cf6;color:#f9fbff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600;\">Open nodes page to accept invite</a></p>",

		UnknownLocation: "Unknown location",
		UnknownDevice:   "Unknown device",
	},
	"de": {
		VerificationSubject: "E-Mail verifizieren",
		VerificationText:    "Ihr Verifizierungscode ist {code}. Er ist {minutes} Minuten g\u00fcltig.",
		VerificationHTML: "<p style=\"margin:0 0 12px;\">Verwenden Sie den untenstehenden Code, um Ihre E-Mail zu verifizieren.</p>" +
			"<div style=\"margin:0 0 12px;padding:12px 18px;border:1px solid #c7d7ff;border-radius:10px;background:#f5f8ff;display:inline-block;font-size:28px;letter-spacing:6px;font-weight:700;\">{code}</div>" +
			"<p style=\"margin:0 0 8px;\">Der Code ist in {minutes} Minuten abgelaufen.</p>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">Wenn Sie dies nicht angefordert haben, k\u00f6nnen Sie diese E-Mail ignorieren.</p>",

		PasswordResetSubject: "Passwort zur\u00fccksetzen",
		PasswordResetText:    "Setzen Sie Ihr Passwort zur\u00fcck: {link}\nDer Link ist {hours} Stunde(n) g\u00fcltig.\nWenn Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail.",
		PasswordResetHTML: "<p style=\"margin:0 0 12px;\">Klicken Sie auf den Button, um Ihr Passwort zur\u00fcckzusetzen.</p>" +
			"<p style=\"margin:0 0 16px;\"><a href=\"{link}\" style=\"display:inline-block;background:#4f6cf6;color:#f9fbff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600;\">Passwort zur\u00fccksetzen</a></p>" +
			"<p style=\"margin:0 0 8px;\">Der Link ist {hours} Stunde(n) g\u00fcltig.</p>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">Wenn Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail.</p>",

		OAuthNoticeSubject: "Konto nutzt externe Anmeldung",
		OAuthNoticeText:    "Dieses Konto verwendet eine externe Anmeldemethode. Bitte melden Sie sich mit dieser Methode an, um auf Ihr Konto zuzugreifen.",
		OAuthNoticeHTML: "<p style=\"margin:0 0 10px;\">Dieses Konto verwendet eine externe Anmeldemethode.</p>" +
			"<p style=\"margin:0;\">Bitte melden Sie sich mit dieser Methode an, um auf Ihr Konto zuzugreifen.</p>",

		TwoFactorSubject: "Ihr 2FA-Code",
		TwoFactorText:    "Ihr 2FA-Code ist {code} (g\u00fcltig f\u00fcr {minutes} Minuten).",
		TwoFactorHTML: "<p style=\"margin:0 0 12px;\">Verwenden Sie diesen Code, um fortzufahren.</p>" +
			"<div style=\"margin:0 0 12px;padding:12px 18px;border:1px solid #c7d7ff;border-radius:10px;background:#f5f8ff;display:inline-block;font-size:28px;letter-spacing:6px;font-weight:700;\">{code}</div>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">G\u00fcltig f\u00fcr {minutes} Minuten.</p>",

		SignInSubject: "Neue Anmeldung in Ihrem Konto",
		SignInText: "Hallo {email},\n\nEine neue Anmeldung erfolgte am {time}.\n\n" +
			"IP: {ip}\nOrt: {location}\nGer\u00e4t: {device}\n\n" +
			"Wenn Sie das nicht waren, setzen Sie bitte Ihr Passwort zur\u00fcck und beenden Sie andere Sitzungen.",
		SignInHTML: "<p style=\"margin:0 0 12px;\">Hallo {email},</p>" +
			"<p style=\"margin:0 0 12px;\">Eine neue Anmeldung erfolgte am <strong>{time}</strong>.</p>" +
			"<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%;border:1px solid #d8e2fb;border-radius:8px;margin:0 0 12px;\"><tr><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;width:120px;color:#4e5d86;\">IP</td><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;\">{ip}</td></tr><tr><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;width:120px;color:#4e5d86;\">Ort</td><td style=\"padding:8px 10px;border-bottom:1px solid #d8e2fb;\">{location}</td></tr><tr><td style=\"padding:8px 10px;width:120px;color:#4e5d86;\">Ger\u00e4t</td><td style=\"padding:8px 10px;\">{device}</td></tr></table>" +
			"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">Wenn Sie das nicht waren, setzen Sie bitte Ihr Passwort zur\u00fcck und beenden Sie andere Sitzungen.</p>",

		NodeInviteSubject: "Sie wurden zu einer Node eingeladen",
		NodeInviteText: "Sie wurden von {inviter} zur Node \"{node}\" eingeladen.\n" +
			"Rolle: {permission}\n" +
			"G\u00fcltig bis: {expires}\n\n" +
			"Zum Annehmen \u00f6ffnen: {link}",
		NodeInviteHTML: "<p style=\"margin:0 0 12px;\">Sie wurden von {inviter} zur Node <strong>{node}</strong> eingeladen.</p>" +
			"<p style=\"margin:0 0 4px;\"><strong>Rolle:</strong> {permission}</p>" +
			"<p style=\"margin:0 0 12px;\"><strong>G\u00fcltig bis:</strong> {expires}</p>" +
			"<p style=\"margin:0;\"><a href=\"{link}\" style=\"display:inline-block;background:#4f6cf6;color:#f9fbff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600;\">Nodes-Seite zum Annehmen \u00f6ffnen</a></p>",

		UnknownLocation: "Unbekannter Ort",
		UnknownDevice:   "Unbekanntes Ger\u00e4t",
	},
}

const emailBrandLogoURL = "https://raw.githubusercontent.com/dhernos/vestri/main/public/logos/vestri/vestri.png"

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

func renderTemplateHTML(tmpl string, values map[string]string) string {
	if tmpl == "" || len(values) == 0 {
		return tmpl
	}
	escaped := make(map[string]string, len(values))
	for key, value := range values {
		escaped[key] = html.EscapeString(value)
	}
	return renderTemplate(tmpl, escaped)
}

func wrapEmailHTML(locale, subject, bodyHTML string) string {
	subtitle, footer := emailLayoutCopy(locale)
	return "<!doctype html>" +
		"<html><body style=\"margin:0;padding:0;background:#eef3ff;\">" +
		"<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#eef3ff;padding:24px 0;\"><tr><td align=\"center\">" +
		"<table role=\"presentation\" width=\"560\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:560px;width:100%;background:#f9fbff;border:1px solid #d8e2fb;border-radius:14px;padding:28px;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#22315f;\">" +
		"<tr><td align=\"center\">" +
		"<div style=\"display:inline-flex;align-items:center;justify-content:center;width:56px;height:56px;border-radius:12px;border:1px solid #d8e2fb;background:#f9fbff;overflow:hidden;\">" +
		"<img src=\"" + emailBrandLogoURL + "\" alt=\"Vestri\" width=\"32\" height=\"32\" style=\"display:block;width:32px;height:32px;\"/>" +
		"</div>" +
		"<p style=\"margin:12px 0 6px;font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:#5f6f95;\">Vestri</p>" +
		"<h1 style=\"margin:0 0 6px;font-size:24px;line-height:1.2;\">" + html.EscapeString(subject) + "</h1>" +
		"<p style=\"margin:0 0 18px;font-size:14px;color:#4e5d86;\">" + html.EscapeString(subtitle) + "</p>" +
		"<div style=\"text-align:left;font-size:15px;line-height:1.6;color:#22315f;\">" + bodyHTML + "</div>" +
		"<hr style=\"border:none;border-top:1px solid #d8e2fb;margin:20px 0;\"/>" +
		"<p style=\"margin:0;font-size:12px;color:#5f6f95;\">" + html.EscapeString(footer) + "</p>" +
		"</td></tr></table>" +
		"</td></tr></table>" +
		"</body></html>"
}

func emailLayoutCopy(locale string) (subtitle, footer string) {
	switch NormalizeLocale(locale) {
	case "de":
		return "Sicherheitsbenachrichtigung von Vestri", "Diese E-Mail wurde automatisch von Vestri gesendet."
	default:
		return "Security notification from Vestri", "This email was generated automatically by Vestri."
	}
}

func VerificationEmail(locale, code string, minutes int) EmailContent {
	templates := emailStringsForLocale(locale)
	values := map[string]string{
		"code":    code,
		"minutes": strconv.Itoa(minutes),
	}
	htmlBody := renderTemplateHTML(templates.VerificationHTML, values)
	return EmailContent{
		Subject: templates.VerificationSubject,
		Text:    renderTemplate(templates.VerificationText, values),
		HTML:    wrapEmailHTML(locale, templates.VerificationSubject, htmlBody),
	}
}

func PasswordResetEmail(locale, link string, hours int) EmailContent {
	templates := emailStringsForLocale(locale)
	values := map[string]string{
		"link":  link,
		"hours": strconv.Itoa(hours),
	}
	htmlBody := renderTemplateHTML(templates.PasswordResetHTML, values)
	return EmailContent{
		Subject: templates.PasswordResetSubject,
		Text:    renderTemplate(templates.PasswordResetText, values),
		HTML:    wrapEmailHTML(locale, templates.PasswordResetSubject, htmlBody),
	}
}

func OAuthNoticeEmail(locale string) EmailContent {
	templates := emailStringsForLocale(locale)
	return EmailContent{
		Subject: templates.OAuthNoticeSubject,
		Text:    templates.OAuthNoticeText,
		HTML:    wrapEmailHTML(locale, templates.OAuthNoticeSubject, templates.OAuthNoticeHTML),
	}
}

func TwoFactorEmail(locale, code string, minutes int) EmailContent {
	templates := emailStringsForLocale(locale)
	values := map[string]string{
		"code":    code,
		"minutes": strconv.Itoa(minutes),
	}
	htmlBody := renderTemplateHTML(templates.TwoFactorHTML, values)
	return EmailContent{
		Subject: templates.TwoFactorSubject,
		Text:    renderTemplate(templates.TwoFactorText, values),
		HTML:    wrapEmailHTML(locale, templates.TwoFactorSubject, htmlBody),
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
	htmlBody := renderTemplateHTML(templates.SignInHTML, values)
	return EmailContent{
		Subject: templates.SignInSubject,
		Text:    renderTemplate(templates.SignInText, values),
		HTML:    wrapEmailHTML(locale, templates.SignInSubject, htmlBody),
	}
}

func NodeInviteEmail(locale, inviter, node, permission, expires, link string) EmailContent {
	templates := emailStringsForLocale(locale)
	values := map[string]string{
		"inviter":    inviter,
		"node":       node,
		"permission": permission,
		"expires":    expires,
		"link":       link,
	}
	htmlBody := renderTemplateHTML(templates.NodeInviteHTML, values)
	return EmailContent{
		Subject: templates.NodeInviteSubject,
		Text:    renderTemplate(templates.NodeInviteText, values),
		HTML:    wrapEmailHTML(locale, templates.NodeInviteSubject, htmlBody),
	}
}
