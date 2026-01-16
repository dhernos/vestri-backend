package i18n

import (
	"net/http"
	"strings"
)

const DefaultLocale = "en"

var supportedLocales = map[string]struct{}{
	"en": {},
	"de": {},
}

func LocaleFromRequest(r *http.Request) string {
	if r == nil {
		return DefaultLocale
	}
	return NormalizeLocale(r.Header.Get("Accept-Language"))
}

func NormalizeLocale(header string) string {
	if strings.TrimSpace(header) == "" {
		return DefaultLocale
	}

	parts := strings.Split(header, ",")
	for _, part := range parts {
		lang := strings.TrimSpace(part)
		if lang == "" {
			continue
		}
		if idx := strings.Index(lang, ";"); idx >= 0 {
			lang = lang[:idx]
		}
		lang = strings.ToLower(strings.TrimSpace(lang))
		if lang == "" {
			continue
		}
		if idx := strings.Index(lang, "-"); idx >= 0 {
			lang = lang[:idx]
		}
		if _, ok := supportedLocales[lang]; ok {
			return lang
		}
	}

	return DefaultLocale
}
