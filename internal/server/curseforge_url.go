package server

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var curseForgeModpackSlugPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func normalizeCurseForgeModpackURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid CurseForge URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("CurseForge URL must use HTTP or HTTPS")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("CurseForge URL must not contain credentials")
	}
	if !strings.EqualFold(parsed.Host, "curseforge.com") && !strings.EqualFold(parsed.Host, "www.curseforge.com") {
		return "", fmt.Errorf("URL must use the curseforge.com host")
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) != 3 && len(segments) != 5 {
		return "", fmt.Errorf("URL must identify a Minecraft modpack or modpack file")
	}
	if segments[0] != "minecraft" || segments[1] != "modpacks" || !curseForgeModpackSlugPattern.MatchString(segments[2]) {
		return "", fmt.Errorf("URL must identify a Minecraft modpack")
	}
	if len(segments) == 5 && (segments[3] != "files" || !isDecimalString(segments[4])) {
		return "", fmt.Errorf("URL must identify a CurseForge modpack file")
	}

	return "https://www.curseforge.com/" + strings.Join(segments, "/"), nil
}

func isDecimalString(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
