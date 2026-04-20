package main

import (
	"regexp"
	"strings"
)

// maskedDisplay is the placeholder the /admin/config form uses in place of
// a stored secret. The POST handler treats an incoming maskedDisplay value
// in a known-secret field as "user didn't touch it" and merges the old
// value back in from disk.
const maskedDisplay = "••••••••"

var secretKeyRe = regexp.MustCompile(`(?i)pass|passwd|password|token|secret|nsec|privkey|apikey|api_key|watcher_key`)

// isSecretKey reports whether a UserConfig action-config key names a secret
// the UI should render as bullets rather than plaintext. bot_nsec is a
// legacy leftover but still matches via the regex anyway; the explicit
// match keeps behavior stable if the regex is ever changed.
func isSecretKey(key string) bool {
	if strings.EqualFold(key, "bot_nsec") {
		return true
	}
	return secretKeyRe.MatchString(key)
}
