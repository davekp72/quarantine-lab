package vbox

import (
	"regexp"
	"strings"
)

var (
	rePasswordEq     = regexp.MustCompile(`(?i)(--password=)("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|\S+)`)
	rePasswordSp     = regexp.MustCompile(`(?i)(--password)(\s+)("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|\S+)`)
	rePasswordFileEq = regexp.MustCompile(`(?i)(--passwordfile=)(\S+)`)
	rePasswordFileSp = regexp.MustCompile(`(?i)(--passwordfile)(\s+)(\S+)`)
	// Gateway historically embedded: printf '%s\n' 'secret' | sudo -S
	rePrintfSudo = regexp.MustCompile(`printf '%s\\n' (?:'(?:[^']|'')*'|"(?:\\.|[^"])*")(\s*\|\s*sudo)`)
	reBearer     = regexp.MustCompile(`(?i)(Bearer\s+)\S+`)
	reTokenKV    = regexp.MustCompile(`(?i)((?:agent[_-]?token|api[_-]?token|access[_-]?token|token)[=:\s]+)\S+`)
)

// RedactSecrets removes credentials from command lines and error text before logging.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	out := s
	out = rePasswordEq.ReplaceAllString(out, `${1}***`)
	out = rePasswordSp.ReplaceAllString(out, `${1}${2}***`)
	out = rePasswordFileEq.ReplaceAllString(out, `${1}***`)
	out = rePasswordFileSp.ReplaceAllString(out, `${1}${2}***`)
	out = rePrintfSudo.ReplaceAllString(out, `printf '%s\n' '***'$1`)
	out = reBearer.ReplaceAllString(out, `${1}***`)
	out = reTokenKV.ReplaceAllString(out, `${1}***`)
	return out
}

// FormatArgs joins VBoxManage args with secrets redacted for logs/errors.
func FormatArgs(args []string) string {
	return RedactSecrets(strings.Join(args, " "))
}
