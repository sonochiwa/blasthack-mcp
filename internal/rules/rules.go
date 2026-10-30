// Package rules holds the summary of blast.hk rules used for moderation.
package rules

import (
	_ "embed"
	"strings"
)

//go:embed RULES.md
var text string

// Section returns the whole summary or one "## [name]" section of it.
func Section(name string) string {
	if name == "" || name == "all" {
		return text
	}
	for _, part := range strings.Split(text, "\n## ") {
		if strings.HasPrefix(part, "["+name+"]") {
			return "## " + part
		}
	}
	return text
}
