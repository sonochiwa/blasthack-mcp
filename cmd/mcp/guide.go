package main

import (
	_ "embed"
	"log"
	"os"
	"strings"
)

// builtinGuide is how the assistant reviews the queue. It is sent as the server instructions, served
// by the moderation_guide tool and the review_queue prompt, so clients that ignore server
// instructions still get it.
//
//go:embed guide.md
var builtinGuide string

// loadGuide returns the file named by BLASTHACK_GUIDE when it is set and readable, so the
// instructions can be changed without rebuilding; otherwise the built-in guide.
func loadGuide() string {
	path := strings.TrimSpace(os.Getenv("BLASTHACK_GUIDE"))
	if path == "" {
		return builtinGuide
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) == "" {
		log.Printf("BLASTHACK_GUIDE %q is not usable (%v); using the built-in guide", path, err)
		return builtinGuide
	}
	return strings.TrimPrefix(string(data), "\uFEFF")
}
