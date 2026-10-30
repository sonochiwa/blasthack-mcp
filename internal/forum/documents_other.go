//go:build !windows

package forum

import (
	"os"
	"path/filepath"
)

func documentsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Documents")
}
