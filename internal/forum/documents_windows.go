package forum

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// documentsDir follows a Documents folder moved to another drive or into OneDrive.
func documentsDir() string {
	if dir, err := windows.KnownFolderPath(windows.FOLDERID_Documents, 0); err == nil && dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Documents")
}
