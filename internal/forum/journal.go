package forum

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LogEntry is one decision in the moderator's journal (Documents/blasthack-moderation-log.txt).
type LogEntry struct {
	ContentType string
	ContentID   int
	Action      string
	Applied     bool
	Moderator   string
	Title       string
	Author      string
	AuthorURL   string
	Forum       string
	URL         string
	Date        string
	Attachments []string
	Reason      string
	Notify      bool
	Note        string
}

var actionNames = map[string]string{
	"approve": "ОДОБРЕНО", "reject": "ОТКЛОНЕНО", "delete": "УДАЛЕНО", "spam_clean": "ОЧИСТКА СПАМА",
	"edit": "ОТРЕДАКТИРОВАНО", "move": "ПЕРЕНЕСЕНО",
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (e LogEntry) format(stamp string) string {
	action := actionNames[e.Action]
	if action == "" {
		action = e.Action
	}
	state := "применено"
	if !e.Applied {
		state = "НЕ ПРИМЕНЕНО (осталось в очереди)"
	}
	author := orDash(e.Author)
	if e.AuthorURL != "" {
		author += " (" + e.AuthorURL + ")"
	}
	notify := "нет"
	if e.Notify {
		notify = "да"
	}
	lines := []string{
		fmt.Sprintf("=== %s | %s | %s %d | %s", stamp, action, e.ContentType, e.ContentID, state),
		"Модератор: " + orDash(e.Moderator),
		"Название:  " + orDash(e.Title),
		"Автор:     " + author,
		"Раздел:    " + orDash(e.Forum),
		"Ссылка:    " + orDash(e.URL),
		"Создано:   " + orDash(e.Date),
	}
	if len(e.Attachments) > 0 {
		lines = append(lines, "Файлы:     "+strings.Join(e.Attachments, "; "))
	}
	if e.Reason != "" {
		lines = append(lines, "Причина (видит автор): "+e.Reason)
	}
	lines = append(lines, "Уведомление автору: "+notify)
	if e.Note != "" {
		lines = append(lines, "Заметка модератора: "+e.Note)
	}
	return strings.Join(lines, "\n")
}

// writeLog appends entries to the journal. A new file starts with a UTF-8 BOM so that Notepad on
// older Windows shows Cyrillic correctly.
func (c *Client) writeLog(entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	stamp := time.Now().Format("2006-01-02 15:04:05 -0700")
	var blocks []string
	for _, e := range entries {
		blocks = append(blocks, e.format(stamp))
	}
	if err := os.MkdirAll(filepath.Dir(c.cfg.LogPath), 0o755); err != nil {
		return err
	}
	_, statErr := os.Stat(c.cfg.LogPath)
	f, err := os.OpenFile(c.cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	text := strings.Join(blocks, "\n\n") + "\n\n"
	if os.IsNotExist(statErr) {
		text = "\uFEFF" + text
	}
	_, err = f.WriteString(text)
	return err
}

func defaultLogPath() string {
	return filepath.Join(documentsDir(), "blasthack-moderation-log.txt")
}
