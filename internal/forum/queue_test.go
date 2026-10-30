package forum

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func fixtureClient(t *testing.T) *Client {
	t.Helper()
	page, err := os.ReadFile("testdata/queue.html")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected %s %s: tests must not send forms", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, MaxPostChars: 6000, LogPath: t.TempDir() + "/log.txt"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestQueueList(t *testing.T) {
	out, err := fixtureClient(t).QueueList(context.Background(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	items := out["items"].([]M)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	post, user := items[0], items[1]
	if post["content_type"] != "post" || post["content_id"] != 901 || post["author"] != "newbie" {
		t.Errorf("post item = %v", post)
	}
	if !strings.Contains(post["text"].(string), "```lua\nprint(\"hi\")\n```") {
		t.Errorf("code block lost: %q", post["text"])
	}
	if a := post["actions"].(M); a["approve"] != "Одобрить" || a["delete"] != "Удалить" {
		t.Errorf("actions = %v", a)
	}
	if user["title"] != "spammer" || !strings.Contains(user["text"].(string), "IP: 1.2.3.4") ||
		strings.Contains(user["text"].(string), "Отклонить") {
		t.Errorf("user item = %v", user)
	}
}

func TestQueueProcessDryRun(t *testing.T) {
	c := fixtureClient(t)
	no := false
	out, err := c.QueueProcess(context.Background(), []Decision{
		{ContentType: "post", ContentID: 901, Action: "delete", Reason: "спам"},
		{ContentType: "user", ContentID: 8, Action: "approve"},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range out["form"].([][2]string) {
		got[p[0]] = p[1]
	}
	want := map[string]string{"queue[post][901]": "delete", "reason[post][901]": "спам", "notify[post][901]": "1",
		"queue[user][8]": "approve"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("form[%s] = %q, want %q (form %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected fields: %v", got)
	}

	out, err = c.QueueProcess(context.Background(), []Decision{
		{ContentType: "post", ContentID: 901, Action: "delete", Reason: "x", Notify: &no}}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range out["form"].([][2]string) {
		if p[0] == "notify[post][901]" {
			t.Error("notify sent although notify=false")
		}
	}
}

func TestQueueProcessRefusals(t *testing.T) {
	c := fixtureClient(t)
	cases := map[string]Decision{
		"not available":    {ContentType: "user", ContentID: 8, Action: "spam_clean"},
		"not in the queue": {ContentType: "thread", ContentID: 1, Action: "approve"},
		"at most 100":      {ContentType: "post", ContentID: 901, Action: "delete", Reason: strings.Repeat("я", 101)},
	}
	for want, d := range cases {
		if _, err := c.QueueProcess(context.Background(), []Decision{d}, true); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: err = %v, want %q", d, err, want)
		}
	}
}

func TestReadOnlyRefusesWrites(t *testing.T) {
	c := fixtureClient(t)
	c.cfg.ReadOnly = true
	if _, err := c.QueueProcess(context.Background(), []Decision{{ContentType: "user", ContentID: 8, Action: "approve"}}, false); err == nil {
		t.Error("read-only mode must refuse a real send")
	}
}

func TestJournalEntry(t *testing.T) {
	e := LogEntry{ContentType: "thread", ContentID: 5, Action: "reject", Applied: false, Moderator: "mod",
		Title: "T", Author: "a", AuthorURL: "https://x/members/1/", Reason: "r", Notify: true, Note: "n"}
	text := e.format("2026-10-31 00:00:00 +0600")
	for _, want := range []string{"| ОТКЛОНЕНО | thread 5 | НЕ ПРИМЕНЕНО", "Автор:     a (https://x/members/1/)",
		"Причина (видит автор): r", "Уведомление автору: да", "Заметка модератора: n"} {
		if !strings.Contains(text, want) {
			t.Errorf("journal entry lacks %q:\n%s", want, text)
		}
	}
}
