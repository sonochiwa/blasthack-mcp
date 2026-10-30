package forum

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PuerkitoBio/goquery"
)

var queueName = regexp.MustCompile(`^queue\[([^\]]+)\]\[(\d+)\]$`)

type queueKey struct {
	ContentType string
	ContentID   int
}

type queueItem struct {
	key queueKey
	// options keeps the site's order: "" (do nothing), approve, reject, ...
	options   [][2]string
	container *goquery.Selection
}

func (it *queueItem) hasOption(action string) bool {
	for _, o := range it.options {
		if o[0] == action {
			return true
		}
	}
	return false
}

func (it *queueItem) optionValues() []string {
	var out []string
	for _, o := range it.options {
		out = append(out, o[0])
	}
	return out
}

type queue struct {
	doc   *goquery.Document
	order []*queueItem
	byKey map[queueKey]*queueItem
}

func (c *Client) loadQueue(ctx context.Context) (*queue, error) {
	doc, _, err := c.get(ctx, "/approval-queue/", nil)
	if err != nil {
		return nil, err
	}
	q := &queue{doc: doc, byKey: map[queueKey]*queueItem{}}
	first := map[queueKey]*goquery.Selection{}
	doc.Find(`input[name^="queue["]`).Each(func(_ int, in *goquery.Selection) {
		m := queueName.FindStringSubmatch(in.AttrOr("name", ""))
		if m == nil {
			return
		}
		id, _ := strconv.Atoi(m[2])
		key := queueKey{m[1], id}
		it, ok := q.byKey[key]
		if !ok {
			it = &queueItem{key: key}
			q.byKey[key] = it
			q.order = append(q.order, it)
			first[key] = in
		}
		value := in.AttrOr("value", "")
		label := squash(in.Closest("label").Text())
		if label == "" {
			label = value
		}
		it.options = append(it.options, [2]string{value, label})
	})
	// Each item's container is the largest ancestor of its radio buttons that holds no other item.
	for key, it := range q.byKey {
		own := fmt.Sprintf("queue[%s][%d]", key.ContentType, key.ContentID)
		cur := first[key]
		for {
			parent := cur.Parent()
			if parent.Length() == 0 || goquery.NodeName(parent) == "form" {
				break
			}
			foreign := false
			parent.Find(`input[name^="queue["]`).EachWithBreak(func(_ int, in *goquery.Selection) bool {
				foreign = in.AttrOr("name", "") != own
				return !foreign
			})
			if foreign {
				break
			}
			cur = parent
		}
		it.container = cur
	}
	return q, nil
}

func (c *Client) describeItem(it *queueItem, full bool) M {
	box := it.container
	links := []M{}
	seen := map[string]bool{}
	box.Find("a[href]").Each(func(_ int, a *goquery.Selection) {
		href := a.AttrOr("href", "")
		// Skip the author's "currently viewing ..." activity line and avatar links.
		if a.Closest(".message-attribution, .message-userExtras, .message-avatar").Length() > 0 {
			return
		}
		text := squash(a.Text())
		if text == "" || seen[href] {
			return
		}
		for _, k := range []string{"/threads/", "/posts/", "/members/", "/forums/", "/resources/", "/profile-posts/"} {
			if strings.Contains(href, k) {
				seen[href] = true
				if len(links) < 10 {
					links = append(links, M{"text": text, "url": c.absolute(href)})
				}
				return
			}
		}
	})
	title := box.Find(".message-title, .contentRow-title, h3, h2, .block-header").First()
	if title.Length() == 0 {
		title = box.Find(`.messageNotice--moderated a[href*="/threads/"], .messageNotice--moderated a[href*="/posts/"]`).First()
	}
	authorSel := box.Find(".username, [data-author]").First()
	author := authorSel.AttrOr("data-author", "")
	if author == "" {
		author = strings.TrimSpace(authorSel.Text())
	}
	var text string
	if body := box.Find(".bbWrapper").First(); body.Length() > 0 {
		text = c.ToText(body)
	} else {
		// Non-message content (user registration etc.): the container text without the action row.
		clone := box.Clone()
		clone.Find(`input[name^="queue["]`).Each(func(_ int, in *goquery.Selection) {
			in.Closest(".formRow, .inputChoices, label").Remove()
		})
		text = lines(clone)
	}
	if !full {
		text = clip(text, 2500)
	}
	actions := M{}
	for _, o := range it.options {
		actions[o[0]] = o[1]
	}
	out := M{
		"content_type": it.key.ContentType,
		"content_id":   it.key.ContentID,
		"title":        squash(title.Text()),
		"author":       author,
		"date":         box.Find("time").First().AttrOr("datetime", ""),
		"links":        links,
		"text":         text,
		"actions":      actions,
	}
	if f := box.Find(`.messageNotice--moderated a[href*="/forums/"]`).First(); f.Length() > 0 {
		out["forum"] = squash(f.Text())
	}
	var extra []string
	box.Find("input[name], textarea[name], select[name]").Each(func(_ int, in *goquery.Selection) {
		name := in.AttrOr("name", "")
		if !queueName.MatchString(name) && name != "_xfToken" {
			extra = append(extra, name)
		}
	})
	if extra != nil {
		out["extra_fields"] = extra
	}
	return out
}

func (c *Client) QueueList(ctx context.Context, contentType string, full bool) (M, error) {
	q, err := c.loadQueue(ctx)
	if err != nil {
		return nil, err
	}
	if len(q.order) == 0 {
		out := M{"count": 0, "items": []M{}}
		if msg := pageError(q.doc); msg != "" {
			out["message"] = msg
		}
		return out, nil
	}
	items := []M{}
	for _, it := range q.order {
		if contentType == "" || it.key.ContentType == contentType {
			items = append(items, c.describeItem(it, full))
		}
	}
	return M{"count": len(items), "total_in_queue": len(q.order), "items": items}, nil
}

func (c *Client) QueueItem(ctx context.Context, contentType string, contentID int) (M, error) {
	q, err := c.loadQueue(ctx)
	if err != nil {
		return nil, err
	}
	it, ok := q.byKey[queueKey{contentType, contentID}]
	if !ok {
		return nil, fmt.Errorf("%s %d is not in the approval queue (already handled?)", contentType, contentID)
	}
	out := c.describeItem(it, true)
	switch contentType {
	case "post":
		if p, err := c.ReadPost(ctx, contentID); err == nil {
			out["post"] = p
		} else {
			out["post_error"] = err.Error()
		}
	case "thread":
		if t, err := c.ReadThread(ctx, contentID, 1, true); err == nil {
			out["thread"] = t
		} else {
			out["thread_error"] = err.Error()
		}
	}
	return out, nil
}

type Decision struct {
	ContentType string `json:"content_type" jsonschema:"content type from approval_queue_list, e.g. post, thread, user"`
	ContentID   int    `json:"content_id"`
	Action      string `json:"action" jsonschema:"one of the item's available actions, e.g. approve, reject"`
	Reason      string `json:"reason,omitempty" jsonschema:"text shown to the author as the rejection reason (the site limits it, usually to 100 chars)"`
	Notify      *bool  `json:"notify,omitempty" jsonschema:"notify the author, if the site has that option (default: as the site suggests)"`
	Note        string `json:"note,omitempty" jsonschema:"moderator's own summary for the decision log (why, findings, rule points); not sent to the site"`
}

func formInputs(box *goquery.Selection) []*goquery.Selection {
	var out []*goquery.Selection
	box.Find("input[name], textarea[name], select[name]").Each(func(_ int, in *goquery.Selection) {
		out = append(out, in)
	})
	return out
}

func (c *Client) QueueProcess(ctx context.Context, decisions []Decision, dryRun bool) (M, error) {
	if err := c.checkWritable(dryRun); err != nil {
		return nil, err
	}
	q, err := c.loadQueue(ctx)
	if err != nil {
		return nil, err
	}
	token, err := csrf(q.doc)
	if err != nil {
		return nil, err
	}
	chosen := map[queueKey]Decision{}
	var problems []string
	for _, d := range decisions {
		key := queueKey{d.ContentType, d.ContentID}
		chosen[key] = d
		it, ok := q.byKey[key]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s %d: not in the queue", key.ContentType, key.ContentID))
		case !it.hasOption(d.Action):
			problems = append(problems, fmt.Sprintf("%s %d: action %q not available, options: %q",
				key.ContentType, key.ContentID, d.Action, it.optionValues()))
		case d.Reason != "":
			field := it.container.Find(`input[name*="reason"], textarea[name*="reason"]`).First()
			if limit, err := strconv.Atoi(field.AttrOr("maxlength", "")); err == nil && utf8.RuneCountInString(d.Reason) > limit {
				problems = append(problems, fmt.Sprintf("%s %d: reason is %d chars, the site allows at most %d "+
					"(longer text is silently dropped and nothing happens)", key.ContentType, key.ContentID,
					utf8.RuneCountInString(d.Reason), limit))
			}
		}
	}
	if problems != nil {
		return nil, fmt.Errorf("%s", strings.Join(problems, "; "))
	}

	form := newOrderedForm()
	form.add("_xfToken", token)
	for _, it := range q.order {
		d, ok := chosen[it.key]
		action := ""
		if ok {
			action = d.Action
		}
		form.add(fmt.Sprintf("queue[%s][%d]", it.key.ContentType, it.key.ContentID), action)
		if !ok {
			continue
		}
		for _, in := range formInputs(it.container) {
			name := in.AttrOr("name", "")
			low := strings.ToLower(name)
			_, checked := in.Attr("checked")
			switch {
			case queueName.MatchString(name) || name == "_xfToken":
			case strings.Contains(low, "reason"):
				if d.Reason != "" {
					form.add(name, d.Reason)
				}
			case strings.Contains(low, "notify") || strings.Contains(low, "alert"):
				if (d.Notify != nil && *d.Notify) || (d.Notify == nil && checked) {
					form.add(name, in.AttrOr("value", "1"))
				}
			case in.AttrOr("type", "") == "hidden":
				form.add(name, in.AttrOr("value", ""))
			}
		}
	}
	action := q.doc.Find(`form[action*="approval-queue"]`).First().AttrOr("action", "/approval-queue/process")
	var summary []string
	for _, d := range decisions {
		s := fmt.Sprintf("%s %s %d", d.Action, d.ContentType, d.ContentID)
		if d.Reason != "" {
			s += " (reason: " + d.Reason + ")"
		}
		summary = append(summary, s)
	}
	if dryRun {
		return M{"dry_run": true, "would_post_to": c.absolute(action), "decisions": summary,
			"form": form.visible(), "log_file": c.cfg.LogPath}, nil
	}

	meta := map[queueKey]LogEntry{}
	for key := range chosen {
		meta[key] = c.logMeta(ctx, q.byKey[key])
	}
	moderator := visitorName(q.doc)
	status, body, err := c.post(ctx, action, form.values(), true)
	if err != nil {
		return nil, err
	}
	siteStatus := siteAnswer(body)
	if errs := siteErrors(body); errs != "" {
		return nil, fmt.Errorf("blast.hk: %s", errs)
	}

	// The queue page can lag behind the write for a moment: re-check a few times before calling it a failure.
	var after *queue
	for _, delay := range []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second} {
		if err := sleep(ctx, delay); err != nil {
			return nil, err
		}
		if after, err = c.loadQueue(ctx); err != nil {
			return nil, err
		}
		pending := false
		for key := range chosen {
			pending = pending || after.byKey[key] != nil
		}
		if !pending {
			break
		}
	}
	still := []string{}
	var entries []LogEntry
	for _, d := range decisions {
		key := queueKey{d.ContentType, d.ContentID}
		applied := after.byKey[key] == nil
		if !applied {
			still = append(still, fmt.Sprintf("%s %d", key.ContentType, key.ContentID))
		}
		e := meta[key]
		e.ContentType, e.ContentID, e.Action, e.Reason, e.Note = key.ContentType, key.ContentID, d.Action, d.Reason, d.Note
		e.Moderator, e.Applied = moderator, applied
		if d.Notify != nil {
			e.Notify = *d.Notify
		} else {
			e.Notify = q.byKey[key].container.Find(`input[name*="notify"][checked]`).Length() > 0
		}
		entries = append(entries, e)
	}
	logErr := c.writeLog(entries)
	out := M{"ok": len(still) == 0, "sent": summary, "http_status": status, "site_status": siteStatus,
		"still_in_queue": still, "remaining_in_queue": len(after.order), "log_file": c.cfg.LogPath}
	if len(still) > 0 {
		out["warning"] = "Site answered but these items are still in the queue: the action was NOT applied"
	}
	if logErr != nil {
		out["log_error"] = logErr.Error()
	}
	return out, nil
}

func (c *Client) logMeta(ctx context.Context, it *queueItem) LogEntry {
	d := c.describeItem(it, false)
	e := LogEntry{Title: d["title"].(string), Author: d["author"].(string), Date: d["date"].(string)}
	if f, ok := d["forum"].(string); ok {
		e.Forum = f
	}
	kind := "threads"
	if it.key.ContentType != "thread" {
		kind = "posts"
	}
	e.URL = fmt.Sprintf("%s/%s/%d/", c.cfg.BaseURL, kind, it.key.ContentID)
	for _, l := range d["links"].([]M) {
		u := l["url"].(string)
		if strings.Contains(u, "/members/") && e.AuthorURL == "" {
			e.AuthorURL = u
		}
	}
	if it.key.ContentType == "thread" || it.key.ContentType == "post" {
		var la M
		var err error
		if it.key.ContentType == "thread" {
			la, err = c.ListAttachments(ctx, it.key.ContentID, 0)
		} else {
			la, err = c.ListAttachments(ctx, 0, it.key.ContentID)
		}
		if err == nil {
			e.Attachments = c.describeFiles(la["attachments"].([]M))
		}
	}
	return e
}

func (c *Client) describeFiles(list []M) []string {
	var out []string
	for _, a := range list {
		if a["inline_image"] == true {
			continue
		}
		id := a["attachment_id"].(int)
		s := fmt.Sprintf("%v (id %d, %v", a["name"], id, a["size"])
		if sha := c.cachedSHA256(id); sha != "" {
			s += ", sha256 " + sha
		}
		out = append(out, s+")")
	}
	return out
}

// siteAnswer and siteErrors read XenForo's JSON reply to an ajax form submit.
func siteAnswer(body []byte) any {
	var r struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil
	}
	return r.Status
}

func siteErrors(body []byte) string {
	var r struct {
		Errors json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Errors) == 0 || string(r.Errors) == "null" {
		return ""
	}
	var list []string
	if json.Unmarshal(r.Errors, &list) == nil {
		return strings.Join(list, "; ")
	}
	var byField map[string]string
	if json.Unmarshal(r.Errors, &byField) == nil {
		for _, v := range byField {
			list = append(list, v)
		}
		return strings.Join(list, "; ")
	}
	return string(r.Errors)
}

// orderedForm keeps the field order a browser would send; it matters only for readable dry runs.
type orderedForm struct{ pairs [][2]string }

func newOrderedForm() *orderedForm { return &orderedForm{} }

func (f *orderedForm) add(k, v string) { f.pairs = append(f.pairs, [2]string{k, v}) }

func (f *orderedForm) values() map[string][]string {
	out := map[string][]string{}
	for _, p := range f.pairs {
		out[p[0]] = append(out[p[0]], p[1])
	}
	return out
}

// visible is the dry-run view: no token, no "do nothing" entries.
func (f *orderedForm) visible() [][2]string {
	out := [][2]string{}
	for _, p := range f.pairs {
		if p[0] != "_xfToken" && p[1] != "" {
			out = append(out, p)
		}
	}
	return out
}
