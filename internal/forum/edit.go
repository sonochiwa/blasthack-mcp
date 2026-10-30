package forum

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// formFields returns what a browser would submit for the form as it stands: text fields, checked
// boxes and selected options.
func formFields(form *goquery.Selection) *orderedForm {
	out := newOrderedForm()
	form.Find("input[name], textarea[name], select[name]").Each(func(_ int, el *goquery.Selection) {
		name := el.AttrOr("name", "")
		switch goquery.NodeName(el) {
		case "select":
			el.Find("option[selected]").Each(func(_ int, o *goquery.Selection) {
				out.add(name, o.AttrOr("value", strings.TrimSpace(o.Text())))
			})
		case "textarea":
			out.add(name, el.Text())
		default:
			switch el.AttrOr("type", "") {
			case "checkbox", "radio":
				if _, checked := el.Attr("checked"); checked {
					out.add(name, el.AttrOr("value", "on"))
				}
			case "submit", "button", "file":
			default:
				out.add(name, el.AttrOr("value", ""))
			}
		}
	})
	return out
}

func (f *orderedForm) without(names ...string) *orderedForm {
	drop := map[string]bool{}
	for _, n := range names {
		drop[n] = true
	}
	out := newOrderedForm()
	for _, p := range f.pairs {
		if !drop[p[0]] {
			out.add(p[0], p[1])
		}
	}
	return out
}

func (f *orderedForm) get(name string) (string, bool) {
	for _, p := range f.pairs {
		if p[0] == name {
			return p[1], true
		}
	}
	return "", false
}

func (f *orderedForm) names() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range f.pairs {
		if p[0] != "_xfToken" && !seen[p[0]] {
			seen[p[0]] = true
			out = append(out, p[0])
		}
	}
	return out
}

type EditParams struct {
	PostID        int
	AppendBBCode  string
	ReplaceBBCode string
	Silent        bool
	NotifyAuthor  bool
	AlertReason   string
	Note          string
	DryRun        bool
}

// EditPost appends to or replaces a post's BBCode as moderator; title, prefixes, custom fields and
// attachments are submitted unchanged.
func (c *Client) EditPost(ctx context.Context, p EditParams) (M, error) {
	if (p.AppendBBCode == "") == (p.ReplaceBBCode == "") {
		return nil, fmt.Errorf("pass exactly one of append_bbcode / replace_bbcode")
	}
	if err := c.checkWritable(p.DryRun); err != nil {
		return nil, err
	}
	doc, _, err := c.get(ctx, fmt.Sprintf("/posts/%d/edit", p.PostID), nil)
	if err != nil {
		return nil, err
	}
	form := doc.Find(fmt.Sprintf(`form[action*="/posts/%d/edit"]`, p.PostID)).First()
	if form.Length() == 0 {
		return nil, fmt.Errorf("no edit form: you may not have permission to edit this post")
	}
	fields := formFields(form)
	old, ok := fields.get("message")
	if !ok {
		return nil, fmt.Errorf("the edit form has no BBCode 'message' field")
	}
	text := p.ReplaceBBCode
	if p.AppendBBCode != "" {
		text = strings.TrimRight(old, " \t\r\n") + "\n\n" + strings.TrimSpace(p.AppendBBCode)
	}
	// Send BBCode only: without the WYSIWYG html copy XenForo takes `message` as is.
	out := fields.without("message_html", "message", "silent", "clear_edit", "author_alert", "author_alert_reason")
	out.add("message", text)
	if p.Silent {
		out.add("silent", "1")
	}
	if p.NotifyAuthor {
		out.add("author_alert", "1")
		out.add("author_alert_reason", p.AlertReason)
	}
	title, _ := fields.get("title")
	preview := M{"post_id": p.PostID, "title": title, "silent": p.Silent, "notify_author": p.NotifyAuthor,
		"kept_fields": out.names(), "old_length": len([]rune(old)), "new_length": len([]rune(text))}
	if p.NotifyAuthor {
		preview["alert_reason"] = p.AlertReason
	}
	if p.AppendBBCode != "" {
		preview["added_text"] = p.AppendBBCode
	} else {
		preview["new_text"] = text
	}
	action := form.AttrOr("action", "")
	if p.DryRun {
		preview["dry_run"] = true
		preview["would_post_to"] = c.absolute(action)
		return preview, nil
	}

	status, body, err := c.post(ctx, action, out.values(), true)
	if err != nil {
		return nil, err
	}
	if errs := siteErrors(body); errs != "" {
		return nil, fmt.Errorf("blast.hk: %s", errs)
	}
	check, _, err := c.get(ctx, fmt.Sprintf("/posts/%d/edit", p.PostID), nil)
	if err != nil {
		return nil, err
	}
	applied := strings.TrimSpace(check.Find(`textarea[name="message"]`).Text()) == strings.TrimSpace(text)

	entry := LogEntry{ContentType: "post", ContentID: p.PostID, Action: "edit", Applied: applied,
		Moderator: visitorName(doc), Title: title, URL: fmt.Sprintf("%s/posts/%d/", c.cfg.BaseURL, p.PostID),
		Notify: p.NotifyAuthor}
	if post, err := c.ReadPost(ctx, p.PostID); err == nil {
		entry.Author, _ = post["author"].(string)
	}
	if p.NotifyAuthor {
		entry.Reason = "уведомление автору: " + p.AlertReason
	}
	entry.Note = p.Note
	if p.AppendBBCode != "" {
		entry.Note = strings.TrimSpace(entry.Note + "\nДобавлено в пост:\n" + p.AppendBBCode)
	} else {
		entry.Note = strings.TrimSpace(entry.Note + "\nТекст поста заменён целиком.")
	}
	result := M{"ok": applied, "http_status": status, "site_status": siteAnswer(body), "log_file": c.cfg.LogPath}
	if err := c.writeLog([]LogEntry{entry}); err != nil {
		result["log_error"] = err.Error()
	}
	if !applied {
		result["warning"] = "The post text did not change: the edit was NOT applied"
	}
	return result, nil
}

type MoveParams struct {
	ThreadID      int
	TargetForumID int
	AlertAuthor   bool
	AlertReason   string
	LeaveRedirect bool
	Note          string
	DryRun        bool
}

// MoveThread moves a thread to another section. A thread still awaiting approval is not moved into a
// section the account cannot moderate: it would become invisible to the moderator and get stuck there.
func (c *Client) MoveThread(ctx context.Context, p MoveParams) (M, error) {
	if err := c.checkWritable(p.DryRun); err != nil {
		return nil, err
	}
	doc, _, err := c.get(ctx, fmt.Sprintf("/threads/%d/move", p.ThreadID), nil)
	if err != nil {
		return nil, err
	}
	form := doc.Find(fmt.Sprintf(`form[action*="/threads/%d/move"]`, p.ThreadID)).First()
	if form.Length() == 0 {
		return nil, fmt.Errorf("no move form: you may not have permission to move this thread")
	}
	names := map[string]string{}
	from, fromID := "", ""
	form.Find(`select[name="target_node_id"] option`).Each(func(_ int, o *goquery.Selection) {
		label := strings.TrimSpace(strings.ReplaceAll(o.Text(), " ", " "))
		names[o.AttrOr("value", "")] = label
		if _, sel := o.Attr("selected"); sel {
			from, fromID = label, o.AttrOr("value", "")
		}
	})
	target := strconv.Itoa(p.TargetForumID)
	to, ok := names[target]
	if !ok {
		return nil, fmt.Errorf("forum %d is not a valid move target", p.TargetForumID)
	}
	thread, _, err := c.get(ctx, fmt.Sprintf("/threads/%d/", p.ThreadID), nil)
	if err != nil {
		return nil, err
	}
	canModerate, err := c.CanModerateForum(ctx, p.TargetForumID)
	if err != nil {
		return nil, err
	}
	if threadStatus(thread)["status"] == "awaiting_approval" && !canModerate {
		return nil, fmt.Errorf("you have no moderator rights in «%s» (%d). The thread is still awaiting approval: "+
			"after the move you could neither approve it nor move it back. Approve it first (then move), "+
			"or ask a moderator of that section", to, p.TargetForumID)
	}

	fields := formFields(form)
	out := fields.without("target_node_id", "redirect_type", "notify_watchers", "starter_alert", "starter_alert_reason")
	out.add("target_node_id", target)
	redirect := "none"
	if p.LeaveRedirect {
		redirect = "permanent"
	}
	out.add("redirect_type", redirect)
	out.add("notify_watchers", "1")
	if p.AlertAuthor {
		out.add("starter_alert", "1")
		out.add("starter_alert_reason", p.AlertReason)
	}
	var prefixes []string
	form.Find(`select[name="prefix_id[]"] option[selected]`).Each(func(_ int, o *goquery.Selection) {
		prefixes = append(prefixes, strings.TrimSpace(o.Text()))
	})
	title, _ := fields.get("title")
	preview := M{"thread_id": p.ThreadID, "title": title, "prefixes": prefixes, "from": from, "from_id": fromID,
		"to": to, "to_id": p.TargetForumID, "alert_author": p.AlertAuthor, "leave_redirect": p.LeaveRedirect,
		"you_moderate_target": canModerate}
	if p.AlertAuthor {
		preview["alert_reason"] = p.AlertReason
	}
	action := form.AttrOr("action", "")
	if p.DryRun {
		preview["dry_run"] = true
		preview["would_post_to"] = c.absolute(action)
		preview["note"] = "Several sections share a name (there are many «Читы»): check to_id. Prefixes are kept; " +
			"check that they exist in the target section."
		return preview, nil
	}

	status, body, err := c.post(ctx, action, out.values(), true)
	if err != nil {
		return nil, err
	}
	if errs := siteErrors(body); errs != "" {
		return nil, fmt.Errorf("blast.hk: %s", errs)
	}
	// The thread page may now be a 403 ("awaiting approval") for us, so read it without judging.
	after, _, _, err := c.fetch(ctx, fmt.Sprintf("/threads/%d/", p.ThreadID), nil)
	nowForum := 0
	if err == nil {
		after.Find(".p-breadcrumbs").First().Find(`a[href*="/forums/"]`).Each(func(_ int, a *goquery.Selection) {
			nowForum = idFrom(a.AttrOr("href", ""), "forums")
		})
	}
	applied := nowForum == p.TargetForumID
	author := ""
	if err == nil {
		author = after.Find("article.message--post").First().AttrOr("data-author", "")
	}
	entry := LogEntry{ContentType: "thread", ContentID: p.ThreadID, Action: "move", Applied: applied,
		Moderator: visitorName(doc), Title: title, Author: author, Notify: p.AlertAuthor, Note: p.Note,
		URL:   fmt.Sprintf("%s/threads/%d/", c.cfg.BaseURL, p.ThreadID),
		Forum: fmt.Sprintf("%s (%s) → %s (%d)", from, fromID, to, p.TargetForumID)}
	if p.AlertAuthor {
		entry.Reason = "уведомление автору: " + p.AlertReason
	}
	result := M{"ok": applied, "http_status": status, "site_status": siteAnswer(body), "now_in_forum": nowForum,
		"log_file": c.cfg.LogPath}
	if err := c.writeLog([]LogEntry{entry}); err != nil {
		result["log_error"] = err.Error()
	}
	if !applied {
		result["warning"] = "The thread is not in the target section: the move was NOT applied"
	}
	return result, nil
}
