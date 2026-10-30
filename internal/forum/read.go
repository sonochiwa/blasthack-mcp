package forum

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func (c *Client) Whoami(ctx context.Context) (M, error) {
	doc, _, err := c.get(ctx, "/", nil)
	if err != nil {
		return nil, err
	}
	return M{
		"logged_in":                   doc.Find("html").AttrOr("data-logged-in", "") == "true",
		"username":                    visitorName(doc),
		"approval_queue_link_visible": doc.Find(`a[href*="/approval-queue/"]`).Length() > 0,
		"base_url":                    c.cfg.BaseURL,
	}, nil
}

func visitorName(doc *goquery.Document) string {
	user := doc.Find(".p-navgroup--member .p-navgroup-link--user").First()
	if alt := user.Find("img[alt]").AttrOr("alt", ""); alt != "" {
		return alt
	}
	return squash(user.Text())
}

// CanModerateForum reports whether the account has moderator tools (inline moderation) in a section.
func (c *Client) CanModerateForum(ctx context.Context, forumID int) (bool, error) {
	doc, _, err := c.get(ctx, fmt.Sprintf("/forums/%d/", forumID), nil)
	if err != nil {
		return false, err
	}
	return doc.Find(".js-inlineModToggle, [data-xf-init*=inline-mod]").Length() > 0, nil
}

func (c *Client) ListForums(ctx context.Context) (M, error) {
	doc, _, err := c.get(ctx, "/", nil)
	if err != nil {
		return nil, err
	}
	var forums []M
	doc.Find(".block--category").Each(func(_ int, cat *goquery.Selection) {
		catTitle := squash(cat.Find(".block-header").First().Text())
		cat.Find(".node").Each(func(_ int, node *goquery.Selection) {
			a := node.Find(".node-title a").First()
			if a.Length() == 0 {
				return
			}
			href := a.AttrOr("href", "")
			kind := "forum"
			switch {
			case strings.Contains(href, "/categories/"):
				kind = "category"
			case strings.Contains(href, "/link-forums/"):
				kind = "link"
			}
			id := idFrom(href, "forums")
			if id == 0 {
				id = idFrom(href, "categories")
			}
			f := M{"id": id, "kind": kind, "title": strings.TrimSpace(a.Text()), "category": catTitle}
			if d := squash(node.Find(".node-description").Text()); d != "" {
				f["description"] = d
			}
			var subs []M
			node.Find(".node-subNodeFlatList a, .node-subNodeMenu a").Each(func(_ int, s *goquery.Selection) {
				if sid := idFrom(s.AttrOr("href", ""), "forums"); sid != 0 {
					subs = append(subs, M{"id": sid, "title": strings.TrimSpace(s.Text())})
				}
			})
			if subs != nil {
				f["subforums"] = subs
			}
			forums = append(forums, f)
		})
	})
	return M{"forums": forums}, nil
}

func pageCount(doc *goquery.Document) int {
	pages := 1
	doc.Find(".pageNav-main .pageNav-page a").Each(func(_ int, a *goquery.Selection) {
		if n, err := strconv.Atoi(strings.TrimSpace(a.Text())); err == nil && n > pages {
			pages = n
		}
	})
	return pages
}

func pagePath(base string, page int) string {
	if page > 1 {
		return fmt.Sprintf("%spage-%d", base, page)
	}
	return base
}

func (c *Client) ListThreads(ctx context.Context, forumID, page, prefixID int) (M, error) {
	var query url.Values
	if prefixID > 0 {
		query = url.Values{"prefix_id": {strconv.Itoa(prefixID)}}
	}
	doc, finalURL, err := c.get(ctx, pagePath(fmt.Sprintf("/forums/%d/", forumID), page), query)
	if err != nil {
		return nil, err
	}
	var subs []M
	doc.Find(".node-title a").Each(func(_ int, a *goquery.Selection) {
		subs = append(subs, M{"id": idFrom(a.AttrOr("href", ""), "forums"), "title": strings.TrimSpace(a.Text())})
	})
	var threads []M
	doc.Find(".structItem--thread").Each(func(_ int, it *goquery.Selection) {
		a := it.Find(".structItem-title a[href*='/threads/']").First()
		if a.Length() == 0 {
			return
		}
		var meta []string
		it.Find(".structItem-cell--meta dd").Each(func(_ int, dd *goquery.Selection) {
			meta = append(meta, strings.TrimSpace(dd.Text()))
		})
		status := "visible"
		if it.HasClass("is-deleted") {
			status = "deleted"
		} else if it.HasClass("is-moderated") {
			status = "awaiting_approval"
		}
		author := it.AttrOr("data-author", "")
		if author == "" {
			author = strings.TrimSpace(it.Find(".username").First().Text())
		}
		t := M{
			"thread_id": idFrom(a.AttrOr("href", ""), "threads"),
			"status":    status,
			"title":     strings.TrimSpace(a.Text()),
			"prefix":    strings.TrimSpace(it.Find(".structItem-title .label").First().Text()),
			"author":    author,
			"started":   it.Find(".structItem-startDate time, .structItem-minor time").First().AttrOr("datetime", ""),
			"last_post": it.Find(".structItem-cell--latest time").First().AttrOr("datetime", ""),
			"sticky":    it.Find(".structItem-status--sticky").Length() > 0,
			"locked":    it.Find(".structItem-status--locked").Length() > 0,
		}
		if len(meta) > 0 {
			t["replies"] = meta[0]
		}
		if len(meta) > 1 {
			t["views"] = meta[1]
		}
		threads = append(threads, t)
	})
	out := M{"forum": strings.TrimSpace(doc.Find("h1.p-title-value").Text()), "url": finalURL, "page": max(page, 1),
		"pages": pageCount(doc), "threads": threads}
	if subs != nil {
		out["subforums"] = subs
	}
	return out, nil
}

// threadStatus reads the moderator-only status banner: deleted (with who, when and why),
// awaiting approval, locked.
func threadStatus(doc *goquery.Document) M {
	out := M{"status": "visible"}
	if d := doc.Find(".blockStatus-message--deleted").First(); d.Length() > 0 {
		out["status"] = "deleted"
		out["deleted_info"] = squash(d.Text())
	} else if doc.Find(".blockStatus-message--moderated").Length() > 0 {
		out["status"] = "awaiting_approval"
	}
	if doc.Find(".blockStatus-message--locked").Length() > 0 {
		out["locked"] = true
	}
	return out
}

func postStatus(art *goquery.Selection) M {
	if d := art.Find(".messageNotice--deleted").First(); art.HasClass("is-deleted") || d.Length() > 0 {
		out := M{"status": "deleted"}
		if d.Length() > 0 {
			out["deleted_info"] = squash(d.Text())
		}
		return out
	}
	if art.HasClass("is-moderated") || art.Find(".messageNotice--moderated").Length() > 0 {
		return M{"status": "awaiting_approval"}
	}
	return M{"status": "visible"}
}

func (c *Client) parseAttachments(art *goquery.Selection) []M {
	var out []M
	known := map[int]bool{}
	art.Find(".attachmentList .file").Each(func(_ int, f *goquery.Selection) {
		id := idFrom(f.Find(`a[href*="/attachments/"]`).AttrOr("href", ""), "attachments")
		name := f.Find(".file-name").First()
		title := name.AttrOr("title", "")
		if title == "" {
			title = strings.TrimSpace(name.Text())
		}
		size, _, _ := strings.Cut(squash(f.Find(".file-meta").Text()), "·")
		known[id] = true
		out = append(out, M{"attachment_id": id, "name": title, "size": strings.TrimSpace(size)})
	})
	// Images inserted inline also live under /attachments/.
	art.Find(`.bbWrapper a[href*="/attachments/"], .bbWrapper img[src*="/attachments/"]`).Each(func(_ int, s *goquery.Selection) {
		href := s.AttrOr("href", s.AttrOr("src", ""))
		id := idFrom(href, "attachments")
		if id == 0 || known[id] {
			return
		}
		known[id] = true
		out = append(out, M{"attachment_id": id, "name": s.AttrOr("alt", s.AttrOr("title", "")), "inline_image": true})
	})
	return out
}

var digits = regexp.MustCompile(`\d+`)

func (c *Client) parsePost(art *goquery.Selection, full bool) M {
	text := c.ToText(art.Find(".message-body .bbWrapper").First())
	if text == "" {
		text = c.ToText(art.Find(".bbWrapper").First())
	}
	if !full {
		text = clip(text, c.cfg.MaxPostChars)
	}
	postID, _ := strconv.Atoi(digits.FindString(art.AttrOr("data-content", art.AttrOr("id", ""))))
	p := M{
		"post_id": postID,
		"author":  art.AttrOr("data-author", ""),
		"date":    art.Find("time.u-dt").First().AttrOr("datetime", ""),
		"url":     fmt.Sprintf("%s/posts/%d/", c.cfg.BaseURL, postID),
		"text":    text,
	}
	for k, v := range postStatus(art) {
		p[k] = v
	}
	if att := c.parseAttachments(art); att != nil {
		p["attachments"] = att
	}
	return p
}

func (c *Client) ReadThread(ctx context.Context, threadID, page int, firstPostOnly bool) (M, error) {
	doc, finalURL, err := c.get(ctx, pagePath(fmt.Sprintf("/threads/%d/", threadID), page), nil)
	if err != nil {
		return nil, err
	}
	title := doc.Find("h1.p-title-value").First()
	var tags, crumbs []string
	doc.Find(".tagList .tagItem").Each(func(_ int, s *goquery.Selection) { tags = append(tags, strings.TrimSpace(s.Text())) })
	doc.Find(".p-breadcrumbs").First().Find("a").Each(func(_ int, s *goquery.Selection) {
		crumbs = append(crumbs, strings.TrimSpace(s.Text()))
	})
	arts := doc.Find("article.message--post")
	if firstPostOnly {
		arts = arts.First()
	}
	var posts []M
	arts.Each(func(_ int, art *goquery.Selection) { posts = append(posts, c.parsePost(art, firstPostOnly)) })
	out := M{"thread_id": threadID, "title": squash(title.Text()), "prefix": strings.TrimSpace(title.Find(".label").First().Text()),
		"breadcrumbs": crumbs, "tags": tags, "url": finalURL, "page": max(page, 1), "pages": pageCount(doc), "posts": posts}
	for k, v := range threadStatus(doc) {
		out[k] = v
	}
	return out, nil
}

func (c *Client) ReadPost(ctx context.Context, postID int) (M, error) {
	doc, finalURL, err := c.get(ctx, fmt.Sprintf("/posts/%d/", postID), nil)
	if err != nil {
		return nil, err
	}
	art := doc.Find(fmt.Sprintf(`article[data-content="post-%d"]`, postID)).First()
	if art.Length() == 0 {
		return nil, fmt.Errorf("post %d not found on %s", postID, finalURL)
	}
	ts := threadStatus(doc)
	out := c.parsePost(art, true)
	out["thread_title"] = squash(doc.Find("h1.p-title-value").First().Text())
	out["thread_id"] = idFrom(finalURL, "threads")
	out["thread_status"] = ts["status"]
	if info, ok := ts["deleted_info"]; ok {
		out["thread_deleted_info"] = info
	}
	return out, nil
}

type SearchParams struct {
	Query         string
	ForumID       int
	TitlesOnly    bool
	Author        string
	Order         string
	ResolveHidden bool
}

func (c *Client) Search(ctx context.Context, p SearchParams) (M, error) {
	page, _, err := c.get(ctx, "/search/", nil)
	if err != nil {
		return nil, err
	}
	token, err := csrf(page)
	if err != nil {
		return nil, err
	}
	order := p.Order
	if order == "" {
		order = "relevance"
	}
	form := url.Values{"_xfToken": {token}, "keywords": {p.Query}, "order": {order}, "search_type": {"post"}}
	if p.TitlesOnly {
		form.Set("c[title_only]", "1")
	}
	if p.Author != "" {
		form.Set("c[users]", p.Author)
	}
	if p.ForumID > 0 {
		form.Set("c[nodes][]", strconv.Itoa(p.ForumID))
		form.Set("c[child_nodes]", "1")
	}
	resp, err := c.request(ctx, "POST", "/search/search", nil, strings.NewReader(form.Encode()), false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	doc, err := parseHTML(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := pageProblem(doc); err != nil {
		return nil, err
	}
	var results []M
	doc.Find(".contentRow").Each(func(_ int, row *goquery.Selection) {
		a := row.Find(".contentRow-title a").First()
		if a.Length() == 0 {
			return
		}
		href := a.AttrOr("href", "")
		r := M{
			"title":     squash(a.Text()),
			"url":       c.absolute(href),
			"thread_id": idFrom(href, "threads"),
			"post_id":   idFrom(href, "posts"),
			"snippet":   squash(row.Find(".contentRow-snippet").Text()),
			"date":      row.Find("time").First().AttrOr("datetime", ""),
			"meta":      squash(row.Find(".contentRow-minor").Text()),
			"status":    "visible",
		}
		// XenForo marks both deleted and moderated content as is-deleted in search results.
		if row.HasClass("is-deleted") {
			r["status"] = "hidden"
		}
		results = append(results, r)
	})
	for _, r := range results {
		if r["status"] != "hidden" {
			continue
		}
		r["status"] = "deleted_or_awaiting_approval"
		if tid := r["thread_id"].(int); p.ResolveHidden && tid != 0 {
			if tdoc, _, err := c.get(ctx, fmt.Sprintf("/threads/%d/", tid), nil); err == nil {
				for k, v := range threadStatus(tdoc) {
					r[k] = v
				}
			}
		}
	}
	out := M{"url": resp.Request.URL.String(), "results": results}
	if results == nil {
		out["results"] = []M{}
		if msg := pageError(doc); msg != "" {
			out["message"] = msg
		}
	}
	return out, nil
}
