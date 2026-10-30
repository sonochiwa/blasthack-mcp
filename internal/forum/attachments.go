package forum

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"github.com/sonochiwa/blasthack-mcp/internal/analyzer"
)

var hosterRules = []struct {
	re   *regexp.Regexp
	note string
}{
	{regexp.MustCompile(`(?i)disk\.yandex|yadi\.sk|drive\.google|docs\.google|dropbox\.com|onedrive\.live|1drv\.ms|cloud\.mail\.ru`),
		"forbidden: file host where the file can be replaced without changing the link"},
	{regexp.MustCompile(`(?i)mega\.nz|mediafire|gofile|anonfiles|sendspace|uploadfiles|zippyshare|4shared|rghost`),
		"file host: check that the link is direct and the content matches"},
	{regexp.MustCompile(`(?i)github\.com|gitlab\.com|raw\.githubusercontent`),
		"repository: check that the release matches the attachment"},
	{regexp.MustCompile(`(?i)adf\.ly|shorte\.st|ouo\.io|linkvertise|bc\.vc|clk\.sh|exe\.io|cutt\.ly|bit\.ly|tinyurl`),
		"monetised/short link: allowed only alongside a direct link or attachment"},
}

var redirectID = regexp.MustCompile(`/redirect/([A-Za-z0-9_\-=]+)`)

// realLink decodes XenForo's /redirect/<base64> wrapper around external links.
func (c *Client) realLink(href string) string {
	m := redirectID.FindStringSubmatch(href)
	if m == nil {
		return c.absolute(href)
	}
	raw := strings.TrimRight(m[1], "=")
	if dec, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return string(dec)
	}
	if dec, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return string(dec)
	}
	return href
}

func (c *Client) firstPost(ctx context.Context, threadID, postID int) (*goquery.Selection, string, error) {
	var path, selector string
	switch {
	case postID > 0:
		path, selector = fmt.Sprintf("/posts/%d/", postID), fmt.Sprintf(`article[data-content="post-%d"]`, postID)
	case threadID > 0:
		path, selector = fmt.Sprintf("/threads/%d/", threadID), "article.message--post"
	default:
		return nil, "", fmt.Errorf("pass thread_id or post_id")
	}
	doc, finalURL, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, "", err
	}
	art := doc.Find(selector).First()
	if art.Length() == 0 {
		return nil, "", fmt.Errorf("post not found on %s", finalURL)
	}
	return art, finalURL, nil
}

func (c *Client) ListAttachments(ctx context.Context, threadID, postID int) (M, error) {
	art, finalURL, err := c.firstPost(ctx, threadID, postID)
	if err != nil {
		return nil, err
	}
	external := []M{}
	art.Find(".bbWrapper a[href]").Each(func(_ int, a *goquery.Selection) {
		href := a.AttrOr("href", "")
		if !strings.Contains(href, "/redirect/") && !strings.HasPrefix(href, "http") {
			return
		}
		real := c.realLink(href)
		if real == "" || strings.HasPrefix(real, c.cfg.BaseURL) {
			return
		}
		link := M{"url": real, "text": clip(squash(a.Text()), 80)}
		for _, r := range hosterRules {
			if r.re.MatchString(real) {
				link["rule_note"] = r.note
				break
			}
		}
		external = append(external, link)
	})
	attachments := c.parseAttachments(art)
	if attachments == nil {
		attachments = []M{}
	}
	return M{"url": finalURL, "author": art.AttrOr("data-author", ""), "attachments": attachments,
		"external_links": external}, nil
}

// download fetches an attachment into memory (never to disk) and caches it for later reads.
func (c *Client) download(ctx context.Context, id int) (attachment, error) {
	c.mu.Lock()
	cached, ok := c.attachments[id]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}
	resp, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/attachments/%d/", id), nil, nil, false)
	if err != nil {
		return attachment{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return attachment{}, fmt.Errorf("attachment %d: HTTP %d", id, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxAttachmentBytes+1))
	if err != nil {
		return attachment{}, err
	}
	if int64(len(data)) > c.cfg.MaxAttachmentBytes {
		return attachment{}, fmt.Errorf("attachment %d is larger than %d MB", id, c.cfg.MaxAttachmentBytes>>20)
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") && bytes.Contains(data, []byte("data-template=")) {
		doc, err := parseHTML(bytes.NewReader(data))
		if err == nil {
			if problem := pageProblem(doc); problem != nil {
				return attachment{}, problem
			}
		}
		return attachment{}, fmt.Errorf("attachment %d: got an HTML page instead of a file", id)
	}
	name := fmt.Sprintf("attachment-%d", id)
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil && params["filename"] != "" {
		name = params["filename"]
	}
	a := attachment{name: name, data: data}
	c.mu.Lock()
	c.attachments[id] = a
	c.mu.Unlock()
	return a, nil
}

func (c *Client) cachedSHA256(id int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if a, ok := c.attachments[id]; ok {
		return analyzer.SHA256(a.data)
	}
	return ""
}

func (c *Client) AnalyzeAttachment(ctx context.Context, id int, includeInfo bool) (M, error) {
	a, err := c.download(ctx, id)
	if err != nil {
		return nil, err
	}
	rep := analyzer.Analyze(a.name, a.data)
	if !includeInfo {
		for i := range rep.Files {
			kept := []analyzer.Finding{}
			for _, f := range rep.Files[i].Findings {
				if f.Severity != "info" {
					kept = append(kept, f)
				}
			}
			rep.Files[i].Findings = kept
		}
	}
	return M{"attachment_id": id, "name": rep.Name, "size": rep.Size, "sha256": rep.SHA256, "files": rep.Files,
		"summary": rep.Summary, "note": rep.Note}, nil
}

func (c *Client) ReadAttachment(ctx context.Context, id int, member string, startLine, maxLines int) (M, error) {
	a, err := c.download(ctx, id)
	if err != nil {
		return nil, err
	}
	path, blob, err := analyzer.ReadMember(a.name, a.data, member)
	if err != nil {
		return nil, err
	}
	kind := analyzer.Sniff(blob, path)
	var text string
	if kind == "text" {
		text = analyzer.DecodeText(blob)
	} else {
		text = analyzer.PrintableStrings(blob, 6)
	}
	all := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	start := max(startLine, 1)
	if maxLines <= 0 {
		maxLines = 300
	}
	maxLines = min(maxLines, 2000)
	end := min(start-1+maxLines, len(all))
	var b strings.Builder
	width := len(fmt.Sprint(end))
	for i := start - 1; i < end; i++ {
		line := all[i]
		if r := []rune(line); len(r) > 2000 {
			line = string(r[:2000])
		}
		fmt.Fprintf(&b, "%*d| %s\n", width, i+1, line)
	}
	out := M{"file": path, "type": kind, "total_lines": len(all), "from": start, "to": end, "content": b.String()}
	if kind != "text" {
		out["note"] = "binary file: showing printable strings"
	}
	return out, nil
}
