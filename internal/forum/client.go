// Package forum talks to blast.hk (XenForo 2) as a logged-in moderator by reading its HTML pages
// and submitting the same forms a browser would.
package forum

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

// M is a JSON object returned to the MCP client.
type M = map[string]any

type Config struct {
	BaseURL            string
	UserAgent          string
	Cookies            string
	ReadOnly           bool
	MaxPostChars       int
	MaxAttachmentBytes int64
	LogPath            string
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// ConfigFromEnv reads the BLASTHACK_* environment variables documented in the README.
func ConfigFromEnv() Config {
	cookies := os.Getenv("BLASTHACK_COOKIES")
	for env, name := range map[string]string{"BLASTHACK_XF_USER": "xf_user", "BLASTHACK_XF_SESSION": "xf_session"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			cookies += "; " + name + "=" + v
		}
	}
	base := strings.TrimRight(os.Getenv("BLASTHACK_BASE_URL"), "/")
	if base == "" {
		base = "https://www.blast.hk"
	}
	ua := os.Getenv("BLASTHACK_USER_AGENT")
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
	}
	readOnly := strings.ToLower(os.Getenv("BLASTHACK_READONLY"))
	logPath := os.Getenv("BLASTHACK_LOG")
	if logPath == "" {
		logPath = defaultLogPath()
	}
	return Config{
		BaseURL:            base,
		UserAgent:          ua,
		Cookies:            cookies,
		ReadOnly:           readOnly == "1" || readOnly == "true" || readOnly == "yes",
		MaxPostChars:       envInt("BLASTHACK_MAX_POST_CHARS", 6000),
		MaxAttachmentBytes: int64(envInt("BLASTHACK_MAX_ATTACHMENT_MB", 100)) << 20,
		LogPath:            logPath,
	}
}

type attachment struct {
	name string
	data []byte
}

type Client struct {
	cfg  Config
	http *http.Client

	mu          sync.Mutex
	attachments map[int]attachment
}

func New(cfg Config) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	var cookies []*http.Cookie
	for _, part := range strings.Split(cfg.Cookies, ";") {
		if k, v, ok := strings.Cut(part, "="); ok && strings.TrimSpace(k) != "" {
			cookies = append(cookies, &http.Cookie{Name: strings.TrimSpace(k), Value: strings.TrimSpace(v), Path: "/"})
		}
	}
	jar.SetCookies(base, cookies)
	return &Client{
		cfg:         cfg,
		http:        &http.Client{Jar: jar, Timeout: 90 * time.Second},
		attachments: map[int]attachment{},
	}, nil
}

func (c *Client) Config() Config { return c.cfg }

func (c *Client) request(ctx context.Context, method, path string, query url.Values, body io.Reader, ajax bool) (*http.Response, error) {
	u := c.cfg.BaseURL + path
	if strings.HasPrefix(path, "http") {
		u = path
	}
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept-Language", "ru,en;q=0.8")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if ajax {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	return c.http.Do(req)
}

// fetch loads a page without judging it: callers that expect error pages (a 403 on a hidden thread)
// inspect the document themselves.
func (c *Client) fetch(ctx context.Context, path string, query url.Values) (*goquery.Document, int, string, error) {
	resp, err := c.request(ctx, http.MethodGet, path, query, nil, false)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	doc, err := parseHTML(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, "", err
	}
	return doc, resp.StatusCode, resp.Request.URL.String(), nil
}

// get loads a page and turns login, 2FA and error pages into errors.
func (c *Client) get(ctx context.Context, path string, query url.Values) (*goquery.Document, string, error) {
	doc, status, finalURL, err := c.fetch(ctx, path, query)
	if err != nil {
		return nil, "", err
	}
	if err := pageProblem(doc); err != nil {
		return nil, finalURL, err
	}
	if status >= 400 && status != 403 {
		return nil, finalURL, fmt.Errorf("blast.hk: HTTP %d for %s", status, path)
	}
	return doc, finalURL, nil
}

// post submits a form. ajax=true asks XenForo for its JSON answer instead of a redirect.
func (c *Client) post(ctx context.Context, path string, form url.Values, ajax bool) (int, []byte, error) {
	var query url.Values
	if ajax {
		query = url.Values{"_xfResponseType": {"json"}}
	}
	resp, err := c.request(ctx, http.MethodPost, path, query, strings.NewReader(form.Encode()), ajax)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, body, err
}

// parseHTML parses like a browser with JavaScript off. XenForo puts the BBCode editor field
// (textarea "message") inside <noscript>; with scripting on, that content would be plain text.
func parseHTML(r io.Reader) (*goquery.Document, error) {
	root, err := html.ParseWithOptions(r, html.ParseOptionEnableScripting(false))
	if err != nil {
		return nil, err
	}
	return goquery.NewDocumentFromNode(root), nil
}

func template(doc *goquery.Document) string {
	return doc.Find("[data-template]").First().AttrOr("data-template", "")
}

func pageProblem(doc *goquery.Document) error {
	switch template(doc) {
	case "login":
		return errors.New("blast.hk requires login for this page: cookies are missing or expired. " +
			"Update BLASTHACK_COOKIES (see README)")
	case "login_two_step":
		return errors.New("blast.hk asks for two-factor authentication: xf_user alone is not enough for a 2FA account. " +
			"Add the xf_tfa_trust cookie (log in with 'trust this device') via BLASTHACK_COOKIES")
	case "error", "message_page":
		msg := pageError(doc)
		if msg == "" {
			msg = "error page"
		}
		return errors.New("blast.hk: " + msg)
	}
	return nil
}

// pageError returns the real error text, skipping the site-wide "JavaScript disabled" and
// "outdated browser" notices that come first in every page.
func pageError(doc *goquery.Document) string {
	msg := ""
	doc.Find(".blockMessage").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		text := squash(s.Text())
		if strings.Contains(text, "JavaScript") || strings.Contains(text, "устаревший браузер") {
			return true
		}
		msg = text
		return false
	})
	return msg
}

func csrf(doc *goquery.Document) (string, error) {
	if t := doc.Find("html").AttrOr("data-csrf", ""); t != "" {
		return t, nil
	}
	if t := doc.Find(`input[name="_xfToken"]`).First().AttrOr("value", ""); t != "" {
		return t, nil
	}
	return "", errors.New("could not find the _xfToken on the page")
}

func (c *Client) absolute(href string) string {
	if href == "" || strings.HasPrefix(href, "http") {
		return href
	}
	return c.cfg.BaseURL + href
}

var idPatterns sync.Map

func idFrom(href, kind string) int {
	re, ok := idPatterns.Load(kind)
	if !ok {
		re, _ = idPatterns.LoadOrStore(kind, regexp.MustCompile(`/`+kind+`/(?:[^/]*\.)?(\d+)/`))
	}
	m := re.(*regexp.Regexp).FindStringSubmatch(href)
	if m == nil {
		return 0
	}
	id, _ := strconv.Atoi(m[1])
	return id
}

func squash(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func (c *Client) checkWritable(dryRun bool) error {
	if c.cfg.ReadOnly && !dryRun {
		return errors.New("server is in read-only mode (BLASTHACK_READONLY=1)")
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
