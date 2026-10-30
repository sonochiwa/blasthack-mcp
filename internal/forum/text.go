package forum

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

func hasClass(n *html.Node, class string) bool {
	for _, a := range n.Attr {
		if a.Key == "class" {
			for _, c := range strings.Fields(a.Val) {
				if c == class {
					return true
				}
			}
		}
	}
	return false
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func findFirst(n *html.Node, match func(*html.Node) bool) *html.Node {
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		if ch.Type == html.ElementNode && match(ch) {
			return ch
		}
		if found := findFirst(ch, match); found != nil {
			return found
		}
	}
	return nil
}

func byTag(tag string) func(*html.Node) bool {
	return func(n *html.Node) bool { return n.Data == tag }
}

func byClass(classes ...string) func(*html.Node) bool {
	return func(n *html.Node) bool {
		for _, c := range classes {
			if hasClass(n, c) {
				return true
			}
		}
		return false
	}
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(n)
	return b.String()
}

var (
	trailingSpaces = regexp.MustCompile(`[ \t]+\n`)
	manyNewlines   = regexp.MustCompile(`\n{3,}`)
)

// ToText renders a XenForo bbWrapper into readable markdown-like text: code blocks, quotes, spoilers,
// links and images survive, styling is dropped.
func (c *Client) ToText(sel *goquery.Selection) string {
	if sel == nil || sel.Length() == 0 {
		return ""
	}
	var b strings.Builder
	c.renderNode(&b, sel.Nodes[0])
	text := trailingSpaces.ReplaceAllString(b.String(), "\n")
	return strings.TrimSpace(manyNewlines.ReplaceAllString(text, "\n\n"))
}

func (c *Client) renderChildren(b *strings.Builder, n *html.Node) {
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		c.renderNode(b, ch)
	}
}

func (c *Client) renderNode(b *strings.Builder, n *html.Node) {
	if n.Type == html.TextNode {
		b.WriteString(n.Data)
		return
	}
	if n.Type != html.ElementNode {
		c.renderChildren(b, n)
		return
	}
	switch {
	case n.Data == "script" || n.Data == "style" || n.Data == "noscript":
	case n.Data == "br":
		b.WriteString("\n")
	case hasClass(n, "bbCodeBlock--code"):
		code := findFirst(n, byTag("code"))
		if code == nil {
			code = findFirst(n, byTag("pre"))
		}
		if code == nil {
			code = n
		}
		fmt.Fprintf(b, "\n```%s\n%s\n```\n", attr(n, "data-lang"), strings.TrimRight(nodeText(code), " \t\n"))
	case hasClass(n, "bbCodeBlock--quote"):
		body := findFirst(n, byClass("bbCodeBlock-expandContent"))
		if body == nil {
			body = findFirst(n, byClass("bbCodeBlock-content"))
		}
		if body == nil {
			body = n
		}
		var inner strings.Builder
		c.renderNode(&inner, body)
		text := strings.TrimSpace(inner.String())
		if who := attr(n, "data-quote"); who != "" {
			text = who + " said:\n" + text
		}
		b.WriteString("\n")
		for _, line := range strings.Split(text, "\n") {
			b.WriteString("> " + line + "\n")
		}
	case hasClass(n, "bbCodeSpoiler") || hasClass(n, "bbCodeBlock--spoiler"):
		title := ""
		if t := findFirst(n, byClass("bbCodeSpoiler-button-title", "bbCodeBlock-title")); t != nil {
			title = strings.TrimSpace(nodeText(t))
		}
		body := findFirst(n, byClass("bbCodeBlock-content"))
		if body == nil {
			body = n
		}
		var inner strings.Builder
		c.renderNode(&inner, body)
		fmt.Fprintf(b, "\n[spoiler: %s]\n%s\n[/spoiler]\n", title, strings.TrimSpace(inner.String()))
	case n.Data == "img":
		alt := attr(n, "alt")
		if hasClass(n, "smilie") {
			b.WriteString(alt)
			break
		}
		src := attr(n, "data-src")
		if src == "" {
			src = attr(n, "src")
		}
		fmt.Fprintf(b, "![%s](%s)", alt, c.absolute(src))
	case n.Data == "a":
		href := c.absolute(attr(n, "href"))
		text := nodeText(n)
		if href != "" && strings.TrimSpace(text) != "" && strings.TrimSpace(text) != href {
			fmt.Fprintf(b, "[%s](%s)", text, href)
		} else if href != "" {
			b.WriteString(href)
		} else {
			b.WriteString(text)
		}
	case n.Data == "li":
		b.WriteString("\n- ")
		c.renderChildren(b, n)
	case n.Data == "h1" || n.Data == "h2" || n.Data == "h3" || n.Data == "h4":
		b.WriteString("\n## ")
		c.renderChildren(b, n)
		b.WriteString("\n")
	case n.Data == "b" || n.Data == "strong":
		b.WriteString("**")
		c.renderChildren(b, n)
		b.WriteString("**")
	case n.Data == "div" || n.Data == "p" || n.Data == "table" || n.Data == "tr" || n.Data == "ul" || n.Data == "ol":
		b.WriteString("\n")
		c.renderChildren(b, n)
		b.WriteString("\n")
	case n.Data == "td" || n.Data == "th":
		b.WriteString(" | ")
		c.renderChildren(b, n)
	default:
		c.renderChildren(b, n)
	}
}

func clip(text string, limit int) string {
	r := []rune(text)
	if len(r) <= limit {
		return text
	}
	return string(r[:limit]) + fmt.Sprintf("\n…[cut %d chars]", len(r)-limit)
}

// lines returns the element's text with one stripped text node per line.
func lines(sel *goquery.Selection) string {
	var out []string
	for _, n := range sel.Nodes {
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.TextNode {
				if t := strings.TrimSpace(n.Data); t != "" {
					out = append(out, t)
				}
			}
			for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
				walk(ch)
			}
		}
		walk(n)
	}
	return strings.Join(out, "\n")
}
