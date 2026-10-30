package forum

import (
	"strings"
	"testing"
)

// XenForo keeps the BBCode copy of the editor inside <noscript>; it must be read as a form field.
func TestEditFormFieldsInsideNoscript(t *testing.T) {
	page := `<form action="/posts/1/edit">
<select name="prefix_id[]" multiple><option value="43" selected>Lua</option><option value="7">CLEO</option></select>
<input name="title" value="T">
<textarea name="message_html">&lt;p&gt;x&lt;/p&gt;</textarea>
<noscript><textarea name="message">[B]x[/B]</textarea></noscript>
<input type="checkbox" name="silent" value="1">
<input type="checkbox" name="author_alert" value="1" checked>
</form>`
	doc, err := parseHTML(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	f := formFields(doc.Find("form"))
	for name, want := range map[string]string{"message": "[B]x[/B]", "title": "T", "prefix_id[]": "43", "author_alert": "1"} {
		if got, ok := f.get(name); !ok || got != want {
			t.Errorf("%s = %q (present %v), want %q", name, got, ok, want)
		}
	}
	if _, ok := f.get("silent"); ok {
		t.Error("unchecked box submitted")
	}
	kept := f.without("message_html", "author_alert").names()
	if strings.Join(kept, ",") != "prefix_id[],title,message" {
		t.Errorf("kept = %v", kept)
	}
}
