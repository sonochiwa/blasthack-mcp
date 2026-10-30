package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sonochiwa/blasthack-mcp/internal/forum"
)

func connect(t *testing.T, guide string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	fc, err := forum.New(forum.Config{BaseURL: "http://127.0.0.1:1", LogPath: filepath.Join(t.TempDir(), "log.txt")})
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := mcp.NewInMemoryTransports()
	if _, err := newServer(fc, guide).Connect(ctx, serverSide, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func text(t *testing.T, content []mcp.Content) string {
	t.Helper()
	if len(content) == 0 {
		t.Fatal("empty content")
	}
	tc, ok := content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T", content[0])
	}
	return tc.Text
}

// The same guide must reach the model three ways: server instructions, a tool and a prompt.
func TestGuideIsOfferedEveryWay(t *testing.T) {
	ctx := context.Background()
	cs := connect(t, builtinGuide)
	if cs.InitializeResult().Instructions != builtinGuide {
		t.Error("server instructions differ from guide.md")
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "moderation_guide"})
	if err != nil || res.IsError {
		t.Fatalf("moderation_guide: %v %v", err, res)
	}
	if text(t, res.Content) != builtinGuide {
		t.Error("moderation_guide differs from guide.md")
	}
	p, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "review_queue"})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Messages[0].Content.(*mcp.TextContent).Text; !strings.HasPrefix(got, builtinGuide) {
		t.Error("review_queue prompt does not start with the guide")
	}
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 17 {
		t.Errorf("tools = %d, want 17", len(tools.Tools))
	}
}

func TestGuideOverride(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "guide.md")
	if err := os.WriteFile(custom, []byte("\uFEFFМой порядок работы\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLASTHACK_GUIDE", custom)
	if got := loadGuide(); got != "Мой порядок работы\n" {
		t.Errorf("override = %q", got)
	}
	t.Setenv("BLASTHACK_GUIDE", filepath.Join(t.TempDir(), "missing.md"))
	if loadGuide() != builtinGuide {
		t.Error("a missing file must fall back to the built-in guide")
	}
	if !strings.Contains(builtinGuide, "dry_run=true") {
		t.Error("built-in guide lost the confirmation rule")
	}
}
