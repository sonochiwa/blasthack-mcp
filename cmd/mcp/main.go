// BlastHack MCP lets an AI assistant help blast.hk moderators: read the forum, scan attachments for
// stealers without running them, review the approval queue against the forum rules and act on it.
// Every write is previewed first and logged to the moderator's decision journal.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sonochiwa/blasthack-mcp/internal/forum"
)

func newServer(client *forum.Client, guide string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "blasthack", Title: "BlastHack MCP", Version: version},
		&mcp.ServerOptions{Instructions: guide})
	registerTools(server, client, guide)
	return server
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println("BlastHack MCP v" + version)
		return
	}
	// stdout carries the MCP protocol, so diagnostics go to stderr.
	log.SetOutput(os.Stderr)
	client, err := forum.New(forum.ConfigFromEnv())
	if err != nil {
		log.Fatal(err)
	}
	if err := newServer(client, loadGuide()).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
