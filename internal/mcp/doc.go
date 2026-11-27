// Package mcp is whois-lookup's stdio MCP server, speaking both eras of the
// protocol through nlink-jp/mcp's server.ToolServer (ADR-0001), with the
// lookup / cache_status / get_usage tools. Tool errors are structured
// ({code, message, details}); invalid input returns code "invalid_input"
// without touching the network. The embedded usage.md manual is pinned by a
// test.
package mcp
