// Package mcp implements the zero-dependency stdio JSON-RPC 2.0 MCP server
// (Phase 2) with the lookup / cache_status / get_usage tools, skeleton
// ported from data-toolbox-mcp. Tool errors are structured
// ({code, message, details}); invalid input returns code "invalid_input"
// without touching the network. The embedded usage.md manual is pinned by a
// test.
package mcp
