// Package engine ties query + bootstrap + rdap + whois + cache + config
// together (Phase 1): validate the input, consult the cache, resolve the
// RDAP endpoint, query, fall back to port 43 when the TLD has no RDAP, and
// normalize the result. Shared by the CLI and (Phase 2) the MCP server so
// their behaviour cannot diverge. All I/O dependencies are injected for
// tests.
package engine
