package mcp

import (
	"strings"
	"testing"
)

// TestUsagePinned keeps usage.md coherent with the real tool surface:
// adding/renaming a tool, a result field, or an error code means updating
// the manual, or this test fails.
func TestUsagePinned(t *testing.T) {
	for _, term := range []string{
		// tools
		"lookup", "cache_status", "get_usage",
		// lookup arguments
		"`query`", "`type`", "`raw`", "`refresh`",
		// result fields
		"query_ascii", "source", "registrar", "abuse_contact", "raw_text",
		// error codes
		"invalid_input", "not_found", "no_rdap_service", "network_error",
	} {
		if !strings.Contains(usageMarkdown, term) {
			t.Errorf("usage.md does not mention %q", term)
		}
	}
	for _, term := range []string{"lookup", "get_usage", "structured"} {
		if !strings.Contains(Instructions, term) {
			t.Errorf("Instructions does not mention %q", term)
		}
	}
}
