package mcp

import (
	"encoding/json"
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

// TestEveryToolSchemaIsValidAndClosed keeps a mistyped argument from reading as
// a real one: org ADR-021 §10 requires every registered schema to set
// additionalProperties:false, and requires this assertion to exist, because a
// rule stated only in prose is re-decided by whoever adds the next tool.
//
// The flag is the declared half of the contract — what a schema-checking client
// refuses before the call. The enforcing half is decodeArgs
// (DisallowUnknownFields), which refuses an unknown argument that arrives
// anyway; TestUnknownArgumentIsRefusedByName covers it.
func TestEveryToolSchemaIsValidAndClosed(t *testing.T) {
	b, err := json.Marshal(toolsList())
	if err != nil {
		t.Fatalf("marshal tool list: %v", err)
	}
	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Type                 string `json:"type"`
				AdditionalProperties *bool  `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("tool list is not valid JSON: %v", err)
	}
	// Without this the loop below passes by having nothing to check.
	if len(list.Tools) == 0 {
		t.Fatal("toolsList returned no tools")
	}
	for _, tool := range list.Tools {
		if tool.InputSchema.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", tool.Name, tool.InputSchema.Type)
		}
		if tool.InputSchema.AdditionalProperties == nil || *tool.InputSchema.AdditionalProperties {
			t.Errorf("%s: schema should set additionalProperties:false so typos are caught", tool.Name)
		}
	}
}
