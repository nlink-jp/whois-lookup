package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// structured decodes a {code, message} tool error, which is the shape this
// server's errorResult produces.
func structured(t *testing.T, text string) (string, string) {
	t.Helper()
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(text), &e); err != nil {
		t.Fatalf("tool error is not structured JSON: %v (%s)", err, text)
	}
	return e.Code, e.Message
}

// TestUnknownArgumentIsRefusedByName is the enforcing half of org ADR-021 §4:
// additionalProperties:false only tells a client what is allowed, and a client
// that does not check the schema sends the typo anyway. Every tool must refuse
// it, and the message must name the offending field — a caller that is told
// only "invalid arguments" has to re-read the schema to find its own typo.
//
// `refresh` is the one that matters here: dropped, it serves a record from a
// cache with a 24h TTL as a freshly fetched one, and an expiry date is exactly
// what a caller passes `refresh` for.
func TestUnknownArgumentIsRefusedByName(t *testing.T) {
	cases := []struct {
		tool  string
		args  string
		field string
	}{
		{"lookup", `{"query":"example.com","refesh":true}`, "refesh"},
		{"lookup", `{"query":"example.com","kind":"domain"}`, "kind"},
		{"lookup", `{"query":"example.com","raw_text":true}`, "raw_text"},
		{"cache_status", `{"verbose":true}`, "verbose"},
		{"get_usage", `{"topic":"rdap"}`, "topic"},
	}
	for _, tc := range cases {
		t.Run(tc.tool+"/"+tc.field, func(t *testing.T) {
			req := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":%q,\"arguments\":%s}}\n", tc.tool, tc.args)
			text, isErr := toolText(t, drive(t, req)[0])
			if !isErr {
				t.Fatalf("%s accepted unknown argument %q: %s", tc.tool, tc.field, text)
			}
			code, msg := structured(t, text)
			if code != "invalid_input" {
				t.Errorf("%s: error code = %q, want invalid_input", tc.tool, code)
			}
			// Matching the decoder's own phrasing, not just the field name: a
			// message like "provide 'query'" happens to contain "query", so a
			// bare substring test can pass for the wrong reason.
			want := `unknown field "` + tc.field + `"`
			if !strings.Contains(msg, want) {
				t.Errorf("%s: error does not name the offending argument: want %s, got %s", tc.tool, want, msg)
			}
		})
	}
}

// TestMalformedArgumentsAreRefused covers the other half of the discarded
// error: `_ = json.Unmarshal` left `a` at its zero value when the object did
// not decode, so a wrong-typed argument produced the same call as an absent
// one — and "provide 'query'" is a misleading answer to a request that did
// provide it.
func TestMalformedArgumentsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		args string
	}{
		{"number for string", `{"query":1}`},
		{"array for object", `["example.com"]`},
		{"string for boolean", `{"query":"example.com","raw":"yes"}`},
		{"object for string", `{"query":{"name":"example.com"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"lookup\",\"arguments\":%s}}\n", tc.args)
			text, isErr := toolText(t, drive(t, req)[0])
			if !isErr {
				t.Fatalf("lookup accepted malformed arguments: %s", text)
			}
			_, msg := structured(t, text)
			if strings.Contains(msg, "provide 'query'") {
				t.Errorf("lookup reported the argument as missing instead of malformed: %s", msg)
			}
			if !strings.Contains(msg, "arguments:") {
				t.Errorf("error is not a decode error: %s", msg)
			}
		})
	}
}

// TestOmittedArgumentsStillMeanNone pins the boundary of the change: strict
// decoding must not turn a legitimately argument-less call into an error.
func TestOmittedArgumentsStillMeanNone(t *testing.T) {
	for _, args := range []string{``, `,"arguments":{}`, `,"arguments":null`} {
		req := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"cache_status\"%s}}\n", args)
		text, isErr := toolText(t, drive(t, req)[0])
		if isErr {
			t.Errorf("cache_status with arguments %q was refused: %s", args, text)
		}
	}
}
