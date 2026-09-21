package mcp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/bootstrap"
	"github.com/nlink-jp/whois-lookup/internal/engine"
	"github.com/nlink-jp/whois-lookup/internal/query"
	"github.com/nlink-jp/whois-lookup/internal/rdap"
)

// usageMarkdown is the operating manual returned by the get_usage tool. Its
// coherence with the real tools/results is pinned by usage_test.go.
//
//go:embed usage.md
var usageMarkdown string

// Instructions is the initialize-time hint (surfaced via the MCP
// `instructions` field) that makes get_usage discoverable and steers clients
// away from common errors.
const Instructions = "whois-lookup returns the registration data (registrar, dates, nameservers, abuse contact) " +
	"of a domain, IP address, or AS number — RDAP-first with a port 43 WHOIS fallback, no credentials. " +
	"Call the lookup tool with a single query; the input type is auto-detected and results are cached locally. " +
	"Tool errors are structured JSON ({code, message}); code \"not_found\" means the object does not exist. " +
	"Call get_usage for the full tool reference and error-recovery table."

// obj builds a tool's input schema. Every schema goes through here so that
// org ADR-021 §10's `additionalProperties: false` is set once instead of being
// remembered per tool — the next tool added gets the closed schema for free.
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// decodeArgs decodes a tool's arguments strictly: an argument the tool does not
// declare is refused by name, and a malformed argument object is refused rather
// than read as an empty one. Every tool decodes through here.
//
// obj() above is only the declared half of org ADR-021 §4 — what a
// schema-checking client refuses before the call. This is the half that
// actually refuses, and it is needed because not every client checks the
// schema. The `_ = json.Unmarshal` this replaces discarded the decode error as
// well as the unknown field, so both defects were silent in the same way: a
// misspelt `refresh` served a cached record as a freshly fetched one — which
// matters here, because the default TTL is 24h and an expiry date is exactly
// what a caller re-fetches for — and `{"query": 1}` ran as if no target had
// been named.
func decodeArgs(raw json.RawMessage, into any) error {
	raw = bytes.TrimSpace(raw)
	// Omitted or null arguments mean the empty object, not an error: a tool
	// whose arguments are all optional is legitimately called with none.
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errors.New("arguments: " + err.Error())
	}
	return nil
}

// toolsList returns the advertised tool set with JSON Schema for each input.
func toolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name":        "get_usage",
				"description": "Return this server's operating manual (markdown): the tools, the result schema, and the error-recovery table. Call it once before first use.",
				"inputSchema": obj(map[string]any{}),
			},
			{
				"name":        "lookup",
				"description": "Look up the registration data of a domain, IP address, or AS number (registrar, created/updated/expires, nameservers, status, abuse contact). RDAP-first with port 43 WHOIS fallback for RDAP-less ccTLDs such as .jp; IDN input is converted to punycode automatically. Results are cached locally (default 24h).",
				"inputSchema": obj(map[string]any{
					"query":   map[string]any{"type": "string", "description": "IP address, domain name (IDN ok), or AS number (e.g. AS13335)."},
					"type":    map[string]any{"type": "string", "enum": []string{"ip", "domain", "asn"}, "description": "Override input-type auto-detection."},
					"raw":     map[string]any{"type": "boolean", "description": "Include the raw RDAP response (raw) or WHOIS text (raw_text)."},
					"refresh": map[string]any{"type": "boolean", "description": "Bypass the local cache and re-fetch."},
				}, "query"),
			},
			{
				"name":        "cache_status",
				"description": "Report the local cache state: query-entry count, TTL, and the IANA bootstrap files' freshness.",
				"inputSchema": obj(map[string]any{}),
			},
		},
	}
}

func (s *server) toolsCall(params json.RawMessage) (toolResult, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolResult{}, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	switch p.Name {
	case "get_usage":
		// No arguments — which still means "none", not "any".
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult("invalid_input", err.Error()), nil
		}
		return textResult(false, usageMarkdown), nil
	case "lookup":
		return s.toolLookup(p.Arguments), nil
	case "cache_status":
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult("invalid_input", err.Error()), nil
		}
		return s.toolCacheStatus(), nil
	default:
		return toolResult{}, &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}
	}
}

func (s *server) toolLookup(args json.RawMessage) toolResult {
	var a struct {
		Query   string `json:"query"`
		Type    string `json:"type"`
		Raw     bool   `json:"raw"`
		Refresh bool   `json:"refresh"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return errorResult("invalid_input", err.Error())
	}
	if a.Query == "" {
		return errorResult("invalid_input", "provide 'query' (an IP address, domain name, or AS number)")
	}
	res, err := s.e.Lookup(a.Query, engine.Options{
		TypeHint: query.Type(a.Type),
		Raw:      a.Raw,
		Refresh:  a.Refresh,
	})
	switch {
	case errors.Is(err, query.ErrInvalid):
		return errorResult("invalid_input", err.Error())
	case errors.Is(err, rdap.ErrNotFound):
		return errorResult("not_found", err.Error())
	case errors.Is(err, engine.ErrNoRDAP):
		return errorResult("no_rdap_service", err.Error())
	case err != nil:
		return errorResult("network_error", err.Error())
	}
	return jsonResult(res)
}

func (s *server) toolCacheStatus() toolResult {
	files := bootstrap.Status(filepath.Join(s.e.Cfg.CacheDir, "bootstrap"))
	bs := make([]map[string]any, 0, len(files))
	now := time.Now()
	for _, f := range files {
		bs = append(bs, map[string]any{
			"file":      f.Name,
			"fetched":   f.FetchedAt.UTC().Format(time.RFC3339),
			"age_hours": int(now.Sub(f.FetchedAt).Hours()),
		})
	}
	return jsonResult(map[string]any{
		"cache_dir":     s.e.Cfg.CacheDir,
		"query_entries": s.e.Cache.Count(),
		"ttl_hours":     int(s.e.Cfg.CacheTTL.Hours()),
		"bootstrap":     bs,
	})
}

// errorResult renders a structured tool error: {code, message}. Codes:
// invalid_input, not_found, no_rdap_service, network_error.
func errorResult(code, message string) toolResult {
	b, _ := json.Marshal(map[string]string{"code": code, "message": message})
	return textResult(true, string(b))
}

// jsonResult marshals v into a non-error text result.
func jsonResult(v any) toolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult("network_error", "encode result: "+err.Error())
	}
	return textResult(false, string(b))
}
