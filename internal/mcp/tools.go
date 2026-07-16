package mcp

import (
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

// toolsList returns the advertised tool set with JSON Schema for each input.
func toolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name":        "get_usage",
				"description": "Return this server's operating manual (markdown): the tools, the result schema, and the error-recovery table. Call it once before first use.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			},
			{
				"name":        "lookup",
				"description": "Look up the registration data of a domain, IP address, or AS number (registrar, created/updated/expires, nameservers, status, abuse contact). RDAP-first with port 43 WHOIS fallback for RDAP-less ccTLDs such as .jp; IDN input is converted to punycode automatically. Results are cached locally (default 24h).",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"query"},
					"properties": map[string]any{
						"query":   map[string]any{"type": "string", "description": "IP address, domain name (IDN ok), or AS number (e.g. AS13335)."},
						"type":    map[string]any{"type": "string", "enum": []string{"ip", "domain", "asn"}, "description": "Override input-type auto-detection."},
						"raw":     map[string]any{"type": "boolean", "description": "Include the raw RDAP response (raw) or WHOIS text (raw_text)."},
						"refresh": map[string]any{"type": "boolean", "description": "Bypass the local cache and re-fetch."},
					},
				},
			},
			{
				"name":        "cache_status",
				"description": "Report the local cache state: query-entry count, TTL, and the IANA bootstrap files' freshness.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
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
		return textResult(false, usageMarkdown), nil
	case "lookup":
		return s.toolLookup(p.Arguments), nil
	case "cache_status":
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
	_ = json.Unmarshal(args, &a)
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
