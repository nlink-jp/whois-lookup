package mcp

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
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

// Instructions is the hint a client receives when it opens the server (the
// MCP `instructions` field, in initialize or server/discover) that makes
// get_usage discoverable and steers clients away from common errors.
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
	// encoding/json matches names case-insensitively, so "IP" would reach ip.
	// The schema names every argument exactly; refuse any other spelling by
	// name, as an undeclared argument is.
	var names map[string]json.RawMessage
	if err := json.Unmarshal(raw, &names); err != nil {
		return errors.New("arguments: " + err.Error())
	}
	declared := argNames(into)
	for n := range names {
		if !declared(n) {
			return fmt.Errorf("arguments: json: unknown field %q", n)
		}
	}
	return nil
}

// argNames reports whether a name is an argument the decode target declares,
// spelt as declared. A field with an explicit json name accepts that name
// exactly; a field without one is matched as encoding/json matches it (any
// case), since no spelling is declared for it; an embedded struct's fields
// count as the target's own; "-" fields are not arguments. A target that is
// not a struct (a map, say) declares no names, so every name passes here and
// is left to the decoder.
func argNames(into any) func(string) bool {
	t := reflect.TypeOf(into)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return func(string) bool { return true }
	}
	exact := map[string]bool{}
	var loose []string
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" {
				ft := f.Type
				for ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if ft.Kind() == reflect.Struct {
					walk(ft)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			if name == "" {
				loose = append(loose, f.Name)
			} else {
				exact[name] = true
			}
		}
	}
	walk(t)
	return func(n string) bool {
		if exact[n] {
			return true
		}
		for _, l := range loose {
			if strings.EqualFold(l, n) {
				return true
			}
		}
		return false
	}
}

// toolsList returns the advertised tool set with JSON Schema for each input.
func toolsList() []map[string]any {
	return []map[string]any{
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
	}
}

// toolsCall dispatches one call by tool name and builds its result.
func (s *server) toolsCall(ctx context.Context, name string, args json.RawMessage) toolResult {
	switch name {
	case "get_usage":
		// No arguments — which still means "none", not "any".
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return errorResult("invalid_input", err.Error())
		}
		return textResult(false, usageMarkdown)
	case "lookup":
		return s.toolLookup(args)
	case "cache_status":
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return errorResult("invalid_input", err.Error())
		}
		return s.toolCacheStatus()
	default:
		// Not reached: the protocol layer refuses a tool it did not register.
		return textResult(true, "unknown tool: "+name)
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
