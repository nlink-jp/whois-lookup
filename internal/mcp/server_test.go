package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/cache"
	"github.com/nlink-jp/whois-lookup/internal/config"
	"github.com/nlink-jp/whois-lookup/internal/engine"
	"github.com/nlink-jp/whois-lookup/internal/query"
	"github.com/nlink-jp/whois-lookup/internal/rdap"
)

type stubResolver struct{}

func (stubResolver) Resolve(query.Query, time.Time) ([]string, error) {
	return []string{"https://rdap.test/"}, nil
}

type stubRDAP struct{}

func (stubRDAP) Lookup(base string, q query.Query) (*rdap.Result, json.RawMessage, error) {
	if q.Value == "gone.example" {
		return nil, nil, fmt.Errorf("%w: gone", rdap.ErrNotFound)
	}
	return &rdap.Result{Query: q.Original, Type: string(q.Type), Source: "rdap", Registrar: "Stub Registrar"},
		json.RawMessage(`{}`), nil
}

func testEngine(t *testing.T) *engine.Engine {
	t.Helper()
	return &engine.Engine{
		Cfg:       &config.Config{CacheTTL: time.Hour, CacheDir: t.TempDir()},
		Cache:     &cache.Store{Dir: t.TempDir()},
		Bootstrap: stubResolver{},
		RDAP:      stubRDAP{},
		Now:       time.Now,
	}
}

// drive feeds newline-delimited JSON-RPC requests and returns the decoded
// responses.
func drive(t *testing.T, input string) []response {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(testEngine(t), "test", strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	var resps []response
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r response
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		resps = append(resps, r)
	}
	return resps
}

func toolText(t *testing.T, r response) (string, bool) {
	t.Helper()
	b, err := json.Marshal(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	var tr toolResult
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	if len(tr.Content) != 1 {
		t.Fatalf("content = %+v", tr.Content)
	}
	return tr.Content[0].Text, tr.IsError
}

func TestServeProtocolAndTools(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lookup","arguments":{"query":"example.com"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"lookup","arguments":{"query":"!!!"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"lookup","arguments":{"query":"gone.example"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"cache_status"}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_usage"}}
{"jsonrpc":"2.0","id":8,"method":"nope"}
`
	resps := drive(t, input)
	if len(resps) != 8 {
		t.Fatalf("responses = %d (notification must be skipped)", len(resps))
	}

	// initialize echoes the client's protocol version and carries instructions.
	init, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(init), "2025-03-26") || !strings.Contains(string(init), "whois-lookup") {
		t.Errorf("initialize = %s", init)
	}

	// tools/list advertises the three tools.
	list, _ := json.Marshal(resps[1].Result)
	for _, name := range []string{"lookup", "cache_status", "get_usage"} {
		if !strings.Contains(string(list), name) {
			t.Errorf("tools/list missing %q", name)
		}
	}

	// Successful lookup.
	text, isErr := toolText(t, resps[2])
	if isErr || !strings.Contains(text, "Stub Registrar") {
		t.Errorf("lookup = err:%v %s", isErr, text)
	}

	// Structured errors.
	for i, wantCode := range map[int]string{3: "invalid_input", 4: "not_found"} {
		text, isErr := toolText(t, resps[i])
		if !isErr {
			t.Errorf("resp %d should be a tool error", i)
		}
		var e struct{ Code, Message string }
		if err := json.Unmarshal([]byte(text), &e); err != nil || e.Code != wantCode {
			t.Errorf("resp %d = %q, want code %q", i, text, wantCode)
		}
	}

	// cache_status counts the cached lookup from above.
	text, isErr = toolText(t, resps[5])
	if isErr || !strings.Contains(text, `"query_entries": 1`) {
		t.Errorf("cache_status = err:%v %s", isErr, text)
	}

	// get_usage returns the manual.
	text, _ = toolText(t, resps[6])
	if !strings.Contains(text, "operating manual") {
		t.Errorf("get_usage = %s", text)
	}

	// Unknown method → JSON-RPC error, not a tool error.
	if resps[7].Error == nil || resps[7].Error.Code != -32601 {
		t.Errorf("unknown method = %+v", resps[7])
	}
}

func TestServeMalformedJSONStops(t *testing.T) {
	resps := drive(t, `{"jsonrpc":"2.0","id":1,"method":"ping"}
{not json`)
	if len(resps) != 2 || resps[1].Error == nil || resps[1].Error.Code != -32700 {
		t.Fatalf("resps = %+v", resps)
	}
}
