package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/bootstrap"
	"github.com/nlink-jp/whois-lookup/internal/cache"
	"github.com/nlink-jp/whois-lookup/internal/config"
	"github.com/nlink-jp/whois-lookup/internal/query"
	"github.com/nlink-jp/whois-lookup/internal/rdap"
)

type fakeResolver struct {
	bases []string
	err   error
	calls int
}

func (f *fakeResolver) Resolve(query.Query, time.Time) ([]string, error) {
	f.calls++
	return f.bases, f.err
}

type fakeRDAP struct {
	perBase map[string]error // base → error ("" entry means success)
	calls   []string
}

func (f *fakeRDAP) Lookup(base string, q query.Query) (*rdap.Result, json.RawMessage, error) {
	f.calls = append(f.calls, base)
	if err := f.perBase[base]; err != nil {
		return nil, nil, err
	}
	res := &rdap.Result{Query: q.Original, Type: string(q.Type), Source: "rdap", Handle: "H-" + base}
	return res, json.RawMessage(`{"objectClassName":"domain"}`), nil
}

func newEngine(t *testing.T, r Resolver, c RDAPClient) *Engine {
	t.Helper()
	return &Engine{
		Cfg:       &config.Config{CacheTTL: time.Hour},
		Cache:     &cache.Store{Dir: t.TempDir()},
		Bootstrap: r,
		RDAP:      c,
		Now:       func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
}

func TestLookupFallsThroughBasesAndCaches(t *testing.T) {
	res1 := &fakeResolver{bases: []string{"https://down.example/", "https://up.example/"}}
	rd := &fakeRDAP{perBase: map[string]error{"https://down.example/": fmt.Errorf("HTTP 503")}}
	e := newEngine(t, res1, rd)

	res, err := e.Lookup("example.com", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Handle != "H-https://up.example/" || res.Cached {
		t.Errorf("first lookup = %+v", res)
	}
	if len(rd.calls) != 2 {
		t.Errorf("rdap calls = %v (both bases expected)", rd.calls)
	}

	// Second lookup: cache hit, no resolver/rdap traffic.
	res, err = e.Lookup("example.com", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached {
		t.Error("second lookup should be served from cache")
	}
	if res.Raw != nil {
		t.Error("Raw must be stripped without opts.Raw")
	}
	if res1.calls != 1 || len(rd.calls) != 2 {
		t.Errorf("cache hit still hit the network: resolver=%d rdap=%v", res1.calls, rd.calls)
	}

	// --raw on a cache hit still returns the stored raw body.
	res, err = e.Lookup("example.com", Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached || len(res.Raw) == 0 {
		t.Errorf("raw cache hit = cached:%v raw:%d bytes", res.Cached, len(res.Raw))
	}

	// --refresh bypasses the cache.
	res, err = e.Lookup("example.com", Options{Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Cached || res1.calls != 2 {
		t.Errorf("refresh: cached=%v resolver calls=%d", res.Cached, res1.calls)
	}
}

func TestLookupInvalidInputNeverTouchesNetwork(t *testing.T) {
	res1 := &fakeResolver{bases: []string{"https://up.example/"}}
	rd := &fakeRDAP{}
	e := newEngine(t, res1, rd)

	for _, in := range []string{"", "bad domain.com", "example.com\r\nX", "日本語.jp"} {
		if _, err := e.Lookup(in, Options{}); !errors.Is(err, query.ErrInvalid) {
			t.Errorf("Lookup(%q) = %v, want ErrInvalid", in, err)
		}
	}
	if res1.calls != 0 || len(rd.calls) != 0 {
		t.Fatalf("invalid input reached the network: resolver=%d rdap=%v", res1.calls, rd.calls)
	}
}

func TestLookupNotFoundIsAuthoritativeAndUncached(t *testing.T) {
	res1 := &fakeResolver{bases: []string{"https://a.example/", "https://b.example/"}}
	rd := &fakeRDAP{perBase: map[string]error{
		"https://a.example/": fmt.Errorf("%w: gone", rdap.ErrNotFound),
	}}
	e := newEngine(t, res1, rd)

	if _, err := e.Lookup("gone.example", Options{}); !errors.Is(err, rdap.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if len(rd.calls) != 1 {
		t.Errorf("404 must not fall through to the next base: %v", rd.calls)
	}
	// Not-found is not cached: a second call queries again.
	if _, err := e.Lookup("gone.example", Options{}); !errors.Is(err, rdap.ErrNotFound) {
		t.Fatal(err)
	}
	if len(rd.calls) != 2 {
		t.Errorf("second not-found lookup should re-query, calls = %v", rd.calls)
	}
}

func TestLookupNoRDAPService(t *testing.T) {
	res1 := &fakeResolver{err: fmt.Errorf("%w for \"example.jp\"", bootstrap.ErrNoService)}
	e := newEngine(t, res1, &fakeRDAP{})

	_, err := e.Lookup("example.jp", Options{})
	if !errors.Is(err, ErrNoRDAP) {
		t.Fatalf("err = %v, want ErrNoRDAP", err)
	}
}

func TestLookupAllBasesFail(t *testing.T) {
	res1 := &fakeResolver{bases: []string{"https://a.example/", "https://b.example/"}}
	rd := &fakeRDAP{perBase: map[string]error{
		"https://a.example/": fmt.Errorf("HTTP 503"),
		"https://b.example/": fmt.Errorf("connection refused"),
	}}
	e := newEngine(t, res1, rd)
	if _, err := e.Lookup("example.com", Options{}); err == nil {
		t.Fatal("want error when every base fails")
	}
}
