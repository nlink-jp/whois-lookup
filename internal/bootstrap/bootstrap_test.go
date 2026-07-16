package bootstrap

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/query"
)

const dnsJSON = `{
  "version": "1.0",
  "services": [
    [["com", "net"], ["https://rdap.example.com/com/v1"]],
    [["dev"], ["https://rdap.example.dev/"]]
  ]
}`

const ipv4JSON = `{
  "services": [
    [["8.0.0.0/8"], ["https://rdap.arin.example/registry"]],
    [["8.8.0.0/16"], ["https://rdap.more-specific.example/"]]
  ]
}`

const asnJSON = `{
  "services": [
    [["13335"], ["https://rdap.exact.example/"]],
    [["1-100000"], ["https://rdap.range.example/"]]
  ]
}`

// newServer serves bootstrap files with an ETag and counts requests.
func newServer(t *testing.T, etag string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	files := map[string]string{"/dns.json": dnsJSON, "/ipv4.json": ipv4JSON, "/asn.json": asnJSON}
	for p, body := range files {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			fmt.Fprint(w, body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newResolver(t *testing.T, srvURL string) *Resolver {
	t.Helper()
	return &Resolver{
		Client:     http.DefaultClient,
		BaseURL:    srvURL + "/",
		Dir:        t.TempDir(),
		Revalidate: 24 * time.Hour,
		UserAgent:  "whois-lookup-test",
	}
}

func mustQuery(t *testing.T, in string) query.Query {
	t.Helper()
	q, err := query.Classify(in, "")
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestResolveDomainAndFreshness(t *testing.T) {
	var hits atomic.Int64
	srv := newServer(t, `"v1"`, &hits)
	r := newResolver(t, srv.URL)
	now := time.Unix(1_800_000_000, 0)

	urls, err := r.Resolve(mustQuery(t, "example.com"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || urls[0] != "https://rdap.example.com/com/v1/" {
		t.Fatalf("urls = %v (trailing slash expected)", urls)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}

	// Within the revalidation window: served from disk, no request.
	if _, err := r.Resolve(mustQuery(t, "example.net"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d after fresh reuse, want 1", hits.Load())
	}

	// Past the window: conditional GET → 304 → stamp refreshed, no re-download.
	if _, err := r.Resolve(mustQuery(t, "example.dev"), now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Errorf("hits = %d after revalidation, want 2", hits.Load())
	}
	// And the stamp refresh means the next call is fresh again.
	if _, err := r.Resolve(mustQuery(t, "example.com"), now.Add(49*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Errorf("hits = %d after 304 stamp refresh, want 2", hits.Load())
	}
}

func TestResolveNoService(t *testing.T) {
	var hits atomic.Int64
	srv := newServer(t, `"v1"`, &hits)
	r := newResolver(t, srv.URL)
	_, err := r.Resolve(mustQuery(t, "example.jp"), time.Unix(1_800_000_000, 0))
	if !errors.Is(err, ErrNoService) {
		t.Fatalf("err = %v, want ErrNoService", err)
	}
}

func TestResolveIPLongestPrefix(t *testing.T) {
	var hits atomic.Int64
	srv := newServer(t, `"v1"`, &hits)
	r := newResolver(t, srv.URL)
	now := time.Unix(1_800_000_000, 0)

	urls, err := r.Resolve(mustQuery(t, "8.8.8.8"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || urls[0] != "https://rdap.more-specific.example/" {
		t.Errorf("urls = %v, want the /16 service", urls)
	}
	urls, err = r.Resolve(mustQuery(t, "8.1.2.3"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || urls[0] != "https://rdap.arin.example/registry/" {
		t.Errorf("urls = %v, want the /8 service", urls)
	}
}

func TestResolveASNRange(t *testing.T) {
	var hits atomic.Int64
	srv := newServer(t, `"v1"`, &hits)
	r := newResolver(t, srv.URL)
	now := time.Unix(1_800_000_000, 0)

	urls, err := r.Resolve(mustQuery(t, "AS13335"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || urls[0] != "https://rdap.exact.example/" {
		t.Errorf("urls = %v, want the exact-match service over the wide range", urls)
	}
	urls, err = r.Resolve(mustQuery(t, "AS99999"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || urls[0] != "https://rdap.range.example/" {
		t.Errorf("urls = %v, want the range service", urls)
	}
}

func TestDegradeToStaleOnNetworkFailure(t *testing.T) {
	var hits atomic.Int64
	srv := newServer(t, `"v1"`, &hits)
	r := newResolver(t, srv.URL)
	now := time.Unix(1_800_000_000, 0)

	if _, err := r.Resolve(mustQuery(t, "example.com"), now); err != nil {
		t.Fatal(err)
	}
	srv.Close() // IANA goes away

	// Stale + unreachable → degrade to the cached copy.
	urls, err := r.Resolve(mustQuery(t, "example.net"), now.Add(72*time.Hour))
	if err != nil {
		t.Fatalf("expected stale degrade, got %v", err)
	}
	if len(urls) != 1 {
		t.Errorf("urls = %v", urls)
	}

	// No cached copy at all → hard error.
	r2 := newResolver(t, srv.URL)
	if _, err := r2.Resolve(mustQuery(t, "example.com"), now); err == nil {
		t.Error("expected error with no cache and no network")
	}
}
