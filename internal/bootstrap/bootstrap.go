package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/cache"
	"github.com/nlink-jp/whois-lookup/internal/query"
)

// ErrNoService means the bootstrap registry lists no RDAP endpoint for the
// query — for domains this is the signal for the port 43 WHOIS fallback
// (Phase 2).
var ErrNoService = errors.New("no RDAP service in the IANA bootstrap registry")

// Doer executes HTTP requests. *http.Client satisfies it; tests inject
// fakes.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Resolver maps a validated query to its RDAP base URLs via the IANA
// bootstrap files, cached on disk with ETag conditional GET.
type Resolver struct {
	Client     Doer
	BaseURL    string        // e.g. https://data.iana.org/rdap/
	Dir        string        // on-disk cache directory for bootstrap files
	Revalidate time.Duration // how old a cached file may be before revalidation
	UserAgent  string
}

// registryFile is the RFC 7484 bootstrap format: each service is a pair of
// [keys, base URLs].
type registryFile struct {
	Services [][2][]string `json:"services"`
}

// meta sits next to each cached bootstrap file; freshness lives here, not in
// the file mtime.
type meta struct {
	ETag          string `json:"etag"`
	FetchedAtUnix int64  `json:"fetched_at_unix"`
}

// Resolve returns the RDAP base URLs for q, most specific match first.
func (r *Resolver) Resolve(q query.Query, now time.Time) ([]string, error) {
	var file string
	switch q.Type {
	case query.TypeDomain:
		file = "dns.json"
	case query.TypeASN:
		file = "asn.json"
	case query.TypeIP:
		if q.Addr.Is4() {
			file = "ipv4.json"
		} else {
			file = "ipv6.json"
		}
	default:
		return nil, fmt.Errorf("unsupported query type %q", q.Type)
	}
	reg, err := r.load(file, now)
	if err != nil {
		return nil, err
	}
	urls := match(reg, q)
	if len(urls) == 0 {
		return nil, fmt.Errorf("%w for %q", ErrNoService, q.Value)
	}
	return urls, nil
}

// load returns the parsed bootstrap file, fetching or revalidating it as
// needed. On a network failure with a usable cached copy it degrades to the
// stale copy rather than erroring.
func (r *Resolver) load(name string, now time.Time) (*registryFile, error) {
	path := filepath.Join(r.Dir, name)
	metaPath := path + ".meta"

	var m meta
	haveLocal := false
	if b, err := os.ReadFile(metaPath); err == nil && json.Unmarshal(b, &m) == nil {
		if _, err := os.Stat(path); err == nil {
			haveLocal = true
		}
	}

	fresh := haveLocal && now.Sub(time.Unix(m.FetchedAtUnix, 0)) <= r.Revalidate
	if !fresh {
		if err := r.fetch(name, path, metaPath, &m, now); err != nil {
			if !haveLocal {
				return nil, err
			}
			// Degrade to the stale cached copy — the files change rarely and
			// a lookup beats an error when IANA is briefly unreachable.
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap %s: %w", name, err)
	}
	var reg registryFile
	if err := json.Unmarshal(b, &reg); err != nil {
		return nil, fmt.Errorf("parse bootstrap %s: %w", name, err)
	}
	return &reg, nil
}

// fetch performs a (conditional) GET. 304 refreshes the meta stamp; 200
// rewrites file and meta atomically.
func (r *Resolver) fetch(name, path, metaPath string, m *meta, now time.Time) error {
	req, err := http.NewRequest(http.MethodGet, r.BaseURL+name, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", r.UserAgent)
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch bootstrap %s: %w", name, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		m.FetchedAtUnix = now.Unix()
		return writeMeta(metaPath, m)
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return fmt.Errorf("fetch bootstrap %s: %w", name, err)
		}
		if !json.Valid(body) {
			return fmt.Errorf("fetch bootstrap %s: response is not JSON", name)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := cache.WriteAtomic(path, body); err != nil {
			return err
		}
		m.ETag = resp.Header.Get("ETag")
		m.FetchedAtUnix = now.Unix()
		return writeMeta(metaPath, m)
	default:
		return fmt.Errorf("fetch bootstrap %s: HTTP %d", name, resp.StatusCode)
	}
}

func writeMeta(path string, m *meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return cache.WriteAtomic(path, b)
}

// match returns the base URLs of the most specific service entry covering q,
// normalized to a trailing slash.
func match(reg *registryFile, q query.Query) []string {
	var best []string
	bestSpec, found := 0, false
	for _, svc := range reg.Services {
		keys, urls := svc[0], svc[1]
		for _, key := range keys {
			spec, ok := keyMatches(key, q)
			if ok && (!found || spec > bestSpec) {
				bestSpec, found = spec, true
				best = urls
			}
		}
	}
	out := make([]string, 0, len(best))
	for _, u := range best {
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		out = append(out, u)
	}
	return out
}

// keyMatches reports whether a bootstrap service key covers q, and how
// specific the match is (higher wins: prefix bits for IP, negated range size
// for ASN, constant for TLD).
func keyMatches(key string, q query.Query) (int, bool) {
	switch q.Type {
	case query.TypeDomain:
		if strings.EqualFold(key, q.TLD()) {
			return 0, true
		}
	case query.TypeIP:
		p, err := netip.ParsePrefix(key)
		if err == nil && p.Contains(q.Addr) {
			return p.Bits(), true
		}
	case query.TypeASN:
		lo, hi, ok := parseASNRange(key)
		if ok && q.ASN >= lo && q.ASN <= hi {
			return -int(hi - lo), true
		}
	}
	return 0, false
}

// parseASNRange parses "64512" or "64512-65534".
func parseASNRange(key string) (lo, hi uint32, ok bool) {
	loS, hiS, found := strings.Cut(key, "-")
	if !found {
		hiS = loS
	}
	l, err1 := strconv.ParseUint(strings.TrimSpace(loS), 10, 32)
	h, err2 := strconv.ParseUint(strings.TrimSpace(hiS), 10, 32)
	if err1 != nil || err2 != nil || l > h {
		return 0, 0, false
	}
	return uint32(l), uint32(h), true
}
