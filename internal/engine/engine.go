package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/bootstrap"
	"github.com/nlink-jp/whois-lookup/internal/cache"
	"github.com/nlink-jp/whois-lookup/internal/config"
	"github.com/nlink-jp/whois-lookup/internal/query"
	"github.com/nlink-jp/whois-lookup/internal/rdap"
)

// ErrNoRDAP means the query's registry provides no RDAP service. For domains
// this is where the port 43 WHOIS fallback takes over in Phase 2; until
// then it surfaces as an actionable error.
var ErrNoRDAP = errors.New("registry has no RDAP service")

// Resolver maps a query to RDAP base URLs (the bootstrap package; faked in
// tests).
type Resolver interface {
	Resolve(q query.Query, now time.Time) ([]string, error)
}

// RDAPClient queries one RDAP base URL (the rdap package; faked in tests).
type RDAPClient interface {
	Lookup(base string, q query.Query) (*rdap.Result, json.RawMessage, error)
}

// Options modify a single lookup.
type Options struct {
	TypeHint query.Type // "" auto-detects
	Refresh  bool       // bypass the query cache
	Raw      bool       // include the raw RDAP response in the result
}

// Engine ties validation, cache, bootstrap, and RDAP together. It is shared
// by the CLI and (Phase 2) the MCP server so their behaviour cannot diverge,
// and it is the only clock reader.
type Engine struct {
	Cfg       *config.Config
	Cache     *cache.Store
	Bootstrap Resolver
	RDAP      RDAPClient
	Now       func() time.Time
}

// New wires a production engine from resolved configuration.
func New(cfg *config.Config, version string) *Engine {
	httpClient := &http.Client{Timeout: cfg.Timeout}
	ua := "whois-lookup/" + version + " (+https://github.com/nlink-jp/whois-lookup)"
	return &Engine{
		Cfg:   cfg,
		Cache: &cache.Store{Dir: cfg.CacheDir},
		Bootstrap: &bootstrap.Resolver{
			Client:     httpClient,
			BaseURL:    cfg.BootstrapURL,
			Dir:        filepath.Join(cfg.CacheDir, "bootstrap"),
			Revalidate: cfg.BootstrapRevalidate,
			UserAgent:  ua,
		},
		RDAP: &rdap.Client{Client: httpClient, UserAgent: ua},
		Now:  time.Now,
	}
}

// Lookup validates input, consults the cache, resolves the RDAP endpoint,
// queries it, and returns the normalized result. Invalid input never reaches
// the network (query.ErrInvalid); a nonexistent object returns
// rdap.ErrNotFound.
func (e *Engine) Lookup(input string, opts Options) (*rdap.Result, error) {
	q, err := query.Classify(input, opts.TypeHint)
	if err != nil {
		return nil, err
	}
	key := cache.Key(string(q.Type), q.Value)
	now := e.Now()

	if !opts.Refresh {
		if raw, ok := e.Cache.Get(key, now, e.Cfg.CacheTTL); ok {
			var res rdap.Result
			if json.Unmarshal(raw, &res) == nil {
				res.Cached = true
				if !opts.Raw {
					res.Raw = nil
				}
				return &res, nil
			}
			// A corrupt entry reads as a miss; the fresh result overwrites it.
		}
	}

	bases, err := e.Bootstrap.Resolve(q, now)
	if err != nil {
		if errors.Is(err, bootstrap.ErrNoService) {
			return nil, fmt.Errorf("%w for %q — the port 43 WHOIS fallback arrives in Phase 2", ErrNoRDAP, q.Value)
		}
		return nil, err
	}

	var res *rdap.Result
	var raw json.RawMessage
	for _, base := range bases {
		res, raw, err = e.RDAP.Lookup(base, q)
		if err == nil {
			break
		}
		if errors.Is(err, rdap.ErrNotFound) {
			return nil, err // authoritative: don't retry other bases
		}
	}
	if err != nil {
		return nil, err
	}

	res.Raw = raw
	if b, merr := json.Marshal(res); merr == nil {
		// Best-effort: a cache-write failure must not fail a successful lookup.
		_ = e.Cache.Put(key, b, now)
	}
	if !opts.Raw {
		res.Raw = nil
	}
	return res, nil
}
