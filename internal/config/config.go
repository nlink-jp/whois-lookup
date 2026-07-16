package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBootstrapURL is the IANA RDAP bootstrap registry base; dns.json,
	// ipv4.json, ipv6.json, and asn.json live under it. Public, no
	// authentication.
	DefaultBootstrapURL = "https://data.iana.org/rdap/"
	// DefaultWhoisRoot is the root of the port 43 referral chain, used only
	// for TLDs without RDAP (Phase 2).
	DefaultWhoisRoot = "whois.iana.org:43"

	// DefaultCacheTTL is how long a per-query result stays fresh. WHOIS data
	// changes slowly and registries rate-limit hard, so the default is high.
	DefaultCacheTTL = 24 * time.Hour
	// DefaultBootstrapRevalidate is how often the cached bootstrap files are
	// revalidated (a cheap ETag conditional GET — the files change rarely).
	DefaultBootstrapRevalidate = 24 * time.Hour
	// DefaultTimeout bounds each RDAP / WHOIS network exchange.
	DefaultTimeout = 10 * time.Second
)

// Config holds resolved runtime settings. There are no credentials: every
// endpoint is public.
type Config struct {
	BootstrapURL        string        // IANA RDAP bootstrap base URL
	BootstrapRevalidate time.Duration // bootstrap ETag revalidation interval
	WhoisRoot           string        // port 43 referral-chain root (Phase 2)
	CacheDir            string        // query-result + bootstrap cache directory
	CacheTTL            time.Duration // per-query result freshness
	Timeout             time.Duration // network timeout per exchange
}

// Load resolves configuration. If configPath is empty the default location
// (~/.config/whois-lookup/config.toml) is used when present. Environment
// variables override file values; the timeoutOverride flag value (non-zero)
// wins over both.
func Load(configPath string, timeoutOverride time.Duration) (*Config, error) {
	cfg := &Config{
		BootstrapURL:        DefaultBootstrapURL,
		BootstrapRevalidate: DefaultBootstrapRevalidate,
		WhoisRoot:           DefaultWhoisRoot,
		CacheDir:            DefaultCacheDir(),
		CacheTTL:            DefaultCacheTTL,
		Timeout:             DefaultTimeout,
	}

	if configPath == "" {
		configPath = DefaultConfigPath()
	}
	if configPath != "" {
		if f, err := os.Open(configPath); err == nil {
			defer f.Close()
			sections, perr := parseTOML(f)
			if perr != nil {
				return nil, fmt.Errorf("parse config %s: %w", configPath, perr)
			}
			if aerr := applySections(cfg, sections); aerr != nil {
				return nil, fmt.Errorf("config %s: %w", configPath, aerr)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("open config %s: %w", configPath, err)
		}
	}

	// Environment overrides.
	if v := os.Getenv("WHOIS_LOOKUP_BOOTSTRAP_URL"); v != "" {
		cfg.BootstrapURL = v
	}
	if v := os.Getenv("WHOIS_LOOKUP_BOOTSTRAP_REVALIDATE_HOURS"); v != "" {
		d, err := parseHours(v)
		if err != nil {
			return nil, fmt.Errorf("WHOIS_LOOKUP_BOOTSTRAP_REVALIDATE_HOURS: %w", err)
		}
		cfg.BootstrapRevalidate = d
	}
	if v := os.Getenv("WHOIS_LOOKUP_WHOIS_ROOT"); v != "" {
		cfg.WhoisRoot = v
	}
	if v := os.Getenv("WHOIS_LOOKUP_CACHE_DIR"); v != "" {
		cfg.CacheDir = expandHome(v)
	}
	if v := os.Getenv("WHOIS_LOOKUP_CACHE_TTL_HOURS"); v != "" {
		d, err := parseHours(v)
		if err != nil {
			return nil, fmt.Errorf("WHOIS_LOOKUP_CACHE_TTL_HOURS: %w", err)
		}
		cfg.CacheTTL = d
	}
	if v := os.Getenv("WHOIS_LOOKUP_TIMEOUT_SECONDS"); v != "" {
		s, err := strconv.ParseFloat(v, 64)
		if err != nil || s <= 0 {
			return nil, fmt.Errorf("WHOIS_LOOKUP_TIMEOUT_SECONDS: %q is not a positive number", v)
		}
		cfg.Timeout = time.Duration(s * float64(time.Second))
	}

	// Explicit flag overrides win.
	if timeoutOverride > 0 {
		cfg.Timeout = timeoutOverride
	}

	if !strings.HasSuffix(cfg.BootstrapURL, "/") {
		cfg.BootstrapURL += "/"
	}
	return cfg, nil
}

func applySections(cfg *Config, sections map[string]map[string]string) error {
	if c := sections["cache"]; c != nil {
		if v := c["ttl_hours"]; v != "" {
			d, err := parseHours(v)
			if err != nil {
				return fmt.Errorf("[cache] ttl_hours: %w", err)
			}
			cfg.CacheTTL = d
		}
		if v := c["dir"]; v != "" {
			cfg.CacheDir = expandHome(v)
		}
	}
	if r := sections["rdap"]; r != nil {
		if v := r["bootstrap_url"]; v != "" {
			cfg.BootstrapURL = v
		}
		if v := r["revalidate_hours"]; v != "" {
			d, err := parseHours(v)
			if err != nil {
				return fmt.Errorf("[rdap] revalidate_hours: %w", err)
			}
			cfg.BootstrapRevalidate = d
		}
	}
	if w := sections["whois"]; w != nil {
		if v := w["root"]; v != "" {
			cfg.WhoisRoot = v
		}
	}
	if n := sections["network"]; n != nil {
		if v := n["timeout_seconds"]; v != "" {
			s, err := strconv.ParseFloat(v, 64)
			if err != nil || s <= 0 {
				return fmt.Errorf("[network] timeout_seconds: %q is not a positive number", v)
			}
			cfg.Timeout = time.Duration(s * float64(time.Second))
		}
	}
	return nil
}

// parseHours parses a non-negative hours value into a Duration.
func parseHours(v string) (time.Duration, error) {
	h, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", v)
	}
	if h < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	return time.Duration(h * float64(time.Hour)), nil
}

// DefaultConfigPath returns the default config file location, honoring
// XDG_CONFIG_HOME.
func DefaultConfigPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "whois-lookup", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "whois-lookup", "config.toml")
}

// DefaultCacheDir returns the default cache directory, honoring
// XDG_CACHE_HOME. Cached lookups and bootstrap files are re-fetchable
// transient state, so they belong under the cache home, not data.
func DefaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "whois-lookup")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "whois-lookup-cache"
	}
	return filepath.Join(home, ".cache", "whois-lookup")
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// parseTOML parses the minimal subset whois-lookup needs: [section] headers
// and key = value lines, where value is an optionally quoted string. Comments
// start with '#'. It intentionally does not support arrays, nested tables, or
// typed values.
func parseTOML(r io.Reader) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	current := "" // top-level keys land in the "" section
	sections[current] = map[string]string{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, "[") {
			end := strings.IndexByte(raw, ']')
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated section header", line)
			}
			current = strings.TrimSpace(raw[1:end])
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		key := strings.TrimSpace(raw[:eq])
		val := parseValue(strings.TrimSpace(raw[eq+1:]))
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		sections[current][key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sections, nil
}

// parseValue strips surrounding quotes, or trims a trailing inline comment
// from a bare value.
func parseValue(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if hash := strings.IndexByte(v, '#'); hash >= 0 {
		v = strings.TrimSpace(v[:hash])
	}
	return v
}
