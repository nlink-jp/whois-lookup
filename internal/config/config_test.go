package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clearEnv unsets every WHOIS_LOOKUP_* variable for the test's duration so
// developer machines don't leak overrides into assertions.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "WHOIS_LOOKUP_") {
			t.Setenv(strings.SplitN(kv, "=", 2)[0], "")
		}
	}
	// t.Setenv("", ...) can't unset; set to empty which Load treats as absent.
	for _, n := range []string{
		"WHOIS_LOOKUP_BOOTSTRAP_URL", "WHOIS_LOOKUP_BOOTSTRAP_REVALIDATE_HOURS",
		"WHOIS_LOOKUP_WHOIS_ROOT", "WHOIS_LOOKUP_CACHE_DIR",
		"WHOIS_LOOKUP_CACHE_TTL_HOURS", "WHOIS_LOOKUP_TIMEOUT_SECONDS",
	} {
		t.Setenv(n, "")
	}
}

func TestDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BootstrapURL != DefaultBootstrapURL {
		t.Errorf("BootstrapURL = %q", cfg.BootstrapURL)
	}
	if cfg.CacheTTL != DefaultCacheTTL || cfg.BootstrapRevalidate != DefaultBootstrapRevalidate {
		t.Errorf("TTLs = %v %v", cfg.CacheTTL, cfg.BootstrapRevalidate)
	}
	if cfg.Timeout != DefaultTimeout || cfg.WhoisRoot != DefaultWhoisRoot {
		t.Errorf("Timeout/WhoisRoot = %v %q", cfg.Timeout, cfg.WhoisRoot)
	}
	if cfg.CacheDir == "" {
		t.Error("CacheDir is empty")
	}
}

func TestFileAndOverrides(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	toml := `
# comment
[cache]
ttl_hours = 48        # inline comment
dir = "` + dir + `/c"

[rdap]
bootstrap_url = "https://mirror.example/rdap"  # no trailing slash on purpose
revalidate_hours = 1

[whois]
root = "whois.example:43"

[network]
timeout_seconds = 2.5
`
	if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CacheTTL != 48*time.Hour {
		t.Errorf("CacheTTL = %v", cfg.CacheTTL)
	}
	if cfg.CacheDir != dir+"/c" {
		t.Errorf("CacheDir = %q", cfg.CacheDir)
	}
	if cfg.BootstrapURL != "https://mirror.example/rdap/" {
		t.Errorf("BootstrapURL = %q (trailing slash should be normalized)", cfg.BootstrapURL)
	}
	if cfg.BootstrapRevalidate != time.Hour {
		t.Errorf("BootstrapRevalidate = %v", cfg.BootstrapRevalidate)
	}
	if cfg.WhoisRoot != "whois.example:43" {
		t.Errorf("WhoisRoot = %q", cfg.WhoisRoot)
	}
	if cfg.Timeout != 2500*time.Millisecond {
		t.Errorf("Timeout = %v", cfg.Timeout)
	}

	// Env beats file.
	t.Setenv("WHOIS_LOOKUP_CACHE_TTL_HOURS", "6")
	t.Setenv("WHOIS_LOOKUP_BOOTSTRAP_URL", "https://env.example/rdap/")
	cfg, err = Load(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CacheTTL != 6*time.Hour || cfg.BootstrapURL != "https://env.example/rdap/" {
		t.Errorf("env override failed: %v %q", cfg.CacheTTL, cfg.BootstrapURL)
	}

	// Flag beats env and file.
	cfg, err = Load(path, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 7*time.Second {
		t.Errorf("flag override failed: %v", cfg.Timeout)
	}
}

func TestBadValues(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	for name, toml := range map[string]string{
		"bad ttl":     "[cache]\nttl_hours = banana\n",
		"neg ttl":     "[cache]\nttl_hours = -1\n",
		"bad timeout": "[network]\ntimeout_seconds = 0\n",
		"no equals":   "[cache]\nttl_hours\n",
		"bad header":  "[cache\nttl_hours = 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".toml")
			if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, 0); err == nil {
				t.Errorf("Load accepted %s", name)
			}
		})
	}
	t.Setenv("WHOIS_LOOKUP_TIMEOUT_SECONDS", "-3")
	if _, err := Load(filepath.Join(dir, "absent.toml"), 0); err == nil {
		t.Error("Load accepted negative env timeout")
	}
}
