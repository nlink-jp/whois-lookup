package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKey(t *testing.T) {
	tests := []struct {
		qtype, canonical, want string
	}{
		{"domain", "example.com", "domain_example.com.json"},
		{"ip", "8.8.8.8", "ip_8.8.8.8.json"},
		{"ip", "2001:db8::1", "ip_2001-db8--1.json"}, // colons never reach the filesystem
		{"asn", "AS13335", "asn_AS13335.json"},
	}
	for _, tt := range tests {
		if got := Key(tt.qtype, tt.canonical); got != tt.want {
			t.Errorf("Key(%q, %q) = %q, want %q", tt.qtype, tt.canonical, got, tt.want)
		}
	}
}

func TestPutGetTTL(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_800_000_000, 0)
	key := Key("domain", "example.com")
	payload := json.RawMessage(`{"query":"example.com"}`)

	if _, ok := s.Get(key, now, time.Hour); ok {
		t.Fatal("Get on empty store should miss")
	}
	if err := s.Put(key, payload, now); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(key, now.Add(30*time.Minute), time.Hour)
	if !ok || string(got) != string(payload) {
		t.Fatalf("Get fresh = %q, %v", got, ok)
	}
	if _, ok := s.Get(key, now.Add(2*time.Hour), time.Hour); ok {
		t.Error("Get past TTL should miss")
	}
}

func TestCorruptEntryIsMiss(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	key := Key("domain", "example.com")
	if err := os.WriteFile(filepath.Join(s.Dir, key), []byte("{truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(key, time.Unix(0, 0), time.Hour); ok {
		t.Error("corrupt entry should read as a miss")
	}
}

func TestClear(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_800_000_000, 0)
	for _, k := range []string{Key("domain", "a.com"), Key("ip", "1.1.1.1")} {
		if err := s.Put(k, json.RawMessage(`{}`), now); err != nil {
			t.Fatal(err)
		}
	}
	// Bootstrap files live in a subdirectory and survive Clear.
	if err := os.MkdirAll(filepath.Join(s.Dir, "bootstrap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "bootstrap", "dns.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := s.Clear()
	if err != nil || n != 2 {
		t.Fatalf("Clear = %d, %v; want 2, nil", n, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "bootstrap", "dns.json")); err != nil {
		t.Error("Clear must not touch the bootstrap subdirectory")
	}
	// Clearing a nonexistent dir is a no-op.
	s2 := &Store{Dir: filepath.Join(t.TempDir(), "absent")}
	if n, err := s2.Clear(); err != nil || n != 0 {
		t.Errorf("Clear absent dir = %d, %v", n, err)
	}
}
