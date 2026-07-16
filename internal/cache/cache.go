package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// record is the on-disk envelope. Freshness lives in the record, not the
// file mtime, so it survives copies and backups.
type record struct {
	FetchedAtUnix int64           `json:"fetched_at_unix"`
	Result        json.RawMessage `json:"result"`
}

// Store is a per-query result cache rooted at a directory. The zero clock is
// supplied by callers (the engine is the only clock reader), keeping the
// store deterministic and testable.
type Store struct {
	Dir string
}

// Key builds the cache filename for a canonical query. Canonical forms keep
// the alias problem away (A-label domains, unmapped IPs), and the small
// character substitution keeps IPv6 colons out of filenames. The query
// package has already rejected control characters, whitespace, and path
// separators are impossible in validated input, so the key is safe as a
// filename.
func Key(qtype, canonical string) string {
	return qtype + "_" + strings.ReplaceAll(canonical, ":", "-") + ".json"
}

// Get returns the cached raw result for key when it is younger than ttl.
func (s *Store) Get(key string, now time.Time, ttl time.Duration) (json.RawMessage, bool) {
	b, err := os.ReadFile(filepath.Join(s.Dir, key))
	if err != nil {
		return nil, false
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, false // corrupt entries read as misses; Put overwrites them
	}
	if now.Sub(time.Unix(rec.FetchedAtUnix, 0)) > ttl {
		return nil, false
	}
	return rec.Result, true
}

// Put stores a raw result under key, stamped with now. The write is atomic
// (temp file + rename) so a crash never leaves a truncated entry.
func (s *Store) Put(key string, result json.RawMessage, now time.Time) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	b, err := json.Marshal(record{FetchedAtUnix: now.Unix(), Result: result})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, key), b)
}

// Clear removes every cached query entry (top-level *.json files only —
// bootstrap files live in a subdirectory and are kept). It returns the
// number of entries removed.
func (s *Store) Clear() (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// writeAtomic writes b to path via a temp file + rename in the same
// directory.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
