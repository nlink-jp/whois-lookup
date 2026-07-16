package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestCacheStatusAndClear(t *testing.T) {
	cfg := newStack(t)
	var out, errb bytes.Buffer

	// Empty cache.
	if code := runCache([]string{"status", "-c", cfg}, &out, &errb); code != exitOK {
		t.Fatalf("status exit = %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "query entries:  0") || !strings.Contains(out.String(), "not fetched yet") {
		t.Errorf("empty status:\n%s", out.String())
	}

	// One lookup populates a query entry and the bootstrap files.
	out.Reset()
	if code := runLookup([]string{"example.com", "-c", cfg}, "test", &out, &errb); code != exitOK {
		t.Fatal(errb.String())
	}
	out.Reset()
	if code := runCache([]string{"status", "-c", cfg}, &out, &errb); code != exitOK {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), "query entries:  1") || !strings.Contains(out.String(), "dns.json") {
		t.Errorf("populated status:\n%s", out.String())
	}

	// Clear removes the entry but keeps bootstrap files.
	out.Reset()
	if code := runCache([]string{"clear", "-c", cfg}, &out, &errb); code != exitOK {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), "cleared 1 cached query") {
		t.Errorf("clear output: %s", out.String())
	}
	out.Reset()
	if code := runCache([]string{"status", "-c", cfg}, &out, &errb); code != exitOK {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), "query entries:  0") || !strings.Contains(out.String(), "dns.json") {
		t.Errorf("post-clear status (bootstrap must survive):\n%s", out.String())
	}
}

func TestCacheUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runCache([]string{}, &out, &errb); code != exitError {
		t.Errorf("no subcommand: exit = %d", code)
	}
	if code := runCache([]string{"bogus"}, &out, &errb); code != exitError {
		t.Errorf("bad subcommand: exit = %d", code)
	}
}
