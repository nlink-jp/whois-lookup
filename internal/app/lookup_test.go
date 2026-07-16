package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newStack serves both the IANA bootstrap and an RDAP endpoint from one
// httptest server, exercising the full CLI path (flags → config → engine →
// bootstrap → rdap → output) without the network.
func newStack(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/dns.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"services":[[["com"],["%s/rdap/"]]]}`, srv.URL)
	})
	mux.HandleFunc("/rdap/domain/example.com", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
		  "objectClassName": "domain",
		  "ldhName": "EXAMPLE.COM",
		  "status": ["active"],
		  "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
		  "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
		  "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}]
		}`)
	})
	mux.HandleFunc("/rdap/domain/gone.com", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// A one-shot local WHOIS root so the .jp fallback path never leaves the
	// test (and never reaches the real whois.iana.org).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 256)
				conn.Read(buf)
				fmt.Fprint(conn, "[登録年月日] 2001/05/30\n[状態] Active\nregistrar: JP Registrar\n")
			}(conn)
		}
	}()

	t.Setenv("WHOIS_LOOKUP_BOOTSTRAP_URL", srv.URL+"/")
	t.Setenv("WHOIS_LOOKUP_WHOIS_ROOT", ln.Addr().String())
	t.Setenv("WHOIS_LOOKUP_CACHE_DIR", t.TempDir())
	return filepath.Join(t.TempDir(), "absent-config.toml") // keep the user's real config out
}

func TestLookupTextAndCache(t *testing.T) {
	cfg := newStack(t)
	var out, errb bytes.Buffer

	code := runLookup([]string{"example.com", "-c", cfg}, "test", &out, &errb)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	text := out.String()
	for _, want := range []string{"source:        rdap", "name:          example.com", "registrar:     Example Registrar", "created:       1995-08-14T04:00:00Z", "nameserver:    a.iana-servers.net"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "cached") {
		t.Error("first lookup must not be cached")
	}

	out.Reset()
	if code := runLookup([]string{"example.com", "-c", cfg}, "test", &out, &errb); code != exitOK {
		t.Fatalf("second lookup exit = %d", code)
	}
	if !strings.Contains(out.String(), "rdap (cached)") {
		t.Errorf("second lookup should be cached:\n%s", out.String())
	}
}

func TestLookupJSONAndRaw(t *testing.T) {
	cfg := newStack(t)
	var out, errb bytes.Buffer

	code := runLookup([]string{"--json", "--raw", "example.com", "-c", cfg}, "test", &out, &errb)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if got["query"] != "example.com" || got["source"] != "rdap" || got["registrar"] != "Example Registrar" {
		t.Errorf("json = %v", got)
	}
	if _, ok := got["raw"]; !ok {
		t.Error("--raw output missing raw field")
	}

	// Without --raw the field is absent.
	out.Reset()
	if code := runLookup([]string{"--json", "example.com", "-c", cfg}, "test", &out, &errb); code != exitOK {
		t.Fatal(errb.String())
	}
	got = map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["raw"]; ok {
		t.Error("raw field must be omitted without --raw")
	}
}

func TestLookupNotFoundExitCode(t *testing.T) {
	cfg := newStack(t)
	var out, errb bytes.Buffer
	if code := runLookup([]string{"gone.com", "-c", cfg}, "test", &out, &errb); code != exitNotFound {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitNotFound, errb.String())
	}
}

func TestLookupWhoisFallback(t *testing.T) {
	cfg := newStack(t)
	var out, errb bytes.Buffer
	// .jp is absent from the test bootstrap → port 43 fallback.
	if code := runLookup([]string{"example.jp", "-c", cfg}, "test", &out, &errb); code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	text := out.String()
	for _, want := range []string{"source:        whois", "registrar:     JP Registrar", "created:       2001/05/30", "status:        Active"} {
		if !strings.Contains(text, want) {
			t.Errorf("fallback output missing %q:\n%s", want, text)
		}
	}
}

func TestLookupWhoisFallbackIDN(t *testing.T) {
	cfg := newStack(t)
	var out, errb bytes.Buffer
	if code := runLookup([]string{"--json", "日本語.jp", "-c", cfg}, "test", &out, &errb); code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["query"] != "日本語.jp" || got["query_ascii"] != "xn--wgv71a119e.jp" || got["source"] != "whois" {
		t.Errorf("json = %v", got)
	}
}

func TestLookupTypeHint(t *testing.T) {
	cfg := newStack(t)
	var out, errb bytes.Buffer
	// "13335" auto-detects as ASN; --type domain forces domain validation,
	// which rejects the all-numeric TLD before any network I/O.
	if code := runLookup([]string{"--type", "domain", "13335", "-c", cfg}, "test", &out, &errb); code != exitError {
		t.Fatalf("exit = %d, want %d", code, exitError)
	}
}
