package engine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nlink-jp/whois-lookup/internal/bootstrap"
	"github.com/nlink-jp/whois-lookup/internal/query"
	"github.com/nlink-jp/whois-lookup/internal/rdap"
	"github.com/nlink-jp/whois-lookup/internal/whois"
)

type fakeWhois struct {
	rec   *whois.Record
	err   error
	calls int
}

func (f *fakeWhois) Lookup(query.Query) (*whois.Record, error) {
	f.calls++
	return f.rec, f.err
}

func noService() *fakeResolver {
	return &fakeResolver{err: fmt.Errorf("%w for tld", bootstrap.ErrNoService)}
}

func TestWhoisFallbackForRDAPlessTLD(t *testing.T) {
	fw := &fakeWhois{rec: &whois.Record{
		Raw:         "[ドメイン情報]\n[登録年月日] 2001/05/30\n",
		Registrar:   "JPRS Registrar",
		Created:     "2001/05/30",
		Nameservers: []string{"ns1.example.jp"},
		Status:      []string{"Active"},
	}}
	e := newEngine(t, noService(), &fakeRDAP{})
	e.Whois = fw

	res, err := e.Lookup("日本語.jp", Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "whois" || res.Registrar != "JPRS Registrar" || res.Created != "2001/05/30" {
		t.Errorf("res = %+v", res)
	}
	if res.QueryASCII != "xn--wgv71a119e.jp" {
		t.Errorf("QueryASCII = %q", res.QueryASCII)
	}
	if res.RawText == "" || res.Raw != nil {
		t.Errorf("whois raw belongs in RawText: raw=%q raw_text=%q", res.Raw, res.RawText)
	}

	// Fallback results are cached like RDAP ones.
	res, err = e.Lookup("日本語.jp", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached || fw.calls != 1 {
		t.Errorf("cached=%v whois calls=%d", res.Cached, fw.calls)
	}
	if res.RawText != "" {
		t.Error("RawText must be stripped without opts.Raw")
	}
}

func TestWhoisFallbackNotFound(t *testing.T) {
	e := newEngine(t, noService(), &fakeRDAP{})
	e.Whois = &fakeWhois{err: fmt.Errorf("%w: x", whois.ErrNotFound)}
	if _, err := e.Lookup("nosuch.jp", Options{}); !errors.Is(err, rdap.ErrNotFound) {
		t.Fatalf("err = %v, want rdap.ErrNotFound mapping", err)
	}
}

func TestNoFallbackForIPAndWithoutClient(t *testing.T) {
	// IP with no RDAP service: no whois fallback (all RIRs have RDAP; this
	// signals breakage, not a fallback case).
	fw := &fakeWhois{rec: &whois.Record{Raw: "x"}}
	e := newEngine(t, noService(), &fakeRDAP{})
	e.Whois = fw
	if _, err := e.Lookup("192.0.2.1", Options{}); !errors.Is(err, ErrNoRDAP) {
		t.Fatalf("ip err = %v, want ErrNoRDAP", err)
	}
	if fw.calls != 0 {
		t.Error("whois must not be consulted for IP queries")
	}
	// Domain but no whois client wired: explicit error, no panic.
	e2 := newEngine(t, noService(), &fakeRDAP{})
	if _, err := e2.Lookup("example.jp", Options{}); !errors.Is(err, ErrNoRDAP) {
		t.Fatalf("nil whois err = %v, want ErrNoRDAP", err)
	}
}
