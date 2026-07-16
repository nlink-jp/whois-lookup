package rdap

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nlink-jp/whois-lookup/internal/query"
)

// domainJSON is a gTLD-style response: registrar entity with a nested abuse
// contact, events, nameservers, status.
const domainJSON = `{
  "objectClassName": "domain",
  "handle": "2336799_DOMAIN_COM-VRSN",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited", "client transfer prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:44Z"}
  ],
  "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
  "entities": [
    {
      "handle": "376",
      "roles": ["registrar"],
      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
      "entities": [
        {
          "roles": ["abuse"],
          "vcardArray": ["vcard", [["fn", {}, "text", "IANA Abuse"], ["email", {}, "text", "abuse@iana.example"]]]
        }
      ]
    }
  ]
}`

// ipJSON is an RIR-style network response: name/country/range, abuse at the
// top level, and an array-valued vCard field (dialect tolerance).
const ipJSON = `{
  "objectClassName": "ip network",
  "handle": "NET-8-8-8-0-2",
  "name": "GOGL",
  "country": "US",
  "startAddress": "8.8.8.0",
  "endAddress": "8.8.8.255",
  "status": ["active"],
  "events": [{"eventAction": "registration", "eventDate": "2023-12-28T17:24:56Z"}],
  "entities": [
    {
      "handle": "ABUSE5250-ARIN",
      "roles": ["abuse"],
      "vcardArray": ["vcard", [["fn", {}, "text", ["Abuse", "Desk"]], ["email", {}, "text", "network-abuse@google.example"]]]
    }
  ]
}`

const autnumJSON = `{
  "objectClassName": "autnum",
  "handle": "AS13335",
  "name": "CLOUDFLARENET",
  "startAutnum": 13335,
  "endAutnum": 13335,
  "status": ["active"]
}`

func mustQuery(t *testing.T, in string) query.Query {
	t.Helper()
	q, err := query.Classify(in, "")
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Client{Client: http.DefaultClient, UserAgent: "whois-lookup-test"}, srv.URL + "/"
}

func TestLookupDomain(t *testing.T) {
	var gotPath, gotAccept string
	c, base := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAccept = r.URL.Path, r.Header.Get("Accept")
		fmt.Fprint(w, domainJSON)
	})
	res, raw, err := c.Lookup(base, mustQuery(t, "Example.COM"))
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/domain/example.com" {
		t.Errorf("path = %q (canonical lowercase expected)", gotPath)
	}
	if gotAccept != "application/rdap+json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if len(raw) == 0 {
		t.Error("raw body missing")
	}
	if res.Source != "rdap" || res.Type != "domain" || res.Query != "Example.COM" {
		t.Errorf("envelope = %+v", res)
	}
	if res.Name != "example.com" || res.Handle != "2336799_DOMAIN_COM-VRSN" {
		t.Errorf("name/handle = %q %q", res.Name, res.Handle)
	}
	if res.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Errorf("registrar = %q", res.Registrar)
	}
	if res.Created != "1995-08-14T04:00:00Z" || res.Updated != "2025-08-14T07:01:44Z" || res.Expires != "2026-08-13T04:00:00Z" {
		t.Errorf("dates = %q %q %q", res.Created, res.Updated, res.Expires)
	}
	if len(res.Nameservers) != 2 || res.Nameservers[0] != "a.iana-servers.net" {
		t.Errorf("nameservers = %v", res.Nameservers)
	}
	if res.AbuseContact == nil || res.AbuseContact.Email != "abuse@iana.example" || res.AbuseContact.Name != "IANA Abuse" {
		t.Errorf("abuse (nested under registrar) = %+v", res.AbuseContact)
	}
	if len(res.Status) != 2 {
		t.Errorf("status = %v", res.Status)
	}
}

func TestLookupIP(t *testing.T) {
	c, base := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ip/8.8.8.8" {
			t.Errorf("path = %q", r.URL.Path)
		}
		fmt.Fprint(w, ipJSON)
	})
	res, _, err := c.Lookup(base, mustQuery(t, "8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "GOGL" || res.Country != "US" || res.Range != "8.8.8.0 - 8.8.8.255" {
		t.Errorf("net fields = %q %q %q", res.Name, res.Country, res.Range)
	}
	if res.AbuseContact == nil || res.AbuseContact.Name != "Abuse Desk" {
		t.Errorf("abuse with array-valued fn = %+v", res.AbuseContact)
	}
	if res.Registrar != "" {
		t.Errorf("ip result should have no registrar, got %q", res.Registrar)
	}
}

func TestLookupAutnum(t *testing.T) {
	c, base := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/autnum/13335" {
			t.Errorf("path = %q (bare number expected)", r.URL.Path)
		}
		fmt.Fprint(w, autnumJSON)
	})
	res, _, err := c.Lookup(base, mustQuery(t, "as13335"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "CLOUDFLARENET" || res.Range != "AS13335 - AS13335" {
		t.Errorf("autnum fields = %q %q", res.Name, res.Range)
	}
}

func TestLookupNotFoundAndErrors(t *testing.T) {
	c, base := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "missing"):
			w.WriteHeader(http.StatusNotFound)
		case strings.Contains(r.URL.Path, "flaky"):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			fmt.Fprint(w, "not json at all")
		}
	})
	if _, _, err := c.Lookup(base, mustQuery(t, "missing.example")); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: err = %v, want ErrNotFound", err)
	}
	if _, _, err := c.Lookup(base, mustQuery(t, "flaky.example")); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("503: err = %v, want non-NotFound error", err)
	}
	if _, _, err := c.Lookup(base, mustQuery(t, "garbled.example")); err == nil {
		t.Error("non-JSON body should error")
	}
}

// TestNormalizeMinimal: a bare-bones response (some ccTLD RDAP servers) must
// not panic or invent fields.
func TestNormalizeMinimal(t *testing.T) {
	res, err := normalize([]byte(`{"objectClassName":"domain","ldhName":"MINIMAL.DEV"}`), mustQuery(t, "minimal.dev"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "minimal.dev" || res.Registrar != "" || res.AbuseContact != nil || res.Created != "" {
		t.Errorf("minimal = %+v", res)
	}
	if res.QueryASCII != "" {
		t.Errorf("QueryASCII should be empty when input is already canonical, got %q", res.QueryASCII)
	}
}
