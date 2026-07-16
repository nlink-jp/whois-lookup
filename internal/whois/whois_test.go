package whois

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/query"
)

// serve starts a one-shot WHOIS server that records the received query and
// responds with respond(query).
func serve(t *testing.T, respond func(q string) string) string {
	t.Helper()
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
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				q := strings.TrimRight(string(buf[:n]), "\r\n")
				io.WriteString(conn, respond(q))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func newClient(root string) *Client {
	d := &net.Dialer{Timeout: 2 * time.Second}
	return &Client{
		Dial:    func(addr string) (net.Conn, error) { return d.Dial("tcp", addr) },
		Root:    root,
		Timeout: 2 * time.Second,
	}
}

func mustQuery(t *testing.T, in string) query.Query {
	t.Helper()
	q, err := query.Classify(in, "")
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestLookupFollowsReferralAndExtractsJPRS(t *testing.T) {
	var registryGot string
	registry := serve(t, func(q string) string {
		registryGot = q
		return `[ドメイン情報]
[ドメイン名]                EXAMPLE.JP
[登録年月日]                2001/05/30
[有効期限]                  2027/05/31
[状態]                      Active
[最終更新]                  2026/06/01 01:05:09 (JST)
[Name Server]               ns1.example.jp
[Name Server]               ns2.example.jp
[Name Server]               ns1.example.jp
`
	})
	var ianaGot string
	iana := serve(t, func(q string) string {
		ianaGot = q
		return "% IANA WHOIS server\nrefer:        " + registry + "\n\ndomain:       JP\n"
	})

	rec, err := newClient(iana).Lookup(mustQuery(t, "example.jp"))
	if err != nil {
		t.Fatal(err)
	}
	if ianaGot != "example.jp" || registryGot != "example.jp" {
		t.Errorf("queries sent = %q, %q", ianaGot, registryGot)
	}
	if len(rec.Servers) != 2 {
		t.Errorf("servers = %v", rec.Servers)
	}
	if rec.Created != "2001/05/30" || rec.Expires != "2027/05/31" || rec.Updated != "2026/06/01 01:05:09 (JST)" {
		t.Errorf("dates = %q %q %q", rec.Created, rec.Expires, rec.Updated)
	}
	if len(rec.Nameservers) != 2 || rec.Nameservers[0] != "ns1.example.jp" {
		t.Errorf("nameservers (deduped) = %v", rec.Nameservers)
	}
	if len(rec.Status) != 1 || rec.Status[0] != "Active" {
		t.Errorf("status = %v", rec.Status)
	}
	if !strings.Contains(rec.Raw, "[ドメイン情報]") {
		t.Error("Raw should be the final (registry) response")
	}
}

func TestLookupThinRegistryChain(t *testing.T) {
	registrar := serve(t, func(q string) string {
		return "Registrar: Example Registrar, Inc.\nCreation Date: 1995-08-14T04:00:00Z\nRegistry Expiry Date: 2026-08-13T04:00:00Z\nName Server: A.IANA-SERVERS.NET\nDomain Status: clientDeleteProhibited\n"
	})
	registry := serve(t, func(q string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: " + registrar + "\nRegistrar: Thin Answer Co\n"
	})
	iana := serve(t, func(q string) string {
		return "refer: " + registry + "\n"
	})

	rec, err := newClient(iana).Lookup(mustQuery(t, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Servers) != 3 {
		t.Errorf("servers = %v (iana → registry → registrar expected)", rec.Servers)
	}
	if rec.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q (final hop wins)", rec.Registrar)
	}
	if rec.Created != "1995-08-14T04:00:00Z" || len(rec.Nameservers) != 1 {
		t.Errorf("fields = %+v", rec)
	}
}

func TestLookupNoMatch(t *testing.T) {
	registry := serve(t, func(q string) string { return "No match!!\n" })
	iana := serve(t, func(q string) string { return "refer: " + registry + "\n" })
	_, err := newClient(iana).Lookup(mustQuery(t, "nosuch.jp"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestLookupReferralLoopStops(t *testing.T) {
	var self string
	self = serve(t, func(q string) string {
		return "refer: " + self + "\nregistrar: Loopy\n"
	})
	rec, err := newClient(self).Lookup(mustQuery(t, "loop.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Servers) != 1 || rec.Registrar != "Loopy" {
		t.Errorf("rec = %+v", rec)
	}
}

func TestLookupDeadRegistrarKeepsRegistryAnswer(t *testing.T) {
	registry := serve(t, func(q string) string {
		return "Registrar WHOIS Server: 127.0.0.1:1\nRegistrar: Registry Answer\n"
	})
	iana := serve(t, func(q string) string { return "refer: " + registry + "\n" })
	rec, err := newClient(iana).Lookup(mustQuery(t, "half.example"))
	if err != nil {
		t.Fatalf("dead registrar hop should not fail the lookup: %v", err)
	}
	if rec.Registrar != "Registry Answer" {
		t.Errorf("registrar = %q (registry answer expected)", rec.Registrar)
	}
}

func TestLookupRootUnreachable(t *testing.T) {
	if _, err := newClient("127.0.0.1:1").Lookup(mustQuery(t, "example.jp")); err == nil {
		t.Fatal("unreachable root must error")
	}
}
