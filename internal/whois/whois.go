package whois

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/nlink-jp/whois-lookup/internal/query"
)

// ErrNotFound means the final WHOIS server answered with a recognizable
// "no match" marker. Detection is best-effort: there is no standard WHOIS
// not-found signal, so unrecognized phrasings surface as a normal result
// whose raw text the caller can read.
var ErrNotFound = errors.New("object not found (WHOIS no match)")

// maxResponse bounds one server response (WHOIS answers are a few KB).
const maxResponse = 1 << 20

// Record is a raw-first WHOIS result: Raw is the primary payload, the
// extracted fields are a best-effort convenience (no full parser, by
// design).
type Record struct {
	Raw         string   // final server's full response
	Servers     []string // referral chain, in query order
	Registrar   string
	Created     string
	Updated     string
	Expires     string
	Nameservers []string
	Status      []string
}

// Client speaks the port 43 protocol with referral chasing. The dial
// function is injected so tests run against local listeners.
type Client struct {
	Dial    func(addr string) (net.Conn, error)
	Root    string        // referral-chain root, e.g. whois.iana.org:43
	Timeout time.Duration // per-exchange read/write deadline
	MaxHops int           // referral chain bound (default 4)
}

// Lookup queries the referral chain for q and returns the final response.
// The input has passed the query package's validation gate, so it contains
// no CRLF or control characters — nothing can be smuggled into the wire
// format below.
func (c *Client) Lookup(q query.Query) (*Record, error) {
	maxHops := c.MaxHops
	if maxHops <= 0 {
		maxHops = 4
	}
	rec := &Record{}
	addr := c.Root
	var raw string
	for hop := 0; hop < maxHops; hop++ {
		rec.Servers = append(rec.Servers, addr)
		var err error
		raw, err = c.exchange(addr, q.Value)
		if err != nil {
			if hop > 0 {
				break // keep the best answer we already have
			}
			return nil, err
		}
		rec.Raw = raw
		next := referral(raw)
		if next == "" || sameServer(next, addr) || contains(rec.Servers, next) {
			break
		}
		addr = next
	}
	if isNoMatch(rec.Raw) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, q.Value)
	}
	extract(rec)
	return rec, nil
}

// exchange performs one "query + CRLF → read to EOF" round trip.
func (c *Client) exchange(addr, q string) (string, error) {
	conn, err := c.Dial(addr)
	if err != nil {
		return "", fmt.Errorf("whois %s: %w", addr, err)
	}
	defer conn.Close()
	if c.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	}
	if _, err := io.WriteString(conn, q+"\r\n"); err != nil {
		return "", fmt.Errorf("whois %s: %w", addr, err)
	}
	b, err := io.ReadAll(io.LimitReader(conn, maxResponse))
	if err != nil && len(b) == 0 {
		return "", fmt.Errorf("whois %s: %w", addr, err)
	}
	return string(b), nil
}

// referral extracts the next server in the chain: IANA's "refer:"/"whois:"
// and the thin-registry "Registrar WHOIS Server:" convention.
func referral(raw string) string {
	for line := range strings.SplitSeq(raw, "\n") {
		key, val, ok := splitKV(line)
		if !ok || val == "" {
			continue
		}
		switch key {
		case "refer", "whois", "whois server", "registrar whois server":
			if !strings.Contains(val, ":") {
				val += ":43"
			}
			return val
		}
	}
	return ""
}

// extract fills the best-effort fields from Raw. It understands the common
// "Key: value" form plus the JPRS bracketed form ("[Name Server] host").
func extract(rec *Record) {
	seenNS := map[string]bool{}
	for line := range strings.SplitSeq(rec.Raw, "\n") {
		key, val, ok := splitKV(line)
		if !ok || val == "" {
			continue
		}
		switch key {
		case "registrar":
			setFirst(&rec.Registrar, val)
		case "creation date", "created", "registered", "登録年月日":
			setFirst(&rec.Created, val)
		case "updated date", "last updated", "last update", "最終更新":
			setFirst(&rec.Updated, val)
		case "registry expiry date", "expiration date", "expiry date", "expires", "有効期限", "状態に関する期限":
			setFirst(&rec.Expires, val)
		case "name server", "nameserver", "nserver":
			ns := strings.ToLower(strings.Fields(val)[0])
			if !seenNS[ns] {
				seenNS[ns] = true
				rec.Nameservers = append(rec.Nameservers, ns)
			}
		case "status", "domain status", "状態":
			rec.Status = append(rec.Status, val)
		}
	}
}

// splitKV parses "Key: value" and JPRS "[Key] value" lines into a lowercase
// key and a trimmed value.
func splitKV(line string) (key, val string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	if strings.HasPrefix(line, "[") {
		end := strings.IndexByte(line, ']')
		if end < 0 {
			return "", "", false
		}
		return strings.ToLower(strings.TrimSpace(line[1:end])), strings.TrimSpace(line[end+1:]), true
	}
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(line[:i])), strings.TrimSpace(line[i+1:]), true
}

func setFirst(dst *string, val string) {
	if *dst == "" {
		*dst = val
	}
}

// isNoMatch recognizes the common not-found phrasings (best-effort).
func isNoMatch(raw string) bool {
	l := strings.ToLower(raw)
	for _, marker := range []string{
		"no match", "not found", "no entries found", "no data found",
		"object does not exist", "domain not found",
	} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func sameServer(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, ":43"), strings.TrimSuffix(b, ":43"))
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if sameServer(v, s) {
			return true
		}
	}
	return false
}
