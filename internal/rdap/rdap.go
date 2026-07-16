package rdap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nlink-jp/whois-lookup/internal/query"
)

// ErrNotFound means the registry answered authoritatively that the object
// does not exist (HTTP 404). It is a successful answer about a nonexistent
// object, distinct from failure — the CLI maps it to exit code 1.
var ErrNotFound = errors.New("object not found")

// Doer executes HTTP requests. *http.Client satisfies it; tests inject
// fakes.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Contact is a normalized point of contact (from an RDAP vCard).
type Contact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// Result is the normalized output schema shared by the CLI and the MCP
// server. Registry dialects are absorbed here; downstream code never sees
// raw RDAP.
type Result struct {
	Query        string          `json:"query"`
	QueryASCII   string          `json:"query_ascii,omitempty"` // set when it differs from Query (IDN)
	Type         string          `json:"type"`
	Source       string          `json:"source"` // "rdap" | "whois"
	Cached       bool            `json:"cached,omitempty"`
	Handle       string          `json:"handle,omitempty"`
	Name         string          `json:"name,omitempty"` // network/autnum name or domain unicode name
	Registrar    string          `json:"registrar,omitempty"`
	Created      string          `json:"created,omitempty"`
	Updated      string          `json:"updated,omitempty"`
	Expires      string          `json:"expires,omitempty"`
	Nameservers  []string        `json:"nameservers,omitempty"`
	Status       []string        `json:"status,omitempty"`
	Range        string          `json:"range,omitempty"` // ip allocation "start - end" / autnum "ASn - ASm"
	Country      string          `json:"country,omitempty"`
	AbuseContact *Contact        `json:"abuse_contact,omitempty"`
	Raw          json.RawMessage `json:"raw,omitempty"`      // raw RDAP response (source: rdap)
	RawText      string          `json:"raw_text,omitempty"` // raw WHOIS response (source: whois)
}

// Client queries RDAP endpoints and normalizes responses.
type Client struct {
	Client    Doer
	UserAgent string
}

// Lookup queries one RDAP base URL for q and returns the normalized result
// plus the raw response body (for --raw).
func (c *Client) Lookup(base string, q query.Query) (*Result, json.RawMessage, error) {
	var path string
	switch q.Type {
	case query.TypeDomain:
		path = "domain/" + url.PathEscape(q.Value)
	case query.TypeIP:
		path = "ip/" + url.PathEscape(q.Value)
	case query.TypeASN:
		path = "autnum/" + strconv.FormatUint(uint64(q.ASN), 10)
	default:
		return nil, nil, fmt.Errorf("unsupported query type %q", q.Type)
	}

	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("rdap query %s: %w", base+path, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil, fmt.Errorf("%w: %s (RDAP 404 from %s)", ErrNotFound, q.Value, base)
	case resp.StatusCode != http.StatusOK:
		return nil, nil, fmt.Errorf("rdap query %s: HTTP %d", base+path, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("rdap query %s: %w", base+path, err)
	}
	res, err := normalize(body, q)
	if err != nil {
		return nil, nil, fmt.Errorf("rdap response from %s: %w", base, err)
	}
	return res, body, nil
}

// --- wire types (lenient: every field optional; dialects vary) ---

type rdapResponse struct {
	Handle       string       `json:"handle"`
	LDHName      string       `json:"ldhName"`
	UnicodeName  string       `json:"unicodeName"`
	Name         string       `json:"name"`
	Country      string       `json:"country"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	StartAutnum  *uint32      `json:"startAutnum"`
	EndAutnum    *uint32      `json:"endAutnum"`
	Status       []string     `json:"status"`
	Events       []rdapEvent  `json:"events"`
	Entities     []rdapEntity `json:"entities"`
	Nameservers  []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"` // abuse is often nested under registrar
}

// normalize maps a raw RDAP body onto Result, tolerating missing fields.
func normalize(body []byte, q query.Query) (*Result, error) {
	var w rdapResponse
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("not valid RDAP JSON: %w", err)
	}
	res := &Result{
		Query:   q.Original,
		Type:    string(q.Type),
		Source:  "rdap",
		Handle:  w.Handle,
		Status:  w.Status,
		Country: w.Country,
	}
	if q.Original != q.Value {
		res.QueryASCII = q.Value
	}

	switch {
	case w.UnicodeName != "":
		res.Name = w.UnicodeName
	case w.Name != "":
		res.Name = w.Name
	case w.LDHName != "":
		res.Name = strings.ToLower(w.LDHName)
	}
	if w.StartAddress != "" || w.EndAddress != "" {
		res.Range = w.StartAddress + " - " + w.EndAddress
	}
	if w.StartAutnum != nil && w.EndAutnum != nil {
		res.Range = fmt.Sprintf("AS%d - AS%d", *w.StartAutnum, *w.EndAutnum)
	}
	for _, ev := range w.Events {
		switch strings.ToLower(ev.Action) {
		case "registration":
			res.Created = ev.Date
		case "last changed":
			res.Updated = ev.Date
		case "expiration":
			res.Expires = ev.Date
		}
	}
	for _, ns := range w.Nameservers {
		if ns.LDHName != "" {
			res.Nameservers = append(res.Nameservers, strings.ToLower(ns.LDHName))
		}
	}

	if e := findEntity(w.Entities, "registrar"); e != nil {
		if c := vcardContact(e.VCardArray); c.Name != "" {
			res.Registrar = c.Name
		} else {
			res.Registrar = e.Handle
		}
	}
	if e := findEntity(w.Entities, "abuse"); e != nil {
		if c := vcardContact(e.VCardArray); c.Name != "" || c.Email != "" {
			res.AbuseContact = &c
		}
	}
	return res, nil
}

// findEntity depth-first-searches entities (abuse contacts are commonly
// nested under the registrar entity).
func findEntity(entities []rdapEntity, role string) *rdapEntity {
	for i := range entities {
		for _, r := range entities[i].Roles {
			if strings.EqualFold(r, role) {
				return &entities[i]
			}
		}
		if e := findEntity(entities[i].Entities, role); e != nil {
			return e
		}
	}
	return nil
}

// vcardContact extracts fn and email from a jCard ("vcardArray") value:
// ["vcard", [[name, params, type, value], ...]]. Everything is optional and
// values may be strings or arrays; be lenient.
func vcardContact(raw json.RawMessage) Contact {
	var c Contact
	if len(raw) == 0 {
		return c
	}
	var outer []json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || len(outer) < 2 {
		return c
	}
	var props [][]json.RawMessage
	if json.Unmarshal(outer[1], &props) != nil {
		return c
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name string
		if json.Unmarshal(p[0], &name) != nil {
			continue
		}
		val := stringValue(p[3])
		switch strings.ToLower(name) {
		case "fn":
			if c.Name == "" {
				c.Name = val
			}
		case "email":
			if c.Email == "" {
				c.Email = val
			}
		}
	}
	return c
}

// stringValue reads a jCard property value that may be a string or an array
// of strings.
func stringValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return strings.Join(arr, " ")
	}
	return ""
}
