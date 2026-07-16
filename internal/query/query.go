package query

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Type is the classified kind of a lookup input.
type Type string

const (
	TypeIP     Type = "ip"
	TypeDomain Type = "domain"
	TypeASN    Type = "asn"
)

// ErrInvalid marks input that is valid as none of IP / ASN / domain. Callers
// must not send such input anywhere near the network.
var ErrInvalid = errors.New("invalid input")

// Query is a validated, canonicalized lookup input.
type Query struct {
	Type     Type
	Original string     // input as given (trimmed)
	Value    string     // canonical form: unmapped IP, "AS<n>", lowercase A-label domain
	Addr     netip.Addr // set when Type == TypeIP
	ASN      uint32     // set when Type == TypeASN
}

// Classify validates input and returns its canonical Query. hint narrows the
// accepted type ("" auto-detects). Detection order: IP → ASN → domain; input
// that fails all three is rejected with ErrInvalid before any network I/O.
func Classify(input string, hint Type) (Query, error) {
	in := strings.TrimSpace(input)
	if in == "" {
		return Query{}, fmt.Errorf("%w: empty input", ErrInvalid)
	}
	// The gate against port 43 protocol injection: the WHOIS wire format is
	// "query + CRLF", so no control character or embedded whitespace may
	// survive into any later stage, regardless of claimed type.
	for _, r := range in {
		if r < 0x21 || r == 0x7f {
			return Query{}, fmt.Errorf("%w: control or whitespace character in input", ErrInvalid)
		}
	}

	switch hint {
	case TypeIP:
		return classifyIP(in)
	case TypeASN:
		return classifyASN(in)
	case TypeDomain:
		return classifyDomain(in, true)
	case "":
	default:
		return Query{}, fmt.Errorf("%w: unknown type hint %q", ErrInvalid, hint)
	}

	if q, err := classifyIP(in); err == nil {
		return q, nil
	}
	if q, err := classifyASN(in); err == nil {
		return q, nil
	}
	q, err := classifyDomain(in, false)
	if err != nil {
		return Query{}, fmt.Errorf("%w: %q is not an IP address, an AS number, or a valid domain name (%v)", ErrInvalid, in, errors.Unwrap(err))
	}
	return q, nil
}

func classifyIP(in string) (Query, error) {
	addr, err := netip.ParseAddr(in)
	if err != nil {
		return Query{}, fmt.Errorf("%w: not an IP address", ErrInvalid)
	}
	if addr.Zone() != "" {
		return Query{}, fmt.Errorf("%w: IPv6 zone is not allowed", ErrInvalid)
	}
	addr = addr.Unmap()
	return Query{Type: TypeIP, Original: in, Value: addr.String(), Addr: addr}, nil
}

func classifyASN(in string) (Query, error) {
	s := in
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	if s == "" || len(s) > 10 {
		return Query{}, fmt.Errorf("%w: not an AS number", ErrInvalid)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > 4294967295 {
		return Query{}, fmt.Errorf("%w: not an AS number", ErrInvalid)
	}
	return Query{Type: TypeASN, Original: in, Value: "AS" + strconv.FormatUint(n, 10), ASN: uint32(n)}, nil
}

// classifyDomain applies the RFC hostname rules (total ≤253 after the
// optional trailing dot, labels 1–63, LDH, last label not all-numeric). A
// single-label name (bare TLD) is allowed only when the type was explicitly
// hinted. Phase 1 accepts A-labels only; non-ASCII input gets a pointer to
// punycode until the idn package (Phase 2) converts it here.
func classifyDomain(in string, hinted bool) (Query, error) {
	name := strings.ToLower(strings.TrimSuffix(in, "."))
	if name == "" {
		return Query{}, fmt.Errorf("%w: empty domain", ErrInvalid)
	}
	for _, r := range name {
		if r > 0x7f {
			return Query{}, fmt.Errorf("%w: IDN U-labels are not supported yet — pass the punycode (xn--) form", ErrInvalid)
		}
	}
	if len(name) > 253 {
		return Query{}, fmt.Errorf("%w: domain exceeds 253 characters", ErrInvalid)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 && !hinted {
		return Query{}, fmt.Errorf("%w: domain needs at least two labels (use --type domain for a bare TLD)", ErrInvalid)
	}
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return Query{}, err
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return Query{}, fmt.Errorf("%w: top-level label cannot be all-numeric", ErrInvalid)
	}
	return Query{Type: TypeDomain, Original: in, Value: name}, nil
}

func checkLabel(l string) error {
	if l == "" {
		return fmt.Errorf("%w: empty label", ErrInvalid)
	}
	if len(l) > 63 {
		return fmt.Errorf("%w: label exceeds 63 characters", ErrInvalid)
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("%w: label cannot start or end with a hyphen", ErrInvalid)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return fmt.Errorf("%w: label contains %q", ErrInvalid, rune(c))
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// TLD returns the last label of a domain query ("" for non-domains).
func (q Query) TLD() string {
	if q.Type != TypeDomain {
		return ""
	}
	if i := strings.LastIndexByte(q.Value, '.'); i >= 0 {
		return q.Value[i+1:]
	}
	return q.Value
}
