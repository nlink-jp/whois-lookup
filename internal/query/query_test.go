package query

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyAutoDetect(t *testing.T) {
	tests := []struct {
		in        string
		wantType  Type
		wantValue string
	}{
		{"8.8.8.8", TypeIP, "8.8.8.8"},
		{"2001:db8::1", TypeIP, "2001:db8::1"},
		{"::ffff:1.2.3.4", TypeIP, "1.2.3.4"}, // v4-mapped canonicalized
		{"AS13335", TypeASN, "AS13335"},
		{"as13335", TypeASN, "AS13335"},
		{"13335", TypeASN, "AS13335"}, // bare number reads as ASN
		{"AS4294967295", TypeASN, "AS4294967295"},
		{"example.com", TypeDomain, "example.com"},
		{"Example.COM", TypeDomain, "example.com"},
		{"example.com.", TypeDomain, "example.com"},
		{"xn--wgv71a119e.jp", TypeDomain, "xn--wgv71a119e.jp"},
		{"日本語.jp", TypeDomain, "xn--wgv71a119e.jp"}, // IDN converted in-house
		{"ドメイン名例.JP", TypeDomain, "xn--eckwd4c7cu47r2wf.jp"},
		{"例え.テスト", TypeDomain, "xn--r8jz45g.xn--zckzah"}, // IDN TLD
		{"a-b.c-d.org", TypeDomain, "a-b.c-d.org"},
		{"  example.com  ", TypeDomain, "example.com"}, // surrounding whitespace trimmed
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			q, err := Classify(tt.in, "")
			if err != nil {
				t.Fatalf("Classify(%q) error: %v", tt.in, err)
			}
			if q.Type != tt.wantType || q.Value != tt.wantValue {
				t.Errorf("Classify(%q) = {%s %q}, want {%s %q}", tt.in, q.Type, q.Value, tt.wantType, tt.wantValue)
			}
		})
	}
}

// TestClassifyRejects is the safety gate: none of these may ever reach the
// network.
func TestClassifyRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"CRLF injection", "example.com\r\nEVIL QUERY"},
		{"embedded CR", "example.com\rx"},
		{"embedded LF", "example.com\nx"},
		{"embedded NUL", "example.com\x00"},
		{"embedded DEL", "example.com\x7fx"},
		{"embedded space", "example .com"},
		{"embedded tab", "example\t.com"},
		{"empty label", "example..com"},
		{"leading dot", ".example.com"},
		{"leading hyphen label", "-example.com"},
		{"trailing hyphen label", "example-.com"},
		{"underscore", "exa_mple.com"},
		{"all-numeric TLD", "1.2.3.4.5"},
		{"IPv6 zone", "fe80::1%en0"},
		{"ASN out of range", "AS4294967296"},
		{"mixed punycode and U-label", "xn--日本語.jp"},
		{"single label without hint", "localhost"},
		{"label over 63", strings.Repeat("a", 64) + ".com"},
		{"total over 253", strings.Repeat("abcdefgh.", 30) + "com"},
		{"garbage", "!!!???"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Classify(tt.in, ""); !errors.Is(err, ErrInvalid) {
				t.Errorf("Classify(%q) = %v, want ErrInvalid", tt.in, err)
			}
		})
	}
}

func TestClassifyHints(t *testing.T) {
	// A bare number is an ASN by default, but --type overrides.
	q, err := Classify("13335", TypeASN)
	if err != nil || q.ASN != 13335 {
		t.Fatalf("hint asn: %v %+v", err, q)
	}
	// A bare TLD is only a domain when explicitly hinted.
	q, err = Classify("jp", TypeDomain)
	if err != nil || q.Type != TypeDomain || q.Value != "jp" {
		t.Fatalf("hint domain bare TLD: %v %+v", err, q)
	}
	// A hint narrows: an IP does not pass as a domain-hinted query.
	if _, err := Classify("8.8.8.8", TypeDomain); !errors.Is(err, ErrInvalid) {
		t.Errorf("8.8.8.8 with domain hint: want ErrInvalid, got %v", err)
	}
	// An unknown hint is rejected.
	if _, err := Classify("example.com", Type("bogus")); !errors.Is(err, ErrInvalid) {
		t.Errorf("bogus hint: want ErrInvalid, got %v", err)
	}
	// A domain does not pass as an IP-hinted query.
	if _, err := Classify("example.com", TypeIP); !errors.Is(err, ErrInvalid) {
		t.Errorf("domain with ip hint: want ErrInvalid, got %v", err)
	}
}

func TestTLD(t *testing.T) {
	q, err := Classify("foo.example.co.jp", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := q.TLD(); got != "jp" {
		t.Errorf("TLD() = %q, want %q", got, "jp")
	}
	if q, _ := Classify("8.8.8.8", ""); q.TLD() != "" {
		t.Errorf("TLD() for IP should be empty")
	}
}
