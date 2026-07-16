package idn

import (
	"errors"
	"testing"
)

// TestEncodeLabelRFCVectors uses the lowercase sample strings from RFC 3492
// §7.1 (the mixed-case vectors exercise case flags, which the simplified
// IDNA lowercases away).
func TestEncodeLabelRFCVectors(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"(A) Arabic", "ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"},
		{"(B) Chinese simplified", "他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"},
		{"(C) Chinese traditional", "他們爲什麽不說中文", "ihqwctvzc91f659drss3x8bo0yb"},
		{"(K) Japanese", "なぜみんな日本語を話してくれないのか", "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa"},
		{"(L) Korean", "세계의모든사람들이한국어를이해한다면얼마나좋을까", "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c"},
		{"(O) Vietnamese", "tạisaohọkhôngthểchỉnóitiếngviệt", "tisaohkhngthchnitingvit-kjcr8268qyxafd2f1b9g"},
		{"(P) 3<nen>B<gumi><kinpachi><sensei>", "3年b組金八先生", "3b-ww4c5e180e575a65lsy2b"},
		{"(S) -> $1.00 <-", "-> $1.00 <-", "-> $1.00 <--"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeLabel(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("encodeLabel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestToASCII(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"日本語.jp", "xn--wgv71a119e.jp"},          // the canonical real-world example
		{"ドメイン名例.jp", "xn--eckwd4c7cu47r2wf.jp"}, // JPRS example domain
		{"例え.テスト", "xn--r8jz45g.xn--zckzah"},     // IDN TLD too
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"example.com", "example.com"},             // ASCII passthrough
		{"MIXED.Example.COM", "mixed.example.com"}, // lowercased
		{"日本語.example.com", "xn--wgv71a119e.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ToASCII(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("ToASCII(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestToASCIIRejectsMixedPunycode(t *testing.T) {
	if _, err := ToASCII("xn--日本語.jp"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("mixed xn--+non-ASCII: err = %v, want ErrUnsupported", err)
	}
}
