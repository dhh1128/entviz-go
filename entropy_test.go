package entviz

import (
	"errors"
	"testing"
)

func mustParse(t *testing.T, s string) *Parsed {
	t.Helper()
	p, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q) errored: %v", s, err)
	}
	if p == nil {
		t.Fatalf("Parse(%q) returned no match", s)
	}
	return p
}

func TestHexAndUUIDBoundary(t *testing.T) {
	if got := mustParse(t, "a1b2c3d4e5f6a7b8").TypeName; got != "hex" {
		t.Errorf("16-hex type = %s, want hex", got)
	}
	if got := mustParse(t, "0123456789abcdef0123456789abcdef").TypeName; got != "UUID" {
		t.Errorf("32-hex type = %s, want UUID", got)
	}
}

func TestUUIDDashedEqualsUndashed(t *testing.T) {
	a := mustParse(t, "550e8400-e29b-41d4-a716-446655440000")
	b := mustParse(t, "550e8400e29b41d4a716446655440000")
	if a.Core != b.Core {
		t.Errorf("cores differ: %s vs %s", a.Core, b.Core)
	}
	if a.Core != "550e8400e29b41d4a716446655440000" {
		t.Errorf("core = %s", a.Core)
	}
}

func TestEthEip55GoodAndBad(t *testing.T) {
	if got := mustParse(t, "0x742d35cc6634c0532925a3b844bc454e4438f44e").TypeName; got != "ETH" {
		t.Errorf("lowercase eth type = %s", got)
	}
	if got := mustParse(t, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").TypeName; got != "ETH" {
		t.Errorf("checksummed eth type = %s", got)
	}
	_, err := Parse("0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	var e *Eip55Error
	if !errors.As(err, &e) {
		t.Fatalf("bad eip55 should error, got %v", err)
	}
	if e.Position != 2 {
		t.Errorf("eip55 position = %d, want 2", e.Position)
	}
}

func TestSwhidGitoidSemanticPrefix(t *testing.T) {
	s := mustParse(t, "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d")
	if !s.PrefixSemantic {
		t.Error("swhid prefix should be semantic")
	}
	if s.Prefix == nil || *s.Prefix != "swh:1:rev:" {
		t.Errorf("swhid prefix = %v", s.Prefix)
	}
	if s.Core != "309cf2674ee7a0749978cf8265ab91a60aea0f7d" {
		t.Errorf("swhid core = %s", s.Core)
	}
	g := mustParse(t, "gitoid:blob:sha256:473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813")
	if !g.PrefixSemantic || g.Prefix == nil || *g.Prefix != "gitoid:blob:sha256:" {
		t.Errorf("gitoid prefix = %v semantic=%v", g.Prefix, g.PrefixSemantic)
	}
}

func TestLEISuffix(t *testing.T) {
	p := mustParse(t, "5493001KJTIIGC8Y1R12")
	if p.TypeName != "LEI" {
		t.Errorf("type = %s", p.TypeName)
	}
	if p.Core != "5493001KJTIIGC8Y1R12"[:18] {
		t.Errorf("core = %s", p.Core)
	}
	if p.Suffix == nil || *p.Suffix != "12" {
		t.Errorf("suffix = %v", p.Suffix)
	}
}

func TestCesrCodes(t *testing.T) {
	tests := []struct{ in, want string }{
		{"DKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx", "CESR Ed25519 pubkey"},
		{"BKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx", "CESR Ed25519 nt pubkey"},
		{"EBfdlu8R27Fbx_ehrqwImnK_8Cm79sqbAQ4caaZG_LFv", "CESR Blake3-256"},
	}
	for _, tt := range tests {
		if got := mustParse(t, tt.in).TypeName; got != tt.want {
			t.Errorf("cesr %q type = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestBech32CosmosSuffix(t *testing.T) {
	p := mustParse(t, "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e")
	if p.TypeName != "bech32" {
		t.Errorf("type = %s", p.TypeName)
	}
	if p.Prefix == nil || *p.Prefix != "cosmos1" {
		t.Errorf("prefix = %v", p.Prefix)
	}
	if p.Suffix == nil || *p.Suffix != "rk363e" {
		t.Errorf("suffix = %v", p.Suffix)
	}
}

func TestCIDv1Label(t *testing.T) {
	p := mustParse(t, "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	if p.TypeName != "CIDv1 dag-pb" {
		t.Errorf("type = %s, want CIDv1 dag-pb", p.TypeName)
	}
}

func TestSSHEd25519(t *testing.T) {
	p := mustParse(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtJVH9hM+2DyhmgRZBfeIDoVqCTbXY+0nKlS5pTkkXY user@example.com")
	if p.TypeName != "SSH ed25519" {
		t.Errorf("type = %s", p.TypeName)
	}
	if p.Prefix == nil || *p.Prefix != "AAAAC3NzaC1lZDI1NTE5AAAA" {
		t.Errorf("prefix = %v", p.Prefix)
	}
}

func TestSnowflakeDecimal(t *testing.T) {
	if got := mustParse(t, "80351110224678912").TypeName; got != "snowflake" {
		t.Errorf("type = %s", got)
	}
}

func TestTextFallbackIsNone(t *testing.T) {
	p, err := Parse("hello world")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if p != nil {
		t.Errorf("expected no match, got %v", p)
	}
}

func TestCharClassHelpers(t *testing.T) {
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"isHex 0aF9", isHex("0aF9"), true},
		{"isHex empty", isHex(""), false},
		{"isHex 0g", isHex("0g"), false},
		{"isBase58 ok", isBase58("abcXYZ123"), true},
		{"isBase58 empty", isBase58(""), false},
		{"isBase58 0OIl", isBase58("0OIl"), false},
		{"isBech32 QPZRY", isBech32Either("QPZRY"), true},
		{"isBech32 empty", isBech32Either(""), false},
		{"isBech32 bob", isBech32Either("bob"), false},
		{"isBase32 abc234", isBase32Either("abc234"), true},
		{"isBase32 089", isBase32Either("089"), false},
		{"allIn abc", allIn("abc", "abcdef"), true},
		{"allIn abx", allIn("abx", "abcdef"), false},
		{"b64url Ab9-_", isBase64urlNopad("Ab9-_"), true},
		{"b64url a+b", isBase64urlNopad("a+b"), false},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestCesrEmptyAndNonmatch(t *testing.T) {
	if p, _ := parseCesr(""); p != nil {
		t.Error("empty cesr should be nil")
	}
	if p, _ := parseCesr("0AshortXX"); p != nil {
		t.Error("wrong-length cesr should be nil")
	}
}

func TestTokenizeEntropyLargeInput(t *testing.T) {
	// 200 hex chars = 100 bytes (>64) forces large-input handling: head (8) +
	// fingerprint-middle (4) + tail (8) = 20 tokens.
	long := ""
	for i := 0; i < 200; i++ {
		long += "a"
	}
	p := mustParse(t, long)
	toks, truncated := TokenizeEntropy(p.Core, p.Alphabet)
	if !truncated {
		t.Error("expected truncation for large input")
	}
	if len(toks) != 20 {
		t.Errorf("token count = %d, want 20", len(toks))
	}
}
