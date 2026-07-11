package entviz

import (
	"errors"
	"strings"
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

func assertDidUrn(t *testing.T, in, wantPrefix, wantCore string) *Parsed {
	t.Helper()
	p := mustParse(t, in)
	if p.TypeName != "" {
		t.Errorf("%q TypeName = %q, want empty", in, p.TypeName)
	}
	if !p.PrefixSemantic {
		t.Errorf("%q PrefixSemantic = false, want true", in)
	}
	if p.Alphabet.Name != BASE64URL.Name {
		t.Errorf("%q alphabet = %s, want base64url", in, p.Alphabet.Name)
	}
	if p.Prefix == nil || *p.Prefix != wantPrefix {
		t.Errorf("%q prefix = %v, want %q", in, p.Prefix, wantPrefix)
	}
	if p.Core != wantCore {
		t.Errorf("%q core = %q, want %q", in, p.Core, wantCore)
	}
	if p.Suffix != nil {
		t.Errorf("%q suffix = %v, want nil", in, p.Suffix)
	}
	return p
}

func TestDidWebBasic(t *testing.T) {
	assertDidUrn(t, "did:web:example.com", "did:web:", "example.com")
}

func TestDidColonPathKept(t *testing.T) {
	// The method-specific-id MAY contain ':' segment separators (kept verbatim).
	assertDidUrn(t, "did:web:example.com:user:alice", "did:web:", "example.com:user:alice")
}

func TestDidUrlTailDropped(t *testing.T) {
	// A DID-URL tail (path/query/fragment) is dropped; core == the bare body.
	bare := assertDidUrn(t, "did:web:example.com", "did:web:", "example.com")
	withTail := assertDidUrn(t, "did:web:example.com/path?q=1#frag", "did:web:", "example.com")
	if bare.Core != withTail.Core {
		t.Errorf("tail not dropped: %q vs %q", bare.Core, withTail.Core)
	}
}

func TestDidKeyFragmentDropped(t *testing.T) {
	assertDidUrn(t,
		"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"did:key:", "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
}

func TestUrnIsbn(t *testing.T) {
	assertDidUrn(t, "urn:isbn:0451450523", "urn:isbn:", "0451450523")
}

func TestUrnNidLowercasedNssPreserved(t *testing.T) {
	// scheme+NID are case-insensitive (NID lowercased); the NSS case is preserved.
	assertDidUrn(t, "URN:ISBN:0451450523", "urn:isbn:", "0451450523")
	assertDidUrn(t, "urn:Example:AbC123", "urn:example:", "AbC123")
}

func TestUrnNssKeepsSlash(t *testing.T) {
	// Unlike a DID, the URN NSS keeps '/'.
	assertDidUrn(t, "urn:example:a/b/c", "urn:example:", "a/b/c")
}

func TestUrnComponentsDropped(t *testing.T) {
	// r-/q-/f-components end the NSS at the first '?' or '#'.
	assertDidUrn(t, "urn:example:weather?=op=map&lat=39#frag", "urn:example:", "weather")
}

// ---------------------------------------------------------------------------
// v14: checksum verification (base58check / bech32 / CashAddr / LEI) rejects a
// structurally-matching address whose bound checksum does not verify, while a
// valid address of the same scheme still parses. Mirrors the entviz corpus
// error vectors and the reference Base58CheckError/Bech32ChecksumError/
// LEIChecksumError behavior.
// ---------------------------------------------------------------------------

func TestV14ChecksumRejection(t *testing.T) {
	bad := []struct{ scheme, in string }{
		{"BTC legacy (base58check)", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"},
		{"BTC segwit (bech32)", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"},
		{"LTC (bech32)", "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n8"},
		{"cosmos (bech32)", "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363f"},
		{"BCH (CashAddr)", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q"},
		{"LEI (MOD 97-10)", "5493001KJTIIGC8Y1R13"},
	}
	for _, b := range bad {
		p, err := Parse(b.in)
		if err == nil {
			t.Errorf("%s: Parse(%q) accepted, want checksum rejection (parsed=%v)", b.scheme, b.in, p)
			continue
		}
		var ce *ChecksumError
		if !errors.As(err, &ce) {
			t.Errorf("%s: Parse(%q) err = %v (%T), want *ChecksumError", b.scheme, b.in, err, err)
		}
	}
}

func TestV14ChecksumAcceptance(t *testing.T) {
	good := []struct{ scheme, in string }{
		{"BTC legacy", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{"cosmos", "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e"},
		{"BCH", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"},
		{"LEI", "5493001KJTIIGC8Y1R12"},
	}
	for _, g := range good {
		if _, err := Parse(g.in); err != nil {
			t.Errorf("%s: Parse(%q) rejected a valid address: %v", g.scheme, g.in, err)
		}
	}
}

// ---------------------------------------------------------------------------
// v15: the top/bottom label strips are a pure projection of the
// characterization through RenderLabel, now with a trailing PREFIX slot:
// [+hash ]PRIMARY[, MOD]...[, SIZE][, PREFIX]. These cases use lineChars=-1
// (no truncation), so the full stripped prefix (SSH header, CID base) shows.
// ---------------------------------------------------------------------------

func TestV15RenderLabelProjection(t *testing.T) {
	cases := []struct{ in, want string }{
		{"BKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx", "CESR, Ed25519 nt"},
		{"DKxy2sgzfplyr_tgwIxS19f2OchFHtLwPWD3v4oYimBx", "CESR, Ed25519"},
		{"EBfdlu8R27Fbx_ehrqwImnK_8Cm79sqbAQ4caaZG_LFv", "CESR, Blake3-256"},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "hex, 256-bit"},
		{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "did:key"},
		{"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", "CIDv1, dag-pb, b"},
		{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtJVH9hM+2DyhmgRZBfeIDoVqCTbXY+0nKlS5pTkkXY", "SSH, ed25519, 264-bit, AAAAC3NzaC1lZDI1NTE5AAAA"},
	}
	for _, c := range cases {
		ch, err := Characterize(c.in)
		if err != nil {
			t.Errorf("Characterize(%q) errored: %v", c.in, err)
			continue
		}
		top, _ := ch.RenderLabel(false, "", "", -1)
		if top != c.want {
			t.Errorf("RenderLabel top for %q = %q, want %q", c.in, top, c.want)
		}
	}
}

func TestV15RenderLabelTruncationMarker(t *testing.T) {
	ch, err := Characterize("Hello World")
	if err != nil {
		t.Fatalf("Characterize errored: %v", err)
	}
	top, bottom := ch.RenderLabel(true, "", "", -1)
	if top != "+hash text, 11-byte" {
		t.Errorf("truncated top = %q", top)
	}
	if bottom != "" {
		t.Errorf("bottom = %q, want empty", bottom)
	}
	top2, bottom2 := ch.RenderLabel(false, "abcd", "hi", -1)
	if top2 != "text, 11-byte" {
		t.Errorf("top2 = %q", top2)
	}
	if bottom2 != "...abcd (hi)" {
		t.Errorf("bottom2 = %q, want '...abcd (hi)'", bottom2)
	}
}

// TestV15PrefixSlot covers the trailing PREFIX slot for bind="none" front
// prefixes (shown in addition to the type name) and its truncation.
func TestV15PrefixSlot(t *testing.T) {
	// Ethereum: "0x" prefix -> "ETH, 0x".
	ch, err := Characterize("0x52908400098527886E0F7030069857D2E4169EE7")
	if err != nil {
		t.Fatalf("Characterize eth errored: %v", err)
	}
	if top, _ := ch.RenderLabel(false, "", "", -1); top != "ETH, 0x" {
		t.Errorf("eth top = %q, want %q", top, "ETH, 0x")
	}
	// SSH header prefix truncates under a tight budget with ASCII "...".
	sh, err := Characterize("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtJVH9hM+2DyhmgRZBfeIDoVqCTbXY+0nKlS5pTkkXY")
	if err != nil {
		t.Fatalf("Characterize ssh errored: %v", err)
	}
	// core = "SSH, ed25519, 264-bit" (21 chars) + ", " = budget must leave room
	// for a truncated prefix ending in "...".
	top, _ := sh.RenderLabel(false, "", "", 30)
	if !strings.HasSuffix(top, "...") {
		t.Errorf("ssh tight top = %q, want a truncated prefix ending in ...", top)
	}
	if strings.HasPrefix(top, "SSH, ed25519, 264-bit, AAAA") == false {
		t.Errorf("ssh tight top = %q, want SSH core + truncated header", top)
	}
}
