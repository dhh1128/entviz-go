// v16: the bech32 HRP is identity-bearing and binds the fingerprint.
//
// Before v16 a bech32 human-readable part was classified as presentation
// framing — validated by the polymod, then dropped. Two values sharing a data
// payload under different HRPs therefore rendered byte-identically in every
// channel a human compares, and differed only in the 12px grey label: a Cosmos
// address and its Osmosis spelling, mainnet and testnet Bitcoin or Cardano,
// and — the case that motivated the change — a nostr `npub1…` public key and
// the `nsec1…` secret key over the same payload.
//
// v16 folds `<hrp>1` into the fingerprint (`prefix ‖ core`), the mechanism
// DIDs, URNs, SWHIDs and gitoids already use. See docs/spec.md "How identity
// material is bound", `this.i:s3mpr3fx`, and `this.i:hrpb1nd`.

package entviz

import (
	"regexp"
	"strings"
	"testing"
)

// Each pair shares a data payload and differs only in the HRP. The checksums
// differ because the polymod covers the HRP; they are the bound suffix and are
// not part of the core, which is exactly why the fold is needed.
var hrpPairs = []struct{ name, a, b string }{
	{"cosmos/osmo",
		"cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e",
		"osmo1qqqsyqcyq5rqwzqfpg9scrgwpugpzysntdz28t"},
	{"bc/tb",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"},
	{"addr/addr_test",
		"addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc" +
			"mtwdac8zunnw36hvamc09a8klra0elsr0jfpr",
		"addr_test1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc" +
			"mtwdac8zunnw36hvamc09a8klra0els30xwlp"},
	{"npub/nsec",
		"npub1802mpadp48s09v7y6hn0wzqe9ga5chtw07qfz23mf3wkuluqjy3swt0n8f",
		"nsec1802mpadp48s09v7y6hn0wzqe9ga5chtw07qfz23mf3wkuluqjy3szayjpu"},
}

// Every attribute below is derived from the fingerprint, so all of them move
// when the hash input changes. Checking the set rather than one of them keeps
// the test honest if a future channel is added or renamed.
var gestaltAttrs = regexp.MustCompile(
	`data-(?:surround-bits|edge-color|cell-quartile|cell-blank[a-z-]*|` +
		`ellipse-[a-z-]+|bar-marker-[a-z]+)="[^"]*"`)

func gestalt(t *testing.T, entropy string) []string {
	t.Helper()
	svg, err := Render(entropy, 1.0, 12.0, nil)
	if err != nil {
		t.Fatalf("Render(%q) errored: %v", entropy, err)
	}
	return gestaltAttrs.FindAllString(svg, -1)
}

func TestSamePayloadDifferentHRPSharesACore(t *testing.T) {
	// The premise of the whole test: the cores really are identical, so nothing
	// except the fold can distinguish these two values. If a future parser
	// change puts the HRP or the checksum into the core, this assertion fails
	// and the pair stops testing what it was written to test.
	for _, p := range hrpPairs {
		pa := mustParse(t, p.a)
		pb := mustParse(t, p.b)
		if pa.Core != pb.Core {
			t.Errorf("%s: cores differ (%q vs %q)", p.name, pa.Core, pb.Core)
		}
		if pa.Prefix == nil || pb.Prefix == nil || *pa.Prefix == *pb.Prefix {
			t.Errorf("%s: prefixes are not distinct (%v vs %v)", p.name, pa.Prefix, pb.Prefix)
		}
		if !pa.PrefixSemantic || !pb.PrefixSemantic {
			t.Errorf("%s: PrefixSemantic = %v/%v, want true/true",
				p.name, pa.PrefixSemantic, pb.PrefixSemantic)
		}
	}
}

func TestSamePayloadDifferentHRPRendersDifferently(t *testing.T) {
	for _, p := range hrpPairs {
		ga := gestalt(t, p.a)
		gb := gestalt(t, p.b)
		if len(ga) == 0 {
			t.Fatalf("%s: no gestalt attributes found", p.name)
		}
		if strings.Join(ga, "|") == strings.Join(gb, "|") {
			t.Errorf("%s: identical fingerprint-derived channels — the HRP is not bound", p.name)
		}
	}
}

func TestTheTwoRendersAreNotMerelyLabelDeep(t *testing.T) {
	// A reader who never looks at the label must still see a difference, so the
	// divergence has to reach the cells' own painted attributes — not just the
	// ellipse or the colour bar at the edges of the picture.
	surround := regexp.MustCompile(`data-surround-bits="[^"]*"`)
	for _, p := range hrpPairs {
		svgA, err := Render(p.a, 1.0, 12.0, nil)
		if err != nil {
			t.Fatalf("Render(%q): %v", p.a, err)
		}
		svgB, err := Render(p.b, 1.0, 12.0, nil)
		if err != nil {
			t.Fatalf("Render(%q): %v", p.b, err)
		}
		ca := surround.FindAllString(svgA, -1)
		cb := surround.FindAllString(svgB, -1)
		if len(ca) == 0 || len(cb) == 0 {
			t.Fatalf("%s: no cell surround attributes found", p.name)
		}
		if strings.Join(ca, "|") == strings.Join(cb, "|") {
			t.Errorf("%s: cells are identical — the difference is label-deep only", p.name)
		}
	}
}

func TestHRPIsStillReadableInTheLabel(t *testing.T) {
	// The fold puts the HRP in the fingerprint, not in the cells, so the label
	// is the only text carrier left. Losing it there would leave a read-aloud
	// comparison with no way to tell these values apart at all.
	cases := []struct{ entropy, want string }{
		{"cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e", "bech32, cosmos1"},
		{"osmo1qqqsyqcyq5rqwzqfpg9scrgwpugpzysntdz28t", "bech32, osmo1"},
		// v17 added the `testnet` mod here. When this vector was written for
		// v16 it read `BTC, tb1` — a testnet address labeled exactly like its
		// mainnet twin, because the network qualifier was hardcoded to
		// mainnet. See v17_network_qualifier_test.go and `this.i:n3twrkq`.
		{"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "BTC, testnet, tb1"},
		{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "BTC, bc1"},
		{"ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", "LTC, ltc1"},
	}
	for _, c := range cases {
		ch, err := Characterize(c.entropy)
		if err != nil {
			t.Fatalf("Characterize(%q): %v", c.entropy, err)
		}
		top, _ := ch.RenderLabel(false, "", "", -1)
		if top != c.want {
			t.Errorf("label for %q = %q, want %q", c.entropy, top, c.want)
		}
	}
}

func TestFoldPrefixSchemesDoNotDoubleThePrefix(t *testing.T) {
	// v16: strippedPrefix now RETURNS a folded prefix (the bech32 HRP has to
	// reach the label, and its PRIMARY is "bech32", not the HRP). The
	// no-doubling rule moved into RenderLabel, which drops the slot only when
	// PRIMARY already displays that exact prefix — which is these four schemes.
	cases := []struct{ entropy, want string }{
		{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "did:key"},
		{"urn:isbn:0451450523", "urn:isbn"},
		{"gitoid:blob:sha256:fe6ec2ba0d1b0d3d2d05be18b1c4c0d1b1a4a3e7c94ba0b6ffb1a6f1e4d5c7a2",
			"gitoid:blob:sha256"},
		{"swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2", "swh:1:cnt"},
	}
	for _, c := range cases {
		ch, err := Characterize(c.entropy)
		if err != nil {
			t.Fatalf("Characterize(%q): %v", c.entropy, err)
		}
		prefix := ch.strippedPrefix()
		if prefix == "" {
			t.Errorf("%q: strippedPrefix is empty; v16 returns folded prefixes too", c.entropy)
			continue
		}
		if trimTrailingColons(prefix) != c.want {
			t.Errorf("%q: prefix %q does not match PRIMARY %q", c.entropy, prefix, c.want)
		}
		top, _ := ch.RenderLabel(false, "", "", -1)
		if top != c.want {
			t.Errorf("label for %q = %q, want %q (prefix must not be doubled)",
				c.entropy, top, c.want)
		}
	}
}

func TestBech32ChecksumIsTheSuffixOnEveryPath(t *testing.T) {
	// v16 made this uniform: before, the generic and Cardano parsers split the
	// checksum off while the Bitcoin-segwit and Litecoin parsers left it in the
	// core — which bound their HRP by accident and inflated size_bits.
	for _, entropy := range []string{
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		"ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
		"cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e",
		"addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc" +
			"mtwdac8zunnw36hvamc09a8klra0elsr0jfpr",
	} {
		p := mustParse(t, entropy)
		if p.Suffix == nil || len([]rune(*p.Suffix)) != 6 {
			t.Errorf("%q: suffix = %v, want a 6-char checksum", entropy, p.Suffix)
			continue
		}
		if !strings.HasSuffix(entropy, *p.Suffix) {
			t.Errorf("%q: suffix %q is not the tail of the input", entropy, *p.Suffix)
		}
		if strings.HasSuffix(p.Core, *p.Suffix) {
			t.Errorf("%q: the checksum is still inside the core", entropy)
		}
	}
}

func TestCardanoShelleyParses(t *testing.T) {
	// Cardano Shelley is bech32 and folds like the rest; addr_test1 is a
	// different network, so it must not share a fingerprint with addr1.
	p := mustParse(t, "addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc"+
		"mtwdac8zunnw36hvamc09a8klra0elsr0jfpr")
	if p.TypeName != "ADA Shelley" {
		t.Errorf("type = %s, want ADA Shelley", p.TypeName)
	}
	if p.Alphabet.Name != BECH32.Name {
		t.Errorf("alphabet = %s, want bech32", p.Alphabet.Name)
	}
	if p.Prefix == nil || *p.Prefix != "addr1" {
		t.Errorf("prefix = %v, want addr1", p.Prefix)
	}
	if !p.PrefixSemantic {
		t.Error("PrefixSemantic = false, want true")
	}
	// A corrupted checksum on a structural Shelley match must REJECT, not fall
	// through to a bare bech32 encoding (v14 checksum rule).
	bad := "addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc" +
		"mtwdac8zunnw36hvamc09a8klra0elsr0jfpq"
	if _, err := Parse(bad); err == nil {
		t.Error("a bad Cardano Shelley checksum did not reject")
	}
}

func TestCardanoByronParses(t *testing.T) {
	// Byron carries no trailing base58check field — its CRC-32 lives inside the
	// CBOR payload — so the whole body is the core, the suffix is nil, and the
	// prefix is presentation framing rather than a fold (v14).
	p := mustParse(t, "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi")
	if p.TypeName != "ADA Byron" {
		t.Errorf("type = %s, want ADA Byron", p.TypeName)
	}
	if p.Suffix != nil {
		t.Errorf("suffix = %v, want nil (Byron has no verified checksum field)", *p.Suffix)
	}
	if p.PrefixSemantic {
		t.Error("PrefixSemantic = true, want false")
	}
}

func TestCashAddrIsTheDocumentedException(t *testing.T) {
	// CashAddr is deliberately NOT folded: its prefix is optional, so a bare
	// body and its prefixed spelling are the same address and must not diverge.
	// It is safe unfolded because its checksum stays in the core and covers the
	// prefix. See parseBitcoinCashAddress.
	const bareText = "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
	const prefixedText = "bitcoincash:" + bareText
	bare := mustParse(t, bareText)
	prefixed := mustParse(t, prefixedText)
	if bare.Core != prefixed.Core {
		t.Errorf("cores differ (%q vs %q)", bare.Core, prefixed.Core)
	}
	if bare.PrefixSemantic || prefixed.PrefixSemantic {
		t.Error("CashAddr must stay unfolded")
	}
	if bare.Suffix != nil {
		t.Errorf("suffix = %v, want nil (the 8-char checksum stays in the core)", *bare.Suffix)
	}
	if strings.Join(gestalt(t, bareText), "|") != strings.Join(gestalt(t, prefixedText), "|") {
		t.Error("a bare CashAddr body and its prefixed spelling render differently")
	}
}
