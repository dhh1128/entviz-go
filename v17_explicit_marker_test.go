// v17 correction 2: a failing checksum rejects ONLY on an explicit marker.
//
// The 2026-08-06 correction fixed the generic bech32 path (see
// v17_bech32_fallthrough_test.go); the same defect was then measured in four
// more places. Across 8100 random values in three alphabets and nine lengths,
// the weak-signal paths refused roughly 2% outright — Bitcoin and Litecoin
// legacy base58check dominating, plus LEI and bare CashAddr.
//
// The rule, stated generally so it stops recurring: a failing checksum REJECTS
// only when the input carries an EXPLICIT, MULTI-CHARACTER scheme marker
// (bc1/tb1, ltc1, addr1/stake1/addr_test1, a TYPED bitcoincash:/bchtest:, and
// 0x + exactly 40 hex for EIP-55). Then "this is that scheme, corrupted" is a
// claim the parser can support. Where the only signal is a leading character, a
// length band, or a reserved digit pair, the parser DECLINES and the input
// continues down the chain, because all a failed check proves is "not that
// scheme".
//
// CashAddr splits BY INPUT, not by parser: the same recognizer rejects when the
// prefix was typed and declines when it was not, because the marker either is
// present in the input or it is not.
//
// See `this.i:w3aksig` and the "Correction 2 to v17" section of
// docs/spec-change-log.md.

package entviz

import (
	"math/rand"
	"strings"
	"testing"
)

// Inputs whose ONLY scheme signal is a leading character, a length band, or a
// reserved digit pair. Each is a valid corpus value with one character
// corrupted. `scheme` is the label text the parser must NOT claim.
var weakSignalBadChecksum = []struct{ name, value, scheme string }{
	// Corpus render vector btc-legacy-bad-checksum-falls-through
	// ("base58, 192-bit"), formerly the err-btc-legacy-bad-checksum error
	// vector. Signal: one leading character from [123mn] plus a length band.
	{"btc-legacy", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "BTC"},
	// Signal: `L`/`tL` plus a fixed length. Generated for this test (version
	// byte 0x30 over a fixed 20-byte hash), last character corrupted; the valid
	// twin is ltcLegacyValid below.
	{"ltc-legacy", "LXwgTPapevJnEg8UWnPsj9xvWzNw78iqRa", "LTC"},
	// Corpus render vector lei-bad-checksum-falls-through ("b64, 120-bit"),
	// formerly err-lei-bad-checksum. Signal: the reserved "00" at positions
	// 4-5, which lands by chance in 1 of 1296 random 20-char base36 strings.
	{"lei", "5493001KJTIIGC8Y1R13", "LEI"},
	// Corpus render vector cashaddr-bare-bad-checksum-falls-through
	// ("bech32"). Signal: a leading q/p plus a length — and, critically, NO
	// typed prefix. The prefixed spelling of this same body still rejects; see
	// explicitMarkerBadChecksum.
	{"cashaddr-bare", "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q", "BCH"},
	// Corpus render vector cosmos-bad-checksum-falls-through ("base58,
	// 264-bit"), the 2026-08-06 correction. Listed here so the whole rule is
	// stated in one table.
	{"generic-bech32", "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363f", "bech32"},
}

// Inputs carrying an unmistakable multi-character marker. A failing checksum
// here really does mean a corrupt instance of that scheme, so rejection stands.
var explicitMarkerBadChecksum = []struct{ name, value string }{
	{"bc1", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"},
	{"ltc1", "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n8"},
	{"bitcoincash:", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q"},
	{"addr1", "addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kcmtwdac8zunnw36hvamc09a8klra0elsr0jfpq"},
	{"eip55", "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
}

// ltcLegacyValid is the uncorrupted twin of the ltc-legacy weak-signal case: a
// real base58check Litecoin P2PKH address. It pins that the fall-through did
// not break acceptance.
const ltcLegacyValid = "LXwgTPapevJnEg8UWnPsj9xvWzNw78iqRx"

func TestV17WeakSignalDeclinesAndNeverClaimsTheScheme(t *testing.T) {
	for _, c := range weakSignalBadChecksum {
		p, err := Parse(c.value)
		if err != nil {
			t.Errorf("%s: Parse(%q) = %v, want fall-through (no error)", c.name, c.value, err)
			continue
		}
		if p == nil {
			t.Errorf("%s: Parse(%q) = nil, must still render as SOMETHING", c.name, c.value)
			continue
		}
		// It never renders AS the scheme: the label reports the encoding
		// actually recognized, so a reader comparing against a known-good
		// address sees a different type name and a different picture.
		if strings.Contains(p.TypeName, c.scheme) {
			t.Errorf("%s: Parse(%q) typed %q — must not claim %s with a failing checksum",
				c.name, c.value, p.TypeName, c.scheme)
		}
	}
}

func TestV17ExplicitMarkerStillRejects(t *testing.T) {
	// Guards the correction from over-reaching: it must not drift into "never
	// reject anything".
	for _, c := range explicitMarkerBadChecksum {
		p, err := Parse(c.value)
		if err == nil {
			t.Errorf("%s: Parse(%q) accepted (parsed=%v), want a hard rejection — "+
				"the marker is explicit, so a failing checksum means a corrupt address",
				c.name, c.value, p)
		}
	}
}

// The same CashAddr body, typed both ways. This is the whole "splits by INPUT"
// rule in one test: identical payload, identical recognizer, opposite verdicts,
// decided solely by whether the marker was present.
func TestV17CashAddrVerdictFollowsTheInputNotTheParser(t *testing.T) {
	const body = "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q" // corrupted last char
	if _, err := Parse("bitcoincash:" + body); err == nil {
		t.Errorf("typed prefix: Parse(bitcoincash:%s) accepted, want rejection", body)
	}
	p, err := Parse(body)
	if err != nil {
		t.Errorf("bare body: Parse(%q) = %v, want fall-through", body, err)
	} else if p == nil || strings.Contains(p.TypeName, "BCH") {
		t.Errorf("bare body: Parse(%q) = %v, want a non-BCH fall-through parse", body, p)
	}
}

// Acceptance is untouched: every weak-signal scheme still parses when its
// checksum verifies.
func TestV17WeakSignalStillParsesWhenValid(t *testing.T) {
	good := []struct{ in, want string }{
		{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC legacy"},
		{ltcLegacyValid, "LTC legacy"},
		{"5493001KJTIIGC8Y1R12", "LEI"},
		{"qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "BCH"},
		{"cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e", "bech32"},
	}
	for _, g := range good {
		p := mustParse(t, g.in)
		if p.TypeName != g.want {
			t.Errorf("Parse(%q) type = %q, want %q", g.in, p.TypeName, g.want)
		}
	}
}

// The property the whole correction exists to establish, stated directly:
// entviz renders arbitrary entropy, so no ordinary random value may be refused
// outright. Before the correction roughly 2% of these were.
func TestV17NoRandomValueIsRefusedOutright(t *testing.T) {
	alphabets := []struct{ name, chars string }{
		{"hex", "0123456789abcdef"},
		{"base58", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"},
		{"base36", "0123456789abcdefghijklmnopqrstuvwxyz"},
	}
	// Fixed seed: a refusal found here must be reproducible, and the property
	// is about the parser, not about today's luck.
	rng := rand.New(rand.NewSource(0x17c2))
	var refused []string
	for _, a := range alphabets {
		for _, n := range []int{12, 16, 20, 24, 26, 32, 34, 40, 42} {
			for i := 0; i < 300; i++ {
				var b strings.Builder
				for j := 0; j < n; j++ {
					b.WriteByte(a.chars[rng.Intn(len(a.chars))])
				}
				s := b.String()
				if _, err := Parse(s); err != nil {
					refused = append(refused, a.name+" "+s+": "+err.Error())
				}
			}
		}
	}
	if len(refused) > 0 {
		show := refused
		if len(show) > 5 {
			show = show[:5]
		}
		t.Errorf("%d of 8100 random values refused outright, want 0; first few: %v",
			len(refused), show)
	}
}
