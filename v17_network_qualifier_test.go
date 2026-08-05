package entviz

// v17: the network qualifier is read from the prefix, not assumed.
//
// Through v16 Characterize() hardcoded `network: "mainnet"` for every BTC
// address and emitted no network at all for Cardano Shelley. Because
// labelMods() surfaces the network only when it *departs* from mainnet (the
// v14 rule — "testnet loud, mainnet silent"), a testnet address rendered a
// label indistinguishable from its mainnet twin: `BTC, tb1` where
// `BTC, testnet, tb1` was required. The reference was non-conformant to its
// own spec, in the same mainnet-versus-testnet confusability family that v16
// closed for the HRP.
//
// The Shelley matcher also had a length hole: its body floor of 50 characters
// excluded every 29-byte Shelley address — all reward (`stake1…`) and
// enterprise addresses, which are 47 characters ahead of the 6-character
// checksum. See `this.i:n3twrkq` and `this.i:sh3lley29`.

import (
	"strings"
	"testing"
)

type networkCase struct {
	value   string
	network string
	label   string
}

var networkCases = []networkCase{
	{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet", "BTC, bc1"},
	{"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet", "BTC, testnet, tb1"},
	{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "mainnet", "BTC, 1"},
	{"mfWyW5fc9NUj75YAnFgoRLrjxgLDn2MMth", "testnet", "BTC, testnet, m"},
	{"ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", "mainnet", "LTC, ltc1"},
	{"bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "mainnet", "BCH, bitcoincash:"},
	{"bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap", "testnet", "BCH, testnet, bchtest:"},
	{"stake1uyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcwfvml6", "mainnet", "ADA, stake1"},
	{"stake_test1uqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcfrxem8", "testnet", "ADA, testnet, stake_test1"},
}

func labelOf(t *testing.T, value string) string {
	t.Helper()
	ch, err := Characterize(value)
	if err != nil {
		t.Fatalf("Characterize(%q): %v", value, err)
	}
	top, _ := ch.RenderLabel(false, "", "", -1)
	return top
}

func TestNetworkIsReadFromThePrefix(t *testing.T) {
	for _, c := range networkCases {
		ch, err := Characterize(c.value)
		if err != nil {
			t.Fatalf("Characterize(%q): %v", c.value, err)
		}
		if got := qStr(ch.Qualifiers, "network"); got != c.network {
			t.Errorf("network for %q = %q, want %q", c.value, got, c.network)
		}
		if got := labelOf(t, c.value); got != c.label {
			t.Errorf("label for %q = %q, want %q", c.value, got, c.label)
		}
	}
}

func TestTestnetIsLoudAndMainnetIsSilent(t *testing.T) {
	// The v14 label rule, restated as a property so it cannot rot: the word
	// appears in the label exactly when the network departs from mainnet.
	for _, c := range networkCases {
		loud := strings.Contains(c.label, "testnet")
		if loud != (c.network == "testnet") {
			t.Errorf("%q: label %q vs network %q disagree on loudness", c.value, c.label, c.network)
		}
	}
}

func TestATestnetAddressNeverLabelsLikeItsMainnetTwin(t *testing.T) {
	// The defect, stated directly. These two share a payload and differ only
	// in the network; before v17 both read "BTC, ...", separable only by the
	// small prefix slot, and their characterizations were byte-identical.
	main := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	test := "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
	pm, err := Parse(main)
	if err != nil {
		t.Fatalf("Parse(%q): %v", main, err)
	}
	pt, err := Parse(test)
	if err != nil {
		t.Fatalf("Parse(%q): %v", test, err)
	}
	if pm.Core != pt.Core {
		t.Fatalf("premise: one payload; got %q vs %q", pm.Core, pt.Core)
	}
	cm, err := Characterize(main)
	if err != nil {
		t.Fatalf("Characterize(%q): %v", main, err)
	}
	ct, err := Characterize(test)
	if err != nil {
		t.Fatalf("Characterize(%q): %v", test, err)
	}
	if cm.QualifiersJSON() == ct.QualifiersJSON() {
		t.Errorf("qualifiers identical across networks: %s", cm.QualifiersJSON())
	}
	if labelOf(t, main) == labelOf(t, test) {
		t.Errorf("labels identical across networks: %q", labelOf(t, main))
	}
}

func TestByronClaimsNoNetwork(t *testing.T) {
	// Deliberate: a Byron address's network magic is inside the CBOR payload,
	// which this parser does not decode — the same reason its CRC-32 goes
	// unverified. Asserting mainnet would be a guess dressed as a fact.
	for _, value := range []string{
		"Ae2tdPwUPEZ7SZaSCeU8sGZXGZ7YrVc96FnzYdZcLkbry4CqUKax9dNeEoe",
		"DdzFFzCqrht1D2Tv5F9HLtZHEd4P9Tddf9DFv3d4KXa2RxudcL4uHKWtc2HfiDopch5UHyZkXQx7",
	} {
		ch, err := Characterize(value)
		if err != nil {
			t.Fatalf("Characterize(%q): %v", value, err)
		}
		if ch.Scheme == nil || *ch.Scheme != "ada" {
			t.Errorf("scheme for %q = %v, want ada", value, ch.Scheme)
		}
		if got := ch.QualifiersJSON(); got != `{"variant":"byron"}` {
			t.Errorf("qualifiers for %q = %s, want only variant=byron", value, got)
		}
		if strings.Contains(labelOf(t, value), "testnet") {
			t.Errorf("Byron label for %q claims a network: %q", value, labelOf(t, value))
		}
	}
}

// --- the Shelley 29-byte hole -----------------------------------------------

func TestTwentyNineByteShelleyAddressesReachTheCardanoParser(t *testing.T) {
	// Before v17 the mainnet form fell through to the generic bech32 parser
	// (scheme "bech32"), and the testnet form did not parse as bech32 at all —
	// `stake_test` contains `_`, outside the generic parser's [a-z] HRP
	// charset, so it landed on the base64url fallback with no scheme and no
	// checksum verification. Both are 47 body characters, under the old floor
	// of 50.
	for _, value := range []string{
		"stake1uyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcwfvml6",
		"stake_test1uqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcfrxem8",
	} {
		p, err := Parse(value)
		if err != nil {
			t.Fatalf("Parse(%q): %v", value, err)
		}
		if p == nil {
			t.Fatalf("Parse(%q) = nil", value)
		}
		if p.TypeName != "ADA Shelley" {
			t.Errorf("type for %q = %q, want ADA Shelley", value, p.TypeName)
		}
		if !p.PrefixSemantic {
			t.Errorf("prefix for %q is not semantic", value)
		}
		ch, err := Characterize(value)
		if err != nil {
			t.Fatalf("Characterize(%q): %v", value, err)
		}
		if ch.Scheme == nil || *ch.Scheme != "ada" {
			t.Errorf("scheme for %q = %v, want ada", value, ch.Scheme)
		}
	}
}

func TestThe57ByteBaseAddressStillParses(t *testing.T) {
	// The floor moved from 50 to 45; the long form must be unaffected.
	value := "addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xmyv4nxw6rfdf4kc" +
		"mtwdac8zunnw36hvamc09a8klra0elsr0jfpr"
	p, err := Parse(value)
	if err != nil {
		t.Fatalf("Parse(%q): %v", value, err)
	}
	if p == nil || p.TypeName != "ADA Shelley" {
		t.Errorf("type for the 57-byte base address = %v, want ADA Shelley", p)
	}
}
