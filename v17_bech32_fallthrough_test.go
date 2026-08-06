// v17 correction: the GENERIC bech32 path claims less.
//
// v14 made a structural `<hrp>1<data>` match with a failing polymod REJECT,
// reasoning that 8+ bech32 data characters after a lowercase HRP was "a clear
// bech32 structural match". The premise was false and the cost was measurable:
// 34 of 3000 random short hex strings (~1.1%) matched by accident and were
// refused outright — ordinary values entviz would not render at all.
//
// Two changes, one principle: do not claim a scheme you cannot substantiate.
// The data floor rises from 8 characters to 32 (data INCLUDING its 6-character
// checksum), and a failing polymod falls through instead of rejecting. Both are
// needed — the floor alone leaves a smaller version of the same bug, and the
// fall-through alone leaves the parser making a claim it cannot support.
//
// Rejection stays for the NAMED schemes (bc1/tb1, ltc1, addr1/stake1,
// bitcoincash:/bchtest:), where the prefix is a genuine signal; that is covered
// by TestV14ChecksumRejection in entropy_test.go.
//
// See `this.i:b3ch32fl` and docs/spec.md "Checksum verification".

package entviz

import "testing"

// A bad polymod on the generic path falls through to the alphabet ladder rather
// than erroring. Mirrors the corpus render vector
// cosmos-bad-checksum-falls-through (last char e->f), whose label reads
// "base58, 264-bit".
func TestV17GenericBech32BadPolymodFallsThrough(t *testing.T) {
	const bad = "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363f"
	p, err := Parse(bad)
	if err != nil {
		t.Fatalf("Parse(%q) = %v, want fall-through (no error)", bad, err)
	}
	// It still never renders AS an address: the label reports the encoding
	// actually recognized, so a reader comparing against a known-good address
	// sees a different type name and a different picture.
	if p.TypeName == "bech32" {
		t.Errorf("type = %q, want anything but bech32", p.TypeName)
	}
	if p.TypeName != "base58" {
		t.Errorf("type = %q, want base58 (the corpus vector's label is %q)",
			p.TypeName, "base58, 264-bit")
	}
	if p.Prefix != nil {
		t.Errorf("prefix = %q, want nil — no HRP was substantiated", *p.Prefix)
	}
}

// The 32-character data floor. `dee1ad37cf96` is one of the measured false
// rejects: `dee` + `1` + 8 bech32 characters matched the old floor, failed the
// polymod, and was refused. It is a real hex value and must render as hex.
// Mirrors the corpus render vector hex-bech32-shaped ("hex, 48-bit").
func TestV17BechShapedHexParsesAsHex(t *testing.T) {
	for _, in := range []string{"dee1ad37cf96", "a15c77a2f24e", "c13a004ecf7d"} {
		p, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q) = %v, want a hex parse", in, err)
			continue
		}
		if p.TypeName != "hex" {
			t.Errorf("Parse(%q) type = %q, want hex", in, p.TypeName)
		}
	}
}

// The floor is on the data part INCLUDING its 6-character checksum, which is
// what the reference's regex group bounds. A 31-character data part is not a
// bech32 claim; 32 is the smallest that may be.
func TestV17GenericBech32DataFloorIs32(t *testing.T) {
	const hrp = "cosmos1"
	// All-`q` data is in the bech32 charset and will not verify, so anything
	// that survives the floor falls through — the point here is only that the
	// short form never reaches the polymod as a bech32 claim.
	for _, n := range []int{8, 31} {
		in := hrp + repeatQ(n)
		p, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q) (%d data chars) = %v, want fall-through", in, n, err)
			continue
		}
		if p.TypeName == "bech32" {
			t.Errorf("Parse(%q) (%d data chars) typed as bech32; the floor is 32", in, n)
		}
	}
}

// A valid generic bech32 address is unaffected by the correction.
func TestV17GenericBech32StillParsesWhenValid(t *testing.T) {
	const good = "cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnrk363e"
	p := mustParse(t, good)
	if p.TypeName != "bech32" {
		t.Errorf("type = %q, want bech32", p.TypeName)
	}
	if p.Prefix == nil || *p.Prefix != "cosmos1" {
		t.Errorf("prefix = %v, want cosmos1", p.Prefix)
	}
	if p.Suffix == nil || *p.Suffix != "rk363e" {
		t.Errorf("suffix = %v, want rk363e (the verified 6-char checksum)", p.Suffix)
	}
}

func repeatQ(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'q'
	}
	return string(b)
}
