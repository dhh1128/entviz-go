package entviz

import (
	"strings"
	"testing"
)

func TestTokenizeHex(t *testing.T) {
	toks := Tokenize("0123456789abcdef", HEX)
	if len(toks) != 3 {
		t.Fatalf("len = %d, want 3", len(toks))
	}
	if toks[0].Text != "012345" {
		t.Errorf("toks[0].Text = %q, want 012345", toks[0].Text)
	}
	if toks[0].Quant != 0x012345 {
		t.Errorf("toks[0].Quant = %#x, want 0x012345", toks[0].Quant)
	}
}

func TestTokenizeQuantExtension(t *testing.T) {
	toks := Tokenize("ab", HEX) // 0xAB -> 0xABABAB
	if toks[0].Quant != 0xABABAB {
		t.Errorf("Quant = %#x, want 0xABABAB", toks[0].Quant)
	}
}

func TestTokenizeEmpty(t *testing.T) {
	if len(Tokenize("", HEX)) != 0 {
		t.Error("tokenize of empty must be empty")
	}
}

func TestTokenizeIndicesSequential(t *testing.T) {
	toks := Tokenize("0123456789abcdef", HEX)
	for i, tok := range toks {
		if tok.Index != i {
			t.Errorf("toks[%d].Index = %d", i, tok.Index)
		}
	}
}

func TestTokenizeUnknownCharIsZero(t *testing.T) {
	toks := Tokenize("!!!!!!", HEX)
	if len(toks) != 1 || toks[0].Quant != 0 {
		t.Errorf("unknown chars -> %v", toks)
	}
}

func TestTokenizeBase64urlSpecial(t *testing.T) {
	toks := Tokenize("ab-_", BASE64URL)
	if len(toks) != 1 {
		t.Fatalf("len = %d", len(toks))
	}
	expected := (uint32(26) << 18) | (uint32(27) << 12) | (uint32(62) << 6) | uint32(63)
	if toks[0].Quant != expected&0xFFFFFF {
		t.Errorf("Quant = %#x, want %#x", toks[0].Quant, expected&0xFFFFFF)
	}
}

func TestCharValue(t *testing.T) {
	tests := []struct {
		chars string
		ch    rune
		bits  uint
		want  int
	}{
		{HEX.Chars, 'A', 4, 10},
		{HEX.Chars, 'a', 4, 10},
		{BASE64URL.Chars, '-', 6, 62},
		{BASE64URL.Chars, '_', 6, 63},
		{BASE64URL.Chars, '+', 6, 62},
		{BASE64URL.Chars, '/', 6, 63},
		{BASE64URL.Chars, '!', 6, -1},
		{HEX.Chars, 'z', 4, -1},
	}
	for _, tt := range tests {
		if got := charValue(tt.chars, strings.ToLower(tt.chars), tt.ch, tt.bits); got != tt.want {
			t.Errorf("charValue(%q, %q, %d) = %d, want %d", tt.chars, tt.ch, tt.bits, got, tt.want)
		}
	}
}

func TestFingerprint22Ftoks(t *testing.T) {
	d := ComputeFingerprint("hello")
	if len(TokenizeFingerprint(d)) != 22 {
		t.Error("expected 22 ftoks")
	}
}

func TestFingerprintDeterministicDistinct(t *testing.T) {
	if ComputeFingerprint("hello") != ComputeFingerprint("hello") {
		t.Error("fingerprint not deterministic")
	}
	if ComputeFingerprint("hello") == ComputeFingerprint("hellp") {
		t.Error("fingerprints must differ")
	}
}

func TestSecondDigestDomainSeparated(t *testing.T) {
	if SecondDigest("hello") == ComputeFingerprint("hello") {
		t.Error("second digest must be domain-separated from primary")
	}
	if SecondDigest("x") != SecondDigest("x") {
		t.Error("second digest not deterministic")
	}
}

func TestMedianEmptyIsNone(t *testing.T) {
	if _, ok := MedianToken(nil); ok {
		t.Error("median of empty must be absent")
	}
}

func TestQuartileEmptyIsFourNones(t *testing.T) {
	q := QuartileTokens(nil)
	if len(q) != 4 {
		t.Fatalf("len = %d", len(q))
	}
	for _, x := range q {
		if x != nil {
			t.Error("expected nil quartile slot")
		}
	}
}

func TestNucleusColors(t *testing.T) {
	bg, fg := NucleusColors(0x452301)
	if bg != "#012345" {
		t.Errorf("bg = %s, want #012345", bg)
	}
	if fg != "#ffffff" {
		t.Errorf("fg = %s, want #ffffff", fg)
	}
	bg2, fg2 := NucleusColors(0x00ffff) // r=ff g=ff b=00 -> #ffff00
	if bg2 != "#ffff00" || fg2 != "#000000" {
		t.Errorf("bright yellow -> (%s,%s)", bg2, fg2)
	}
}

func TestOklabExtremes(t *testing.T) {
	if OklabLightness(255, 255, 255) <= 0.99 {
		t.Error("white lightness too low")
	}
	if OklabLightness(0, 0, 0) >= 0.01 {
		t.Error("black lightness too high")
	}
	mid := OklabLightness(128, 128, 128)
	if mid <= 0.3 || mid >= 0.8 {
		t.Errorf("mid grey lightness = %f", mid)
	}
}

func TestWeightedRGBDistance(t *testing.T) {
	if WeightedRGBDistance("#123456", "#123456") != 0.0 {
		t.Error("equal colors must have zero distance")
	}
	if WeightedRGBDistance("#000000", "#ffffff") <= 0 {
		t.Error("distinct colors must have positive distance")
	}
}

func TestClosestPaletteColor(t *testing.T) {
	palette := []string{"#ffffff", "#000000", "#ff0000"}
	tests := []struct{ target, want string }{
		{"#fefefe", "#ffffff"},
		{"#010101", "#000000"},
		{"#fe0000", "#ff0000"},
	}
	for _, tt := range tests {
		if got := ClosestPaletteColor(tt.target, palette); got != tt.want {
			t.Errorf("ClosestPaletteColor(%s) = %s, want %s", tt.target, got, tt.want)
		}
	}
}

func TestSelectVisualStyleAllFourBg(t *testing.T) {
	for idx := uint32(0); idx < 4; idx++ {
		ftok := Token{Text: "x", Index: 0, Quant: idx}
		style := SelectVisualStyle(ftok)
		if style.BgColor != PossibleEdgeColors[idx] {
			t.Errorf("idx %d bg = %s", idx, style.BgColor)
		}
		if len(style.EdgeColors) != 4 {
			t.Errorf("idx %d edge count = %d", idx, len(style.EdgeColors))
		}
		for _, c := range style.EdgeColors {
			if c == style.BgColor {
				t.Errorf("edge colors must exclude bg")
			}
		}
	}
}

func TestChooseGrid(t *testing.T) {
	g := ChooseGrid(11, 1.0)
	if g.Cols != 3 || g.Rows != 4 {
		t.Errorf("choose_grid(11,1.0) = %dx%d, want 3x4", g.Cols, g.Rows)
	}
	// degenerate counts fall back to 2x2
	for _, tc := range []int{0, 1} {
		g := ChooseGrid(tc, 1.0)
		if g.Cols != 2 || g.Rows != 2 {
			t.Errorf("choose_grid(%d) = %dx%d, want 2x2", tc, g.Cols, g.Rows)
		}
	}
	// tall target prefers tall (fewer cols)
	wide := ChooseGrid(12, 5.0)
	tall := ChooseGrid(12, 0.2)
	if wide.Cols < tall.Cols {
		t.Errorf("wide.Cols (%d) < tall.Cols (%d)", wide.Cols, tall.Cols)
	}
}
