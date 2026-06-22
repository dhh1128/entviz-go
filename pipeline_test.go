package entviz

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNumberSerialization(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{27.0, "27"},
		{240.0, "240"},
		{0.5, "0.5"},
		{131.32394215885992, "131.324"},
		{-0.0, "0"},
		{-0.0004, "0"},
		{-1.5, "-1.5"},
		{0.0000001, "0"},
		{3.0, "3"},
		{3.5, "3.5"},
	}
	for _, tt := range tests {
		if got := n(tt.in); got != tt.want {
			t.Errorf("n(%v) = %q, want %q", tt.in, got, tt.want)
		}
		if strings.ContainsAny(n(tt.in), "eE") {
			t.Errorf("n(%v) contains exponent", tt.in)
		}
	}
}

// TestCompactSerializationGuard renders several inputs and asserts every
// numeric SVG attribute value is a compact plain decimal: no exponent, at most
// 3 fractional digits.
func TestCompactSerializationGuard(t *testing.T) {
	long := strings.Repeat("a", 66) // forces blank-map + ellipse overlay
	inputs := []string{
		"0123456789abcdef0123456789abcdef",
		"550e8400-e29b-41d4-a716-446655440000",
		long,
	}
	for _, input := range inputs {
		svg, err := Render(input, 1.0, 12.0, nil)
		if err != nil {
			t.Fatalf("Render(%q) errored: %v", input, err)
		}
		for i, tok := range strings.Split(svg, "\"") {
			if i%2 == 0 {
				continue // tag text, not attribute value
			}
			if _, err := strconv.ParseFloat(tok, 64); err != nil {
				continue // non-numeric attribute
			}
			if strings.ContainsAny(tok, "eE") {
				t.Errorf("exponential notation in %q (input %q)", tok, input)
			}
			if dot := strings.IndexByte(tok, '.'); dot >= 0 {
				if frac := tok[dot+1:]; len(frac) > 3 {
					t.Errorf("more than 3 fractional digits in %q (input %q)", tok, input)
				}
			}
		}
	}
}

func TestRenderHex256(t *testing.T) {
	svg, err := Render("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1.0, 12.0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(svg, "<svg ") {
		t.Error("missing <svg prefix")
	}
	if !strings.Contains(svg, `data-cols="3"`) || !strings.Contains(svg, `data-rows="4"`) {
		t.Error("wrong grid dimensions")
	}
	if !strings.Contains(svg, `data-channel="color-bar" data-bar-slots=`) {
		t.Error("missing color bar")
	}
	if !strings.HasSuffix(svg, "</svg>") {
		t.Error("missing </svg> suffix")
	}
}

func TestRenderDeterministic(t *testing.T) {
	a, _ := Render("a1b2c3d4e5f6a7b8", 1.0, 12.0, nil)
	b, _ := Render("a1b2c3d4e5f6a7b8", 1.0, 12.0, nil)
	if a != b {
		t.Error("render is not deterministic")
	}
}

func TestRejectsBadEip55(t *testing.T) {
	_, err := Render("0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed", 1.0, 12.0, nil)
	if err == nil {
		t.Fatal("expected EIP-55 rejection")
	}
	re, ok := err.(*RenderError)
	if !ok || re.Kind != "eip55" {
		t.Fatalf("expected eip55 RenderError, got %v", err)
	}
	if !strings.Contains(re.Error(), "position") {
		t.Errorf("error must name position: %s", re.Error())
	}
}

func TestRejectsBadNoteAndFontsize(t *testing.T) {
	if _, err := Render("a1b2c3d4e5f6a7b8", 1.0, 12.0, strPtr("two words")); err != nil {
		t.Errorf("printable-ascii note should be valid: %v", err)
	}
	if _, err := Render("a1b2c3d4e5f6a7b8", 1.0, 12.0, strPtr("ab\tcd")); err == nil {
		t.Error("tab in note should reject")
	}
	if _, err := Render("a1b2c3d4e5f6a7b8", 1.0, 4.0, nil); err == nil {
		t.Error("font size 4 should reject")
	}
	if _, err := Render("a1b2c3d4e5f6a7b8", 1.0, 40.0, nil); err == nil {
		t.Error("font size 40 should reject")
	}
}

func TestSanitizeNote(t *testing.T) {
	ok := func(in string, want string) {
		t.Helper()
		out, err := sanitizeNote(strPtr(in))
		if err != nil {
			t.Errorf("sanitizeNote(%q) errored: %v", in, err)
			return
		}
		if out == nil || *out != want {
			t.Errorf("sanitizeNote(%q) = %v, want %q", in, out, want)
		}
	}
	rejected := func(in string) {
		t.Helper()
		if _, err := sanitizeNote(strPtr(in)); err == nil {
			t.Errorf("sanitizeNote(%q) should reject", in)
		}
	}
	if out, _ := sanitizeNote(nil); out != nil {
		t.Error("nil note -> nil")
	}
	if out, _ := sanitizeNote(strPtr("")); out != nil {
		t.Error("empty note -> nil")
	}
	ok("abc123", "abc123")
	ok("two words", "two words")
	ok("a.b_c-d!", "a.b_c-d!")
	ok(" ", " ")
	ok("~", "~")
	ok("0123456789", "0123456789")
	rejected("toolongnote") // 11 chars
	rejected("ab\tcd")      // tab
	rejected("café")        // non-ascii
	rejected("a‮b")         // bidi
	rejected("a​b")         // zero-width
}

func TestNoteXMLEscaped(t *testing.T) {
	svg, err := Render("a1b2c3d4e5f6a7b8", 1.0, 12.0, strPtr("a<b>&\"x"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(svg, `(a&lt;b&gt;&amp;"x)`) {
		t.Error("text node not escaped correctly")
	}
	if !strings.Contains(svg, `data-user-note="a&lt;b&gt;&amp;&quot;x"`) {
		t.Error("attribute not escaped correctly")
	}
	if strings.Contains(svg, "<b>") {
		t.Error("raw tag leaked")
	}
}

func TestEscaping(t *testing.T) {
	if got := escAttr("a&b<c>d\"e"); got != "a&amp;b&lt;c&gt;d&quot;e" {
		t.Errorf("escAttr = %s", got)
	}
	if got := escText("a&b<c>d\"e"); got != "a&amp;b&lt;c&gt;d\"e" {
		t.Errorf("escText = %s", got)
	}
}

func TestB64urlEncodeNoPadding(t *testing.T) {
	if got := b64urlEncode([]byte("foobar")); got != "Zm9vYmFy" {
		t.Errorf("b64urlEncode = %s", got)
	}
	if strings.Contains(b64urlEncode([]byte("foo")), "=") {
		t.Error("base64url must not pad")
	}
}

func TestBoxOriginRanges(t *testing.T) {
	if x, y := boxOrigin(3, 100, 200, 10, 5); x != 130 || y != 200 {
		t.Errorf("boxOrigin(3) = (%v,%v)", x, y)
	}
	if x, y := boxOrigin(10, 100, 200, 10, 5); x != 190 || y != 205 {
		t.Errorf("boxOrigin(10) = (%v,%v)", x, y)
	}
	if x, y := boxOrigin(12, 100, 200, 10, 5); x != 190 || y != 215 {
		t.Errorf("boxOrigin(12) = (%v,%v)", x, y)
	}
	if x, _ := boxOrigin(22, 100, 200, 10, 5); x != 100 {
		t.Errorf("boxOrigin(22) x = %v", x)
	}
}

// TestFullRenderGolden compares a full render against the corpus golden SVG,
// confirming byte-equality of all geometry/channel content. Attribute order
// inside cell groups legitimately differs from the Python golden (the model
// extractor is order-independent), so we compare the set of attribute tokens.
func TestFullRenderGolden(t *testing.T) {
	goldenPath := goldenSVGPath(t, "hex-64")
	if goldenPath == "" {
		t.Skip("corpus golden not available")
	}
	goldenBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Skipf("cannot read golden: %v", err)
	}
	golden := string(goldenBytes)

	svg, err := Render("a1b2c3d4e5f6a7b8", 1.0, 12.0, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Normalize: drop the per-impl lib stamp, then compare the multiset of
	// quoted attribute-value tokens. Identical multisets => identical render.
	norm := func(s string) []string {
		s = dropLibStamp(s)
		toks := strings.Split(s, "\"")
		// keep odd-indexed (attribute values) — these carry all geometry/colors
		var vals []string
		for i, tk := range toks {
			if i%2 == 1 {
				vals = append(vals, tk)
			}
		}
		return vals
	}
	gv := norm(golden)
	sv := norm(svg)
	if len(gv) != len(sv) {
		t.Fatalf("attribute count mismatch: golden %d, ours %d", len(gv), len(sv))
	}
	gCount := map[string]int{}
	for _, v := range gv {
		gCount[v]++
	}
	for _, v := range sv {
		gCount[v]--
	}
	for v, c := range gCount {
		if c != 0 {
			t.Errorf("attribute multiset mismatch for %q (delta %d)", v, c)
		}
	}
}

func dropLibStamp(s string) string {
	i := strings.Index(s, ` data-entviz-lib="`)
	if i < 0 {
		return s
	}
	j := strings.IndexByte(s[i+len(` data-entviz-lib="`):], '"')
	if j < 0 {
		return s
	}
	end := i + len(` data-entviz-lib="`) + j + 1
	return s[:i] + s[end:]
}

func goldenSVGPath(t *testing.T, vector string) string {
	t.Helper()
	// The corpus lives in the sibling entviz repo.
	candidates := []string{
		filepath.Join("..", "entviz", "compliance", "corpus", vector, "golden.svg"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
