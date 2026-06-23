// Package entviz renders high-entropy values as comparable SVG fingerprints
// (entviz, spec v10). It is a Go port of the certified reference
// implementation; see https://github.com/dhh1128/entviz for the spec.
//
// The deterministic shared core lives here: alphabets, tokenization + 24-bit
// quant extension, the SHA-512 fingerprint, ftok median/quartile selection, the
// Oklab color rules + weighted-RGB edge selection, and grid selection. The
// format-specific parsers live in entropy.go and the SVG renderer in
// pipeline.go.
package entviz

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math"
	"sort"
	"strings"
)

// SpecVersion is the entviz spec level this library implements.
const SpecVersion = "v11"

// LibVersion is this Go module's own version stamp. It is per-impl and is not
// compared by the conformance checker (only data-entviz-version is).
const LibVersion = "0.11.0"

// Alphabet describes a character set and its tokenization density.
type Alphabet struct {
	Name        string
	Chars       string
	BitsPerChar uint
}

// Canonical alphabet constants used across the core and parsers.
var (
	HEX = Alphabet{
		Name:        "hex",
		Chars:       "0123456789ABCDEF",
		BitsPerChar: 4,
	}
	BASE64URL = Alphabet{
		Name:        "base64url",
		Chars:       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		BitsPerChar: 6,
	}
	BASE58 = Alphabet{
		Name:        "base58",
		Chars:       "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
		BitsPerChar: 6,
	}
	BASE64 = Alphabet{
		Name:        "base64",
		Chars:       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
		BitsPerChar: 6,
	}
	BASE32 = Alphabet{
		Name:        "base32",
		Chars:       "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		BitsPerChar: 5,
	}
	BECH32 = Alphabet{
		Name:        "bech32",
		Chars:       "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
		BitsPerChar: 5,
	}
	CROCKFORD32 = Alphabet{
		Name:        "crockford32",
		Chars:       "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
		BitsPerChar: 5,
	}
	BASE36 = Alphabet{
		Name:        "base36",
		Chars:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		BitsPerChar: 6,
	}
	DECIMAL = Alphabet{
		Name:        "decimal",
		Chars:       "0123456789",
		BitsPerChar: 4,
	}
)

// Token is one rendered chunk of entropy (or one ftok of a fingerprint).
type Token struct {
	Text  string
	Index int
	Quant uint32
}

// charValue maps a character to its position in an alphabet, with case folding
// and the base64/base64url special-character aliases. Returns -1 when unknown.
// lowerChars must be strings.ToLower(chars), precomputed once by the caller so
// the lowercased alphabet is not recomputed on every character lookup.
func charValue(chars, lowerChars string, ch rune, bitsPerChar uint) int {
	if i := strings.IndexRune(chars, ch); i >= 0 {
		return i
	}
	if i := strings.IndexRune(lowerChars, toLowerRune(ch)); i >= 0 {
		return i
	}
	if bitsPerChar == 6 {
		switch ch {
		case '-', '+':
			return 62
		case '_', '/':
			return 63
		}
	}
	return -1
}

func toLowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// Tokenize splits text into 24-bit tokens under the given alphabet, extending
// short trailing chunks to a full 24-bit quant by the bit-repeat rule.
func Tokenize(text string, alphabet Alphabet) []Token {
	bitsPerChar := alphabet.BitsPerChar
	tokenLen := int(24 / bitsPerChar)
	lowerAlphabet := strings.ToLower(alphabet.Chars)
	chars := []rune(text)
	var tokens []Token
	i := 0
	for i < len(chars) {
		end := i + tokenLen
		if end > len(chars) {
			end = len(chars)
		}
		chunk := string(chars[i:end])
		i = end
		if chunk == "" {
			continue
		}
		var val uint32
		var actualBits uint
		for _, ch := range chunk {
			cv := charValue(alphabet.Chars, lowerAlphabet, ch, bitsPerChar)
			if cv == -1 {
				cv = 0
			}
			val = (val << bitsPerChar) | uint32(cv)
			actualBits += bitsPerChar
		}
		quant := val
		if actualBits > 0 && actualBits < 24 {
			for actualBits < 24 {
				shift := actualBits
				if 24-actualBits < shift {
					shift = 24 - actualBits
				}
				mask := (uint32(1) << shift) - 1
				add := quant & mask
				quant = (quant << shift) | add
				actualBits += shift
			}
		} else if actualBits > 24 {
			quant = val & 0xFFFFFF
		}
		tokens = append(tokens, Token{
			Text:  chunk,
			Index: len(tokens),
			Quant: quant & 0xFFFFFF,
		})
	}
	return tokens
}

// ComputeFingerprint returns the SHA-512 digest of the core text bytes.
func ComputeFingerprint(core string) [64]byte {
	return sha512.Sum512([]byte(core))
}

// MiddleDomainTag is the frozen domain-separation constant for the second
// digest. The trailing NUL is included; the v6 here is the *construction*
// version (frozen), NOT the spec version — see the spec's large-input section.
var MiddleDomainTag = []byte("entviz/fingerprint-middle/v6\x00")

// SecondDigest returns SHA-512(MiddleDomainTag ‖ core). Computed for every
// input: it drives the two color-bar markers (and the middle cells on large
// inputs).
func SecondDigest(core string) [64]byte {
	h := sha512.New()
	h.Write(MiddleDomainTag)
	h.Write([]byte(core))
	var d [64]byte
	copy(d[:], h.Sum(nil))
	return d
}

var b64urlNoPad = base64.URLEncoding.WithPadding(base64.NoPadding)

// TokenizeFingerprint serializes the 64-byte digest to base64url and splits it
// into the 22 ftoks the spec guarantees.
func TokenizeFingerprint(digest [64]byte) []Token {
	enc := b64urlNoPad.EncodeToString(digest[:])
	toks := Tokenize(enc, BASE64URL)
	if len(toks) != 22 {
		panic(fmt.Sprintf("expected 22 ftoks, got %d", len(toks)))
	}
	return toks
}

// MedianToken returns the lower-middle token of the ASCII text-sorted list.
func MedianToken(tokens []Token) (Token, bool) {
	if len(tokens) == 0 {
		return Token{}, false
	}
	s := make([]Token, len(tokens))
	copy(s, tokens)
	sort.SliceStable(s, func(a, b int) bool {
		if s[a].Text != s[b].Text {
			return s[a].Text < s[b].Text
		}
		return s[a].Index < s[b].Index
	})
	mid := (len(s) - 1) / 2
	return s[mid], true
}

// QuartileTokens returns the first token of each of the four mirror-sorted
// quartiles; a slot is absent (ok=false) when it would fall in padding.
func QuartileTokens(tokens []Token) []*Token {
	if len(tokens) == 0 {
		return []*Token{nil, nil, nil, nil}
	}
	rev := func(s string) string {
		r := []rune(s)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r)
	}
	s := make([]Token, len(tokens))
	copy(s, tokens)
	sort.SliceStable(s, func(a, b int) bool {
		ra, rb := rev(s[a].Text), rev(s[b].Text)
		if ra != rb {
			return ra < rb
		}
		return s[a].Index < s[b].Index
	})
	qSize := (len(s) + 3) / 4 // ceil(n/4)
	out := make([]*Token, 4)
	for i := 0; i < 4; i++ {
		idx := i * qSize
		if idx < len(s) {
			t := s[idx]
			out[i] = &t
		}
	}
	return out
}

// PossibleEdgeColors is the fixed palette; indices 0-3 are background
// candidates, black (index 4) is always an edge color.
var PossibleEdgeColors = [5]string{"#ffffff", "#e7be00", "#ff3f2f", "#2f3fbf", "#000000"}

func srgbToLinear(c float64) float64 {
	if c <= 0.04045 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

// OklabLightness returns the Oklab L of an sRGB color.
func OklabLightness(r, g, b uint8) float64 {
	rl := srgbToLinear(float64(r) / 255.0)
	gl := srgbToLinear(float64(g) / 255.0)
	bl := srgbToLinear(float64(b) / 255.0)
	l := 0.4122214708*rl + 0.5363325363*gl + 0.0514459929*bl
	m := 0.2119034982*rl + 0.6806995451*gl + 0.1073969566*bl
	s := 0.0883024619*rl + 0.2817188376*gl + 0.6299787005*bl
	return 0.2104542553*math.Cbrt(l) + 0.793617785*math.Cbrt(m) - 0.0040720468*math.Cbrt(s)
}

const oklabThreshold = 0.6

// NucleusColors returns (bgHex, fgHex). Red is the low byte of the quant.
func NucleusColors(quant uint32) (string, string) {
	r := uint8(quant & 0xFF)
	g := uint8((quant >> 8) & 0xFF)
	b := uint8((quant >> 16) & 0xFF)
	bg := fmt.Sprintf("#%02x%02x%02x", r, g, b)
	fg := "#000000"
	if OklabLightness(r, g, b) < oklabThreshold {
		fg = "#ffffff"
	}
	return bg, fg
}

func hexToRGB(h string) (int64, int64, int64) {
	return parseHexByte(h[1:3]), parseHexByte(h[3:5]), parseHexByte(h[5:7])
}

func parseHexByte(s string) int64 {
	var v int64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int64(c-'A') + 10
		}
	}
	return v
}

// WeightedRGBDistance is the spec's cheap CIELAB ΔE stand-in for edge selection.
func WeightedRGBDistance(c1, c2 string) float64 {
	r1, g1, b1 := hexToRGB(c1)
	r2, g2, b2 := hexToRGB(c2)
	dr, dg, db := r1-r2, g1-g2, b1-b2
	return math.Sqrt(float64(2*dr*dr + 4*dg*dg + 3*db*db))
}

// ClosestPaletteColor returns the palette entry with minimum weighted distance.
func ClosestPaletteColor(target string, palette []string) string {
	best := palette[0]
	bestD := math.Inf(1)
	for _, c := range palette {
		d := WeightedRGBDistance(c, target)
		if d < bestD {
			bestD = d
			best = c
		}
	}
	return best
}

// VisualStyle is the entviz background plus the 4-entry edge palette.
type VisualStyle struct {
	BgColor    string
	EdgeColors []string
}

// SelectVisualStyle picks the background from the median ftok's low 2 bits and
// forms the edge palette from the remaining four colors.
func SelectVisualStyle(medianFtok Token) VisualStyle {
	idx := int(medianFtok.Quant & 0x03)
	bg := PossibleEdgeColors[idx]
	var edges []string
	for i, c := range PossibleEdgeColors {
		if i != idx {
			edges = append(edges, c)
		}
	}
	return VisualStyle{BgColor: bg, EdgeColors: edges}
}

// Grid is the chosen layout.
type Grid struct {
	Cols       int
	Rows       int
	TokenCount int
}

// ChooseGrid selects the layout whose aspect ratio is closest to (but not below)
// the target, with at least 2 columns and 2 rows.
func ChooseGrid(tokenCount int, targetAR float64) Grid {
	// rows -> tightest (smallest) cols for that row count.
	tightest := map[int]int{}
	for cols := 2; cols <= tokenCount; cols++ {
		rows := (tokenCount + cols - 1) / cols // ceil
		if rows >= 2 {
			if c, ok := tightest[rows]; !ok || cols < c {
				tightest[rows] = cols
			}
		}
	}
	type cand struct {
		cols, rows int
		ar         float64
	}
	var candidates []cand
	// Deterministic ordering over rows.
	rowsKeys := make([]int, 0, len(tightest))
	for r := range tightest {
		rowsKeys = append(rowsKeys, r)
	}
	sort.Ints(rowsKeys)
	for _, rows := range rowsKeys {
		cols := tightest[rows]
		candidates = append(candidates, cand{cols, rows, float64(cols*3) / float64(rows*2)})
	}
	if len(candidates) == 0 {
		return Grid{Cols: 2, Rows: 2, TokenCount: tokenCount}
	}
	var chosen *cand
	for i := range candidates {
		if candidates[i].ar >= targetAR {
			if chosen == nil || (candidates[i].ar-targetAR) < (chosen.ar-targetAR) {
				chosen = &candidates[i]
			}
		}
	}
	if chosen == nil {
		// Nothing at or above target: pick the widest.
		for i := range candidates {
			if chosen == nil || candidates[i].ar > chosen.ar {
				chosen = &candidates[i]
			}
		}
	}
	return Grid{Cols: chosen.cols, Rows: chosen.rows, TokenCount: tokenCount}
}
