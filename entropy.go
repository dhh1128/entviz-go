package entviz

// Format-specific entropy parsing (port of entviz-rs/src/entropy.rs, itself a
// port of src/entviz/entropy.py).
//
// Parse dispatches over the registered parsers in order (order is semantics)
// and returns the first match, or falls back to disproof-based alphabet
// detection. The pipeline re-encodes to base64url only when this returns no
// match. A hard parse error (EIP-55 checksum failure) aborts the whole render.

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Parser alphabets that are not crate-root canonical. HEX and BASE64URL come
// from core.go.

const (
	hexCharsLower = "0123456789abcdef"
	base58Chars   = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	bech32Chars   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	base32CharsUp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// Parsed is a recognized entropy classification.
type Parsed struct {
	TypeName       string
	Alphabet       Alphabet
	Prefix         *string
	Core           string
	Suffix         *string
	PrefixSemantic bool
}

func newParsed(typeName string, alphabet Alphabet, prefix *string, core string, suffix *string) *Parsed {
	return &Parsed{
		TypeName: typeName,
		Alphabet: alphabet,
		Prefix:   prefix,
		Core:     core,
		Suffix:   suffix,
	}
}

func (p *Parsed) semantic() *Parsed {
	p.PrefixSemantic = true
	return p
}

// Eip55Error is a hard rejection: an EIP-55 mixed-case checksum mismatch. The
// Position is the 0-based index (within the 40-hex body) of the first digit
// whose case disagrees with the canonical case.
type Eip55Error struct {
	Position int
}

func (e *Eip55Error) Error() string {
	return "EIP-55 checksum mismatch"
}

func strPtr(s string) *string { return &s }

// --------------------------------------------------------------------------
// Small char-class helpers
// --------------------------------------------------------------------------

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !isASCIIHexDigit(c) {
			return false
		}
	}
	return true
}

func isASCIIHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func allIn(s, set string) bool {
	for _, c := range s {
		if !strings.ContainsRune(set, c) {
			return false
		}
	}
	return true
}

func isBase58(s string) bool {
	return s != "" && allIn(s, base58Chars)
}

func isBech32Either(s string) bool {
	return s != "" && allIn(strings.ToLower(s), bech32Chars)
}

func isBase32Either(s string) bool {
	return s != "" && allIn(strings.ToUpper(s), base32CharsUp)
}

func isBase64urlNopad(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(isASCIIAlphanumeric(c) || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func isASCIIAlphanumeric(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isASCIILower(c rune) bool { return c >= 'a' && c <= 'z' }
func isASCIIUpper(c rune) bool { return c >= 'A' && c <= 'Z' }
func isASCIIAlpha(c rune) bool { return isASCIILower(c) || isASCIIUpper(c) }
func isASCIIDigit(c rune) bool { return c >= '0' && c <= '9' }

// --------------------------------------------------------------------------
// Individual parsers
// --------------------------------------------------------------------------

type cesrCode struct {
	code  string
	label string
	total int
}

func parseCesr(text string) (*Parsed, error) {
	one := []cesrCode{
		{"A", "Ed25519 seed", 44},
		{"B", "Ed25519 nt pubkey", 44},
		{"C", "X25519 pub enckey", 44},
		{"D", "Ed25519 pubkey", 44},
		{"E", "Blake3-256", 44},
		{"F", "Blake2b-256", 44},
		{"G", "Blake2s-256", 44},
		{"H", "SHA3-256", 44},
		{"I", "SHA2-256", 44},
		{"J", "secp256k1 seed", 44},
		{"K", "Ed448 seed", 76},
		{"L", "X448 pub enckey", 76},
		{"O", "X25519 priv deckey", 44},
		{"P", "X25519 124 cipher 44 seed", 124},
		{"Q", "secp256r1 seed", 44},
		{"a", "blinding factor", 44},
		{"c", "FN-DSA-512 seed", 44},
		{"d", "FN-DSA-1024 seed", 44},
		{"e", "FN-DSA-1024 sig", 1708},
		{"b", "FN-DSA-1024 pubkey", 2392},
	}
	two := []cesrCode{
		{"0A", "random 128-bit number", 24},
		{"0B", "Ed25519 sig", 88},
		{"0C", "secp256k1 sig", 88},
		{"0D", "Blake3-512", 88},
		{"0E", "Blake2b-512", 88},
		{"0F", "SHA3-512", 88},
		{"0G", "SHA2-512", 88},
		{"0I", "secp256r1 sig", 88},
	}
	four := []cesrCode{
		{"1AAA", "secp256k1 nt pubkey", 48},
		{"1AAB", "secp256k1 pub/enc key", 48},
		{"1AAC", "Ed448 nt pubkey", 80},
		{"1AAD", "Ed448 pubkey", 80},
		{"1AAE", "Ed448 sig", 156},
		{"1AAH", "X25519 100 cipher 24 salt", 100},
		{"1AAI", "secp256r1 nt pubkey", 48},
		{"1AAJ", "secp256r1 pub/enc key", 48},
		{"1AAR", "FN-DSA-512 sig", 892},
		{"1AAQ", "FN-DSA-512 pubkey", 1200},
	}
	if text == "" {
		return nil, nil
	}
	runes := []rune(text)
	length := len(runes)
	first := runes[0]

	anyLen := func(items []cesrCode) bool {
		for _, x := range items {
			if x.total == length {
				return true
			}
		}
		return false
	}

	var items []cesrCode
	switch {
	case first == '0' && anyLen(two):
		items = two
	case first == '1' && anyLen(four):
		items = four
	case first != '0' && first != '1' && anyLen(one):
		items = one
	default:
		return nil, nil
	}
	for _, it := range items {
		if strings.HasPrefix(text, it.code) && length == it.total && isBase64urlNopad(text) {
			return newParsed("CESR "+it.label, BASE64URL, nil, text, nil), nil
		}
	}
	return nil, nil
}

type sshKeyType struct {
	shortName    string
	matchStr     string
	prefixLength int
}

var sshKeyTypes = []sshKeyType{
	{"ecdsa-nistp256", "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB", 52},
	{"ecdsa-nistp384", "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABh", 52},
	{"ecdsa-nistp521", "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACF", 52},
	{"rsa", "AAAAB3NzaC1yc2EAAAADAQAB", 28},
	{"ed25519", "AAAAC3NzaC1lZDI1NTE5AAAA", 24},
	{"dss", "AAAAB3NzaC1kc3M", 15},
}

func parseSSHKey(text string) (*Parsed, error) {
	payload, ok := sshLineSplit(text)
	if !ok {
		if p, rest, ok2 := sshKeyRegex(text); ok2 {
			return newParsed("SSH key", BASE64, strPtr(p), rest, nil), nil
		}
		return nil, nil
	}
	for _, kt := range sshKeyTypes {
		if strings.HasPrefix(payload, kt.matchStr) && utf8.RuneCountInString(payload) >= kt.prefixLength {
			chars := []rune(payload)
			prefix := string(chars[:kt.prefixLength])
			body := string(chars[kt.prefixLength:])
			return newParsed("SSH "+kt.shortName, BASE64, strPtr(prefix), body, nil), nil
		}
	}
	if p, rest, ok2 := sshKeyRegex(payload); ok2 {
		return newParsed("SSH key", BASE64, strPtr(p), rest, nil), nil
	}
	return nil, nil
}

func sshKeyRegex(text string) (string, string, bool) {
	if !strings.HasPrefix(text, "AAAA") {
		return "", "", false
	}
	rest := text[4:]
	if rest == "" {
		return "", "", false
	}
	bodyEnd := strings.IndexByte(rest, '=')
	if bodyEnd < 0 {
		bodyEnd = len(rest)
	}
	body := rest[:bodyEnd]
	pad := rest[bodyEnd:]
	if body == "" {
		return "", "", false
	}
	for _, c := range body {
		if !(isASCIIAlphanumeric(c) || c == '+' || c == '/') {
			return "", "", false
		}
	}
	if len(pad) > 3 {
		return "", "", false
	}
	for _, c := range pad {
		if c != '=' {
			return "", "", false
		}
	}
	return "AAAA", rest, true
}

func sshLineSplit(text string) (string, bool) {
	s := text
	typePrefixes := []string{
		"ssh-ed25519", "ssh-rsa", "ssh-dss",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	}
	for _, tp := range typePrefixes {
		if strings.HasPrefix(s, tp) {
			rest := s[len(tp):]
			if rest != "" && isWhitespace([]rune(rest)[0]) {
				s = strings.TrimLeft(rest, " \t\r\n\f\v")
				break
			}
		}
	}
	if !strings.HasPrefix(s, "AAAA") {
		return "", false
	}
	chars := []rune(s)
	i := 0
	for i < len(chars) {
		c := chars[i]
		if isASCIIAlphanumeric(c) || c == '+' || c == '/' {
			i++
		} else {
			break
		}
	}
	for i < len(chars) && chars[i] == '=' {
		i++
	}
	payloadEnd := i
	payload := string(chars[:payloadEnd])
	if !strings.HasPrefix(payload, "AAAA") {
		return "", false
	}
	rest := string(chars[payloadEnd:])
	if rest != "" && !isWhitespace([]rune(rest)[0]) {
		return "", false
	}
	return payload, true
}

func isWhitespace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

func parseBitcoinAddress(text string) (*Parsed, error) {
	chars := []rune(text)
	if len(chars) > 0 {
		first := chars[0]
		if strings.ContainsRune("123mn", first) {
			body := string(chars[1:])
			bchars := []rune(body)
			n := len(bchars)
			if n >= 25 && n <= 34 && isBase58(body) {
				mid := string(bchars[:len(bchars)-4])
				suf := string(bchars[len(bchars)-4:])
				midLen := utf8.RuneCountInString(mid)
				if midLen >= 21 && midLen <= 30 {
					return newParsed("BTC legacy", BASE58, strPtr(string(first)), mid, strPtr(suf)), nil
				}
			}
		}
	}
	if prefix, body, ok := matchPrefixBech32(text, []string{"bc1", "tb1"}, 39, 69); ok {
		return newParsed("BTC SegWit", BECH32, strPtr(strings.ToLower(prefix)), strings.ToLower(body), nil), nil
	}
	return nil, nil
}

func matchPrefixBech32(text string, prefixes []string, lo, hi int) (string, string, bool) {
	low := strings.ToLower(text)
	for _, p := range prefixes {
		if strings.HasPrefix(low, p) {
			pn := utf8.RuneCountInString(p)
			tr := []rune(text)
			prefix := string(tr[:pn])
			body := string(tr[pn:])
			n := utf8.RuneCountInString(body)
			if n >= lo && n <= hi && isBech32Either(body) {
				return prefix, body, true
			}
		}
	}
	return "", "", false
}

func parseRippleAddress(text string) (*Parsed, error) {
	if strings.HasPrefix(text, "r") {
		rest := text[1:]
		if utf8.RuneCountInString(rest) == 33 && isBase58(rest) {
			return newParsed("XRP", BASE58, strPtr("r"), rest, nil), nil
		}
	}
	return nil, nil
}

func parseEthereumAddress(text string) (*Parsed, error) {
	hasPrefix := false
	body := text
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		hasPrefix = true
		body = text[2:]
	}
	if utf8.RuneCountInString(body) != 40 || !isHex(body) {
		return nil, nil
	}
	hasLower := false
	hasUpper := false
	for _, c := range body {
		if isASCIIAlpha(c) {
			if isASCIILower(c) {
				hasLower = true
			}
			if isASCIIUpper(c) {
				hasUpper = true
			}
		}
	}
	isMixed := hasLower && hasUpper

	if !hasPrefix {
		if !isMixed {
			return nil, nil
		}
		if err := validateEip55(body); err != nil {
			return nil, err
		}
	} else if isMixed {
		if err := validateEip55(body); err != nil {
			return nil, err
		}
	}
	return newParsed("ETH", HEX, strPtr("0x"), strings.ToLower(body), nil), nil
}

func validateEip55(body string) error {
	lower := strings.ToLower(body)
	digestHex := keccak256Hex([]byte(lower))
	dh := []rune(digestHex)
	for i, c := range []rune(body) {
		if !isASCIIAlpha(c) {
			continue
		}
		canonicalUpper := hexDigitValue(dh[i]) >= 8
		var expected rune
		if canonicalUpper {
			expected = toUpperRune(c)
		} else {
			expected = toLowerRune(c)
		}
		if c != expected {
			return &Eip55Error{Position: i}
		}
	}
	return nil
}

func hexDigitValue(c rune) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
}

func toUpperRune(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - ('a' - 'A')
	}
	return r
}

func parseLitecoinAddress(text string) (*Parsed, error) {
	for _, prefix := range []string{"tL", "L"} {
		if strings.HasPrefix(text, prefix) {
			rest := text[len(prefix):]
			if utf8.RuneCountInString(rest) == 33 && isBase58(rest) {
				return newParsed("LTC legacy", BASE58, strPtr(prefix), rest, nil), nil
			}
		}
	}
	if prefix, body, ok := matchPrefixBech32(text, []string{"ltc1"}, 38, 68); ok {
		return newParsed("LTC", BECH32, strPtr(strings.ToLower(prefix)), strings.ToLower(body), nil), nil
	}
	return nil, nil
}

func parseBitcoinCashAddress(text string) (*Parsed, error) {
	low := strings.ToLower(text)
	var prefix *string
	var rest string
	switch {
	case strings.HasPrefix(low, "bitcoincash:"):
		n := len("bitcoincash:")
		prefix = strPtr(text[:n])
		rest = text[n:]
	case strings.HasPrefix(low, "bchtest:"):
		n := len("bchtest:")
		prefix = strPtr(text[:n])
		rest = text[n:]
	default:
		rest = text
	}
	rchars := []rune(rest)
	if len(rchars) > 0 {
		first := rchars[0]
		if (first == 'p' || first == 'q' || first == 'P' || first == 'Q') && len(rchars) == 42 {
			body := string(rchars[1:])
			if isBech32Either(body) {
				fullBody := strings.ToLower(rest)
				return newParsed("BCH", BECH32, prefix, fullBody, nil), nil
			}
		}
	}
	return nil, nil
}

func parseStellarAddress(text string) (*Parsed, error) {
	chars := []rune(text)
	if len(chars) > 0 {
		first := chars[0]
		if (first == 'G' || first == 'g') && len(chars) == 56 {
			body := string(chars[1:])
			if isBase32Either(body) {
				return newParsed("XLM", BASE32, strPtr("G"), strings.ToUpper(body), nil), nil
			}
		}
		if (first == 'M' || first == 'm') && len(chars) == 69 {
			body := string(chars[1:])
			if isBase32Either(body) {
				return newParsed("XLM muxed", BASE32, strPtr("M"), strings.ToUpper(body), nil), nil
			}
		}
	}
	return nil, nil
}

func parseUUID(text string) (*Parsed, error) {
	s := text
	if strings.HasPrefix(s, "{") {
		s = s[1:]
	}
	if strings.HasSuffix(s, "}") {
		s = s[:len(s)-1]
	}
	groups := []int{8, 4, 4, 4, 12}
	var stripped strings.Builder
	for _, c := range s {
		if c != '-' {
			stripped.WriteRune(c)
		}
	}
	st := stripped.String()
	if utf8.RuneCountInString(st) != 32 || !isHex(st) {
		return nil, nil
	}
	sc := []rune(s)
	pos := 0
	for gi, glen := range groups {
		for k := 0; k < glen; k++ {
			if pos >= len(sc) || !isASCIIHexDigit(sc[pos]) {
				return nil, nil
			}
			pos++
		}
		if gi < len(groups)-1 && pos < len(sc) && sc[pos] == '-' {
			pos++
		}
	}
	if pos != len(sc) {
		return nil, nil
	}
	return newParsed("UUID", HEX, nil, strings.ToLower(st), nil), nil
}

func parseULID(text string) (*Parsed, error) {
	if utf8.RuneCountInString(text) != 26 {
		return nil, nil
	}
	for _, c := range text {
		ok := isASCIIDigit(c) ||
			(c >= 'A' && c <= 'T') ||
			(c >= 'V' && c <= 'Z') ||
			(c >= 'a' && c <= 't') ||
			(c >= 'v' && c <= 'z')
		if !ok {
			return nil, nil
		}
	}
	var b strings.Builder
	for _, c := range text {
		switch c {
		case 'I', 'i', 'L', 'l':
			b.WriteRune('1')
		case 'O', 'o':
			b.WriteRune('0')
		default:
			b.WriteRune(c)
		}
	}
	normalized := strings.ToUpper(b.String())
	return newParsed("ULID", CROCKFORD32, nil, normalized, nil), nil
}

func parseSnowflake(text string) (*Parsed, error) {
	n := utf8.RuneCountInString(text)
	if n < 17 || n > 20 {
		return nil, nil
	}
	for _, c := range text {
		if !isASCIIDigit(c) {
			return nil, nil
		}
	}
	val, ok := parseUint64Dec(text)
	if !ok {
		return nil, nil
	}
	if val>>63 != 0 {
		return nil, nil
	}
	return newParsed("snowflake", DECIMAL, nil, text, nil), nil
}

// parseUint64Dec parses a decimal string into uint64; ok=false on overflow.
func parseUint64Dec(s string) (uint64, bool) {
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		d := uint64(c - '0')
		// overflow check
		if v > (^uint64(0)-d)/10 {
			return 0, false
		}
		v = v*10 + d
	}
	return v, true
}

func parseLEI(text string) (*Parsed, error) {
	if utf8.RuneCountInString(text) != 20 {
		return nil, nil
	}
	for _, c := range text {
		if !isASCIIAlphanumeric(c) {
			return nil, nil
		}
	}
	upper := strings.ToUpper(text)
	if upper[4:6] != "00" {
		return nil, nil
	}
	if !leiChecksumOK(upper) {
		return nil, nil
	}
	return newParsed("LEI", BASE36, nil, upper[:18], strPtr(upper[18:])), nil
}

func leiChecksumOK(lei string) bool {
	var digits strings.Builder
	for _, c := range lei {
		switch {
		case isASCIIDigit(c):
			digits.WriteRune(c)
		case isASCIIUpper(c):
			digits.WriteString(strconv.Itoa(int(c) - 'A' + 10))
		default:
			return false
		}
	}
	var rem uint64
	for _, ch := range []byte(digits.String()) {
		rem = (rem*10 + uint64(ch-'0')) % 97
	}
	return rem == 1
}

// didRegex matches a W3C DID or DID URL: did:<method>:<msid> with an optional
// DID-URL tail (path/query/fragment). The method is lowercase [a-z0-9]+; the
// msid MAY contain ':' and ends at the first '/', '?', or '#'. The trailing '-'
// in the msid class is a literal (last in the class).
var didRegex = regexp.MustCompile(`^did:([a-z0-9]+):([A-Za-z0-9._%:-]+)(?:[/?#].*)?$`)

// urnRegex matches an RFC 8141 URN: urn:<NID>:<NSS> with optional
// r-/q-/f-components. Case-insensitive on the scheme+NID (captured groups keep
// their original case); the NSS keeps '/' and ends at the first '?' or '#'.
var urnRegex = regexp.MustCompile(`(?i)^urn:([A-Za-z0-9][A-Za-z0-9-]{0,31}):([^?#]+)(?:[?#].*)?$`)

// parseDid parses a W3C DID / DID URL. The method-specific-id is the core, kept
// VERBATIM and NOT case-folded; the did:<method>: prefix is IDENTITY (bound by
// prefix-fold via PrefixSemantic); the DID-URL tail is dropped.
func parseDid(text string) (*Parsed, error) {
	if text == "" {
		return nil, nil
	}
	m := didRegex.FindStringSubmatch(text)
	if m == nil {
		return nil, nil
	}
	method, msid := m[1], m[2]
	return newParsed("", BASE64URL, strPtr("did:"+method+":"), msid, nil).semantic(), nil
}

// parseUrn parses an RFC 8141 URN. The NSS is the core, kept VERBATIM (case
// preserved, '/' retained); the urn:<nid>: prefix is IDENTITY (NID LOWERCASED)
// bound by prefix-fold; the r-/q-/f-components are dropped.
func parseUrn(text string) (*Parsed, error) {
	if text == "" {
		return nil, nil
	}
	m := urnRegex.FindStringSubmatch(text)
	if m == nil {
		return nil, nil
	}
	nid, nss := strings.ToLower(m[1]), m[2]
	return newParsed("", BASE64URL, strPtr("urn:"+nid+":"), nss, nil).semantic(), nil
}

func parseSWHID(text string) (*Parsed, error) {
	low := strings.ToLower(text)
	types := []string{"snp", "rel", "rev", "dir", "cnt"}
	for _, t := range types {
		pre := "swh:1:" + t + ":"
		if strings.HasPrefix(low, pre) {
			rest := low[len(pre):]
			hexpart := rest
			if i := strings.IndexByte(rest, ';'); i >= 0 {
				hexpart = rest[:i]
			}
			if utf8.RuneCountInString(hexpart) == 40 && isHex(hexpart) {
				prefix := text[:len(pre)]
				return newParsed("", HEX, strPtr(strings.ToLower(prefix)), hexpart, nil).semantic(), nil
			}
		}
	}
	return nil, nil
}

func parseGitoid(text string) (*Parsed, error) {
	low := strings.ToLower(text)
	if !strings.HasPrefix(low, "gitoid:") {
		return nil, nil
	}
	parts := strings.SplitN(low, ":", 4)
	if len(parts) != 4 {
		return nil, nil
	}
	obj := parts[1]
	algo := parts[2]
	body := parts[3]
	if obj != "blob" && obj != "tree" && obj != "commit" && obj != "tag" {
		return nil, nil
	}
	var want int
	switch algo {
	case "sha1":
		want = 40
	case "sha256":
		want = 64
	default:
		return nil, nil
	}
	if utf8.RuneCountInString(body) != want || !isHex(body) {
		return nil, nil
	}
	prefix := "gitoid:" + obj + ":" + algo + ":"
	return newParsed("", HEX, strPtr(prefix), body, nil).semantic(), nil
}

// ---- bech32 checksum (generic Cosmos-style) ----

func bech32Polymod(values []uint32) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for i, g := range gen {
			if (top>>uint(i))&1 != 0 {
				chk ^= g
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []uint32 {
	var out []uint32
	for _, c := range hrp {
		out = append(out, uint32(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, uint32(c)&31)
	}
	return out
}

func bech32ChecksumConst(hrp, data string) (uint32, bool) {
	var values []uint32
	for _, c := range data {
		idx := strings.IndexRune(bech32Chars, c)
		if idx < 0 {
			return 0, false
		}
		values = append(values, uint32(idx))
	}
	full := bech32HrpExpand(hrp)
	full = append(full, values...)
	return bech32Polymod(full), true
}

func parseBech32Address(text string) (*Parsed, error) {
	low := strings.ToLower(text)
	chars := []rune(low)
	var sepCandidates []int
	for i, c := range chars {
		if c == '1' {
			sepCandidates = append(sepCandidates, i)
		}
	}
	for i := len(sepCandidates) - 1; i >= 0; i-- {
		sep := sepCandidates[i]
		if sep < 1 || sep > 83 {
			continue
		}
		hrp := string(chars[:sep])
		hrpOK := true
		for _, c := range hrp {
			if !isASCIILower(c) {
				hrpOK = false
				break
			}
		}
		if !hrpOK {
			continue
		}
		data := string(chars[sep+1:])
		if utf8.RuneCountInString(data) < 8 || !allIn(data, bech32Chars) {
			continue
		}
		c, ok := bech32ChecksumConst(hrp, data)
		if ok && (c == 1 || c == 0x2bc830a3) {
			dchars := []rune(data)
			core := string(dchars[:len(dchars)-6])
			suffix := string(dchars[len(dchars)-6:])
			return newParsed("bech32", BECH32, strPtr(hrp+"1"), core, strPtr(suffix)), nil
		}
	}
	return nil, nil
}

// ---- IPFS CID ----

func parseIpfsCid(text string) (*Parsed, error) {
	if strings.HasPrefix(text, "Qm") {
		rest := text[2:]
		if utf8.RuneCountInString(rest) == 44 && isBase58(rest) {
			return newParsed("CIDv0", BASE58, strPtr("Qm"), rest, nil), nil
		}
	}
	if strings.HasPrefix(text, "b") {
		rest := text[1:]
		n := utf8.RuneCountInString(rest)
		if n >= 58 && n <= 112 && isBase32Either(rest) {
			label := "CIDv1"
			if codec, hash, ok := b32DecodeMulticodec(rest); ok {
				label = "CIDv1 " + codec
				if hash != "sha2-256" {
					label += "/" + hash
				}
			}
			return newParsed(label, BASE32, strPtr("b"), strings.ToUpper(rest), nil), nil
		}
	}
	return nil, nil
}

func b32DecodeMulticodec(body string) (string, string, bool) {
	bytes, ok := base32Decode(strings.ToUpper(body))
	if !ok {
		return "", "", false
	}
	version, p1, ok := readUvarint(bytes, 0)
	if !ok || version != 1 {
		return "", "", false
	}
	codec, p2, ok := readUvarint(bytes, p1)
	if !ok {
		return "", "", false
	}
	hashFn, _, ok := readUvarint(bytes, p2)
	if !ok {
		return "", "", false
	}
	codecName, ok := multicodecContent(codec)
	if !ok {
		return "", "", false
	}
	hashName, ok := multihashFunc(hashFn)
	if !ok {
		return "", "", false
	}
	return codecName, hashName, true
}

func readUvarint(data []byte, pos int) (uint64, int, bool) {
	var result uint64
	var shift uint
	for pos < len(data) {
		b := data[pos]
		pos++
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, pos, true
		}
		shift += 7
	}
	return 0, 0, false
}

func base32Decode(s string) ([]byte, bool) {
	var bits uint
	var value uint32
	var out []byte
	for _, c := range s {
		idx := strings.IndexRune(base32CharsUp, c)
		if idx < 0 {
			return nil, false
		}
		value = (value << 5) | uint32(idx)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte((value>>bits)&0xff))
		}
	}
	return out, true
}

func multicodecContent(code uint64) (string, bool) {
	switch code {
	case 0x00:
		return "identity", true
	case 0x51:
		return "cbor", true
	case 0x55:
		return "raw", true
	case 0x60:
		return "rlp", true
	case 0x70:
		return "dag-pb", true
	case 0x71:
		return "dag-cbor", true
	case 0x72:
		return "libp2p-key", true
	case 0x78:
		return "git-raw", true
	case 0x90:
		return "eth-block", true
	case 0x97:
		return "eth-tx", true
	case 0x0129:
		return "dag-json", true
	case 0x0202:
		return "car", true
	}
	return "", false
}

func multihashFunc(code uint64) (string, bool) {
	switch code {
	case 0x11:
		return "sha1", true
	case 0x12:
		return "sha2-256", true
	case 0x13:
		return "sha2-512", true
	case 0x14:
		return "sha3-224", true
	case 0x15:
		return "sha3-256", true
	case 0x16:
		return "sha3-384", true
	case 0x17:
		return "sha3-512", true
	case 0x1b:
		return "keccak-256", true
	case 0x41:
		return "blake2b-256", true
	}
	return "", false
}

func parseHexFormat(text string) (*Parsed, error) {
	if text == "" {
		return nil, nil
	}
	var prefix *string
	body := text
	if (strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X")) && utf8.RuneCountInString(text) > 2 {
		prefix = strPtr("0x")
		body = text[2:]
	} else if utf8.RuneCountInString(text)%2 != 0 {
		return nil, nil
	}
	if isHex(body) {
		return newParsed("hex", HEX, prefix, strings.ToLower(body), nil), nil
	}
	return nil, nil
}

func parseEosAddress(text string) (*Parsed, error) {
	if !eosRegex(text) {
		return nil, nil
	}
	allHex := true
	for _, c := range text {
		if !strings.ContainsRune("0123456789abcdef", c) {
			allHex = false
			break
		}
	}
	if allHex {
		return nil, nil
	}
	return newParsed("EOS", BASE64, nil, text, nil), nil
}

func eosRegex(text string) bool {
	chars := []rune(text)
	inSet := func(c rune) bool {
		return isASCIILower(c) || (c >= '1' && c <= '5') || c == '.'
	}
	bodyOK := func(s []rune) bool {
		for _, c := range s {
			if !inSet(c) {
				return false
			}
		}
		return true
	}
	n := len(chars)
	if n >= 2 && n <= 12 {
		last := chars[n-1]
		if bodyOK(chars[:n-1]) && (isASCIILower(last) || (last >= '1' && last <= '5')) {
			return true
		}
	}
	if n == 13 {
		last := chars[12]
		if bodyOK(chars[:12]) && ((last >= 'a' && last <= 'j') || (last >= '1' && last <= '5')) {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// Dispatch
// --------------------------------------------------------------------------

type parserFn func(string) (*Parsed, error)

var parsers = []parserFn{
	parseCesr,
	parseSSHKey,
	parseBitcoinAddress,
	parseRippleAddress,
	parseEthereumAddress,
	parseLitecoinAddress,
	parseBitcoinCashAddress,
	parseStellarAddress,
	parseUUID,
	parseULID,
	parseSnowflake,
	parseLEI,
	parseDid,
	parseUrn,
	parseSWHID,
	parseGitoid,
	parseBech32Address,
	parseIpfsCid,
	parseHexFormat,
	parseEosAddress,
}

// Parse classifies the (already-trimmed) entropy string. It returns:
//   - (parsed, nil) on a recognized type or disproof-detected alphabet,
//   - (nil, nil) when nothing matches (caller re-encodes to base64url),
//   - (nil, err) on a hard rejection (EIP-55 checksum failure).
func Parse(entropy string) (*Parsed, error) {
	entropy = strings.TrimSpace(entropy)
	for _, f := range parsers {
		p, err := f(entropy)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}
	if detected, ok := detectAlphabetByDisproof(entropy); ok {
		var core string
		switch detected.Name {
		case "base32":
			core = strings.ToUpper(entropy)
		case "bech32", "hex":
			core = strings.ToLower(entropy)
		default:
			core = entropy
		}
		return newParsed(detected.Name, detected, nil, core, nil), nil
	}
	return nil, nil
}

func detectAlphabetByDisproof(text string) (Alphabet, bool) {
	if text == "" {
		return Alphabet{}, false
	}
	lower := strings.ToLower(text)
	type entry struct {
		alpha         Alphabet
		charset       string
		caseSensitive bool
	}
	order := []entry{
		{HEX, hexCharsLower, false},
		{BASE32, "abcdefghijklmnopqrstuvwxyz234567", false},
		{BECH32, bech32Chars, false},
		{BASE58, base58Chars, true},
		{BASE64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true},
		{BASE64URL, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", true},
	}
	for _, e := range order {
		view := lower
		if e.caseSensitive {
			view = text
		}
		if allIn(view, e.charset) {
			return e.alpha, true
		}
	}
	return Alphabet{}, false
}

// --------------------------------------------------------------------------
// Large-input tokenization (head + fingerprint-middle + tail)
// --------------------------------------------------------------------------

const (
	headTokens = 8
	tailTokens = 8
	maxTokens  = 22
)

func coreByteLength(core string, alphabet Alphabet) int {
	return (utf8.RuneCountInString(core) * int(alphabet.BitsPerChar)) / 8
}

// crockford5 encodes a 24-bit value as 5 lowercase Crockford base32 chars.
func crockford5(value uint32) string {
	const c = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	out := make([]byte, 5)
	v := value
	for i := 0; i < 5; i++ {
		out[4-i] = c[v&0x1F]
		v >>= 5
	}
	return strings.ToLower(string(out))
}

// TokenizeEntropy tokenizes entropy with v6+ large-input handling. It returns
// (tokens, truncated).
func TokenizeEntropy(core string, alphabet Alphabet) ([]Token, bool) {
	tokenLen := int(24 / alphabet.BitsPerChar)
	nBytes := coreByteLength(core, alphabet)
	runeCount := utf8.RuneCountInString(core)
	tokenCount := (runeCount + tokenLen - 1) / tokenLen
	if tokenCount <= maxTokens && nBytes <= 64 {
		return Tokenize(core, alphabet), false
	}
	chars := []rune(core)
	headChars := headTokens * tokenLen
	tailChars := tailTokens * tokenLen
	headEnd := headChars
	if headEnd > len(chars) {
		headEnd = len(chars)
	}
	head := string(chars[:headEnd])
	tailStart := len(chars) - tailChars
	if tailStart < 0 {
		tailStart = 0
	}
	tail := string(chars[tailStart:])
	headTokensList := Tokenize(head, alphabet)
	tailTokensList := Tokenize(tail, alphabet)

	second := SecondDigest(core)
	middle := make([]Token, 0, 4)
	for i := 0; i < 4; i++ {
		quant := (uint32(second[3*i]) << 16) |
			(uint32(second[3*i+1]) << 8) |
			uint32(second[3*i+2])
		middle = append(middle, Token{
			Text:  crockford5(quant),
			Index: i,
			Quant: quant,
		})
	}

	combined := make([]Token, 0, 20)
	combined = append(combined, headTokensList...)
	combined = append(combined, middle...)
	combined = append(combined, tailTokensList...)
	renumbered := make([]Token, len(combined))
	for i, t := range combined {
		renumbered[i] = Token{Text: t.Text, Index: i, Quant: t.Quant}
	}
	return renumbered, true
}
