package entviz

// Entropy characterization model (spec v13).
//
// Port of src/entviz/characterize.py. The parser (entropy.go) produces a Parsed
// display record whose TypeName string fuses several orthogonal facts (scheme,
// semantic role, network/variant, size). Characterize re-expresses that same
// recognition along independent axes, so downstream consumers read structured
// fields instead of string-parsing the label.
//
// The characterization is REPORTING-ONLY. It changes no rendered pixel, no
// fingerprint input, and no label string. The renderer emits the eight fields
// onto the root <svg> as data-* attributes (see pipeline.go); the conformance
// model extractor recovers them from those attributes. size_bits is NOT the
// >512-bit truncation basis.

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
)

// Closed role enum (spec v13). Nothing outside this set may appear.
const (
	roleKey        = "key"
	roleSignature  = "signature"
	roleDigest     = "digest"
	roleAddress    = "address"
	roleIdentifier = "identifier"
)

// Characterization is the 8-field structured entropy characterization.
// Scheme and Role use pointers so a nil pointer serializes to the empty string
// (data-scheme/data-role) and JSON null semantics; every other field is always
// present.
type Characterization struct {
	Encoding    string
	Scheme      *string
	Role        *string
	Qualifiers  *OrderedMap
	SizeBasis   string
	SizeBits    int
	Parts       []Part
	EntropyType string
}

// Part is one ordered [{text, bind}] entry; bind in {none, fold, core}.
type Part struct {
	Text string
	Bind string
}

// OrderedMap is a small string->value map that preserves insertion order, so
// the emitted data-qualifiers JSON matches the reference insertion order.
// Values are either string or int (the CID version qualifier is numeric).
type OrderedMap struct {
	keys   []string
	values map[string]any
}

func newOrderedMap() *OrderedMap {
	return &OrderedMap{values: map[string]any{}}
}

func (m *OrderedMap) set(k string, v any) {
	if _, ok := m.values[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.values[k] = v
}

// Keys returns the insertion-ordered keys.
func (m *OrderedMap) Keys() []string { return m.keys }

// Get returns the value for a key.
func (m *OrderedMap) Get(k string) any { return m.values[k] }

// jsonScalar marshals a string or int value to its compact JSON form,
// matching Python's json.dumps(ensure_ascii=False) for the value types used
// here (strings and small non-negative ints). HTML escaping is disabled so
// '<', '>', '&' stay literal (as Python emits them); the outer attribute
// XML-escaping is applied by the renderer, exactly as in the reference.
func jsonScalar(v any) string {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimRight(buf.String(), "\n")
}

// QualifiersJSON returns the compact JSON object for data-qualifiers, keys in
// insertion order, no spaces: {"algorithm":"Blake3-256"}. Empty map -> {}.
func (c *Characterization) QualifiersJSON() string {
	if c.Qualifiers == nil || len(c.Qualifiers.keys) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range c.Qualifiers.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonScalar(k))
		b.WriteByte(':')
		b.WriteString(jsonScalar(c.Qualifiers.values[k]))
	}
	b.WriteByte('}')
	return b.String()
}

// PartsJSON returns the compact JSON array for data-parts, no spaces:
// [{"text":"...","bind":"core"}]. Insertion order matches reading order.
func (c *Characterization) PartsJSON() string {
	var b strings.Builder
	b.WriteByte('[')
	for i, p := range c.Parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"text":`)
		b.WriteString(jsonScalar(p.Text))
		b.WriteString(`,"bind":`)
		b.WriteString(jsonScalar(p.Bind))
		b.WriteByte('}')
	}
	b.WriteByte(']')
	return b.String()
}

// SchemeAttr / RoleAttr return the empty string for a nil scheme/role.
func (c *Characterization) SchemeAttr() string {
	if c.Scheme == nil {
		return ""
	}
	return *c.Scheme
}

func (c *Characterization) RoleAttr() string {
	if c.Role == nil {
		return ""
	}
	return *c.Role
}

// _INTEGER_DECODE_ALPHABETS: non-power-of-2 alphabets whose true density is
// below the token-packing bits_per_char convention. For these, size_bits
// decodes the core as a big integer and takes its minimal byte length.
func isIntegerDecodeAlphabet(name string) bool {
	return name == "base58" || name == "base36" || name == "decimal"
}

// decodedBytesInteger returns the minimal byte length of core decoded as a big
// integer in its base. Mirrors the tokenizer's case tolerance. An empty core
// (or a value of zero) is one byte.
func decodedBytesInteger(core string, alphabet Alphabet) int {
	chars := alphabet.Chars
	lower := strings.ToLower(chars)
	base := int64(len([]rune(chars)))
	n := new(big.Int)
	bBase := big.NewInt(base)
	for _, c := range core {
		v := strings.IndexRune(chars, c)
		if v < 0 {
			v = strings.IndexRune(lower, toLowerRune(c))
		}
		if v < 0 {
			v = 0
		}
		n.Mul(n, bBase)
		n.Add(n, big.NewInt(int64(v)))
	}
	if n.Sign() == 0 {
		return 1
	}
	return (n.BitLen() + 7) / 8
}

// sizeBits computes the value size in bits from the CORE only (Resolution A).
func sizeBits(core string, alphabet Alphabet, basis string) int {
	if basis == "utf8" {
		return len([]byte(core)) * 8
	}
	if isIntegerDecodeAlphabet(alphabet.Name) {
		return decodedBytesInteger(core, alphabet) * 8
	}
	runeLen := len([]rune(core))
	return ((runeLen * int(alphabet.BitsPerChar)) / 8) * 8
}

// cesrRole classifies a CESR derivation-code role off the decoded primitive
// name. Signatures -> signature; digests (SAID/hashes) -> digest; everything
// else (seeds, keys, ciphers, blinding factors, random numbers) -> key.
func cesrRole(name string) string {
	low := strings.ToLower(name)
	if strings.Contains(low, "sig") {
		return roleSignature
	}
	digestMarkers := []string{"blake3", "blake2b", "blake2s", "sha3", "sha2", "sha"}
	for _, m := range digestMarkers {
		if strings.Contains(low, m) {
			return roleDigest
		}
	}
	return roleKey
}

func trimTrailingColons(s string) string {
	return strings.TrimRight(s, ":")
}

// describeFromParsed returns (scheme, role, qualifiers, sizeBasis) for a Parsed
// record. sizeBasis is SCHEME-driven: did / urn / UTF-8-fallback are "utf8";
// every recognized encoding scheme is "decoded".
func describeFromParsed(p *Parsed) (*string, *string, *OrderedMap, string) {
	typeName := p.TypeName
	var prefix string
	if p.Prefix != nil {
		prefix = *p.Prefix
	}
	q := newOrderedMap()

	str := func(s string) *string { v := s; return &v }

	// --- Folded identity prefixes: did / urn / gitoid / swhid ---
	if p.Prefix != nil && p.PrefixSemantic {
		switch {
		case strings.HasPrefix(prefix, "did:"):
			method := trimTrailingColons(prefix[len("did:"):])
			q.set("method", method)
			if method == "ethr" {
				head := p.Core
				if i := strings.IndexByte(head, ':'); i >= 0 {
					head = head[:i]
				}
				q.set("network", head)
			}
			return str("did"), str(roleIdentifier), q, "utf8"
		case strings.HasPrefix(prefix, "urn:"):
			nid := trimTrailingColons(prefix[len("urn:"):])
			q.set("nid", nid)
			return str("urn"), str(roleIdentifier), q, "utf8"
		case strings.HasPrefix(prefix, "gitoid:"):
			segs := strings.Split(strings.Trim(prefix, ":"), ":")
			if len(segs) >= 3 {
				q.set("object", segs[1])
				q.set("algorithm", segs[2])
			}
			return str("gitoid"), str(roleDigest), q, "decoded"
		case strings.HasPrefix(prefix, "swh:"):
			segs := strings.Split(strings.Trim(prefix, ":"), ":")
			if len(segs) >= 3 {
				q.set("object", segs[2])
			}
			q.set("algorithm", "sha1")
			return str("swhid"), str(roleDigest), q, "decoded"
		}
	}

	// --- CESR primitives: "CESR <decoded-name>" ---
	if strings.HasPrefix(typeName, "CESR ") {
		name := typeName[len("CESR "):]
		q.set("algorithm", name)
		return str("cesr"), str(cesrRole(name)), q, "decoded"
	}

	// --- SSH public keys: "SSH <algorithm>" or "SSH key" ---
	if strings.HasPrefix(typeName, "SSH") {
		rest := strings.TrimSpace(typeName[len("SSH"):])
		if rest != "" && rest != "key" {
			q.set("algorithm", rest)
		}
		return str("ssh"), str(roleKey), q, "decoded"
	}

	// --- Blockchain addresses ---
	if strings.HasPrefix(typeName, "BTC") {
		q.set("network", "mainnet")
		low := strings.ToLower(typeName)
		if strings.Contains(low, "legacy") {
			q.set("variant", "legacy")
		} else if strings.Contains(low, "segwit") {
			q.set("variant", "segwit")
		}
		return str("btc"), str(roleAddress), q, "decoded"
	}
	if typeName == "BCH" {
		if strings.HasPrefix(strings.ToLower(prefix), "bchtest") {
			q.set("network", "testnet")
		} else {
			q.set("network", "mainnet")
		}
		return str("bch"), str(roleAddress), q, "decoded"
	}
	if strings.HasPrefix(typeName, "LTC") {
		q.set("network", "mainnet")
		if strings.Contains(strings.ToLower(typeName), "legacy") {
			q.set("variant", "legacy")
		}
		return str("ltc"), str(roleAddress), q, "decoded"
	}
	if strings.HasPrefix(typeName, "ADA") {
		if strings.Contains(typeName, "Byron") {
			q.set("variant", "byron")
		} else if strings.Contains(typeName, "Shelley") {
			q.set("variant", "shelley")
		}
		return str("ada"), str(roleAddress), q, "decoded"
	}
	if typeName == "ETH" {
		return str("eth"), str(roleAddress), q, "decoded"
	}
	if strings.HasPrefix(typeName, "XLM") {
		if strings.Contains(typeName, "muxed") {
			q.set("variant", "muxed")
		}
		return str("stellar"), str(roleAddress), q, "decoded"
	}
	if typeName == "XRP" {
		return str("xrp"), str(roleAddress), q, "decoded"
	}
	if typeName == "EOS" {
		return str("eos"), str(roleAddress), q, "decoded"
	}
	if typeName == "bech32" {
		if p.Prefix != nil && strings.HasSuffix(prefix, "1") {
			q.set("hrp", prefix[:len(prefix)-1])
		}
		return str("bech32"), str(roleAddress), q, "decoded"
	}

	// --- Content identifiers (IPFS CID) ---
	if strings.HasPrefix(typeName, "CIDv") {
		if strings.HasPrefix(typeName, "CIDv0") {
			q.set("version", 0)
			q.set("codec", "dag-pb")
			q.set("hash", "sha2-256")
		} else {
			q.set("version", 1)
			rest := strings.TrimSpace(typeName[len("CIDv1"):])
			if rest != "" {
				if i := strings.IndexByte(rest, '/'); i >= 0 {
					q.set("codec", rest[:i])
					q.set("hash", rest[i+1:])
				} else {
					q.set("codec", rest)
					q.set("hash", "sha2-256")
				}
			}
		}
		return str("cid"), str(roleIdentifier), q, "decoded"
	}

	// --- Structured identifiers ---
	if typeName == "UUID" {
		return str("uuid"), str(roleIdentifier), q, "decoded"
	}
	if typeName == "ULID" {
		return str("ulid"), str(roleIdentifier), q, "decoded"
	}
	if typeName == "LEI" {
		return str("lei"), str(roleIdentifier), q, "decoded"
	}
	if typeName == "snowflake" {
		return str("snowflake"), str(roleIdentifier), q, "decoded"
	}
	if strings.HasPrefix(typeName, "multihash") || strings.Contains(typeName, "multihash") {
		return str("multihash"), str(roleDigest), q, "decoded"
	}

	// --- Bare encodings (hex / base64 / base64url / disproof fallbacks) ---
	return nil, nil, q, "decoded"
}

// partsFromParsed returns reading-order [{text, bind}] parts (Wrinkle 4).
func partsFromParsed(p *Parsed) []Part {
	var parts []Part
	if p.Prefix != nil {
		bind := "none"
		if p.PrefixSemantic {
			bind = "fold"
		}
		parts = append(parts, Part{Text: *p.Prefix, Bind: bind})
	}
	parts = append(parts, Part{Text: p.Core, Bind: "core"})
	if p.Suffix != nil {
		parts = append(parts, Part{Text: *p.Suffix, Bind: "none"})
	}
	return parts
}

// Characterize characterizes an entropy string into the structured model
// (spec v13). Never errors for an in-range input: an unrecognized input falls
// back to the UTF-8 -> base64url path (scheme=nil, role=nil, size_basis="utf8",
// size measured over the ORIGINAL input bytes). A hard parse rejection (EIP-55)
// is surfaced via the error, matching Parse.
func Characterize(entropy string) (*Characterization, error) {
	raw := strings.TrimSpace(entropy)
	parsed, err := Parse(raw)
	if err != nil {
		return nil, err
	}

	if parsed == nil {
		core := base64.RawURLEncoding.EncodeToString([]byte(raw))
		return &Characterization{
			Encoding:    BASE64URL.Name,
			Scheme:      nil,
			Role:        nil,
			Qualifiers:  newOrderedMap(),
			SizeBasis:   "utf8",
			SizeBits:    len([]byte(raw)) * 8,
			Parts:       []Part{{Text: core, Bind: "core"}},
			EntropyType: BASE64URL.Name,
		}, nil
	}

	scheme, role, qualifiers, basis := describeFromParsed(parsed)
	bits := sizeBits(parsed.Core, parsed.Alphabet, basis)
	encoding := parsed.Alphabet.Name
	entropyType := encoding
	if scheme != nil {
		entropyType = *scheme
	}
	return &Characterization{
		Encoding:    encoding,
		Scheme:      scheme,
		Role:        role,
		Qualifiers:  qualifiers,
		SizeBasis:   basis,
		SizeBits:    bits,
		Parts:       partsFromParsed(parsed),
		EntropyType: entropyType,
	}, nil
}
