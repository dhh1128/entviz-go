// Issue #36 — the CESR recognizer must cover the Indexer table (indexed
// signatures) and the Dater (datetime) Matter code, instead of dropping them to
// the `raw` base64url fallback.
//
// Scope decisions (see this.i:idxs1gs0 and docs/spec.md role principle):
//
//   - Indexed signatures ARE in scope — a 64-byte controller/witness signature
//     is exactly the high-entropy cryptographic material entviz exists to
//     compare. Every IdrDex variant of one algorithm (current-only "crt", "big"
//     dual-index) collapses to ONE label; the code+index chars stay in the core,
//     so they still drive the cells. Role -> signature.
//   - The Dater is recognized only to LABEL it correctly, not to endorse
//     visualizing a datetime as entropy. A datetime is low-entropy and directly
//     human-readable, so it is recognized (better than a wrong `raw` label) but
//     carries NO role in the closed enum: role is nil, NOT the key default.
//
// Vectors are authoritative — generated from keripy 1.1.33 (keri.core.coring
// Siger / Dater), hardcoded here so the test has no keripy dependency.
package entviz

import "testing"

// (qb64, expected CESR label) — one per length class and per algorithm, small +
// big variants.
var issue36IndexedSigs = []struct{ qb64, label string }{
	// small (hs1/hs2), fs 88 / 156
	{"ABCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "Ed25519 idx sig"},                                                                   // A  Ed25519_Sig      idx1
	{"BDCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "Ed25519 idx sig"},                                                                   // B  Ed25519_Crt_Sig  idx3
	{"CCCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256k1 idx sig"},                                                                 // C  ECDSA_256k1_Sig  idx2
	{"EFCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256r1 idx sig"},                                                                 // E  ECDSA_256r1_Sig  idx5
	{"0ACCAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5", "Ed448 idx sig"}, // 0A Ed448_Sig idx2
	// big (hs2), fs 92 / 160
	{"2AAFAFCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "Ed25519 idx sig"},                                                                   // 2A Ed25519_Big_Sig    idx5
	{"2CABABCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256k1 idx sig"},                                                                 // 2C ECDSA_256k1_Big_Sig idx1
	{"2EAHAHCfhtCBiEx9ZZov6qDFWtAVn4bQgYhMfWWaL-qgxVrQFZ-G0IGITH1lmi_qoMVa0BWfhtCBiEx9ZZov6qDFWtAV", "secp256r1 idx sig"},                                                                 // 2E ECDSA_256r1_Big_Sig idx7
	{"3AAADAADAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5", "Ed448 idx sig"}, // 3A Ed448_Big_Sig idx3
}

// keri.core.coring.Dater(dts="2020-08-22T17:50:09.988921+00:00").qb64
const issue36Dater = "1AAG2020-08-22T17c50c09d988921p00c00"

func TestIssue36IndexedSigsRecognizedNotRaw(t *testing.T) {
	for _, tt := range issue36IndexedSigs {
		p, err := parseCesr(tt.qb64)
		if err != nil {
			t.Fatalf("parseCesr(%q) errored: %v", tt.qb64, err)
		}
		if p == nil {
			t.Errorf("indexed sig fell through to raw: %q", tt.qb64)
			continue
		}
		if want := "CESR " + tt.label; p.TypeName != want {
			t.Errorf("parseCesr(%q) type = %q, want %q", tt.qb64, p.TypeName, want)
		}
		// The derivation code + index stay IN the core (rendered in cells and
		// hashed), like every other CESR primitive; nothing is split to prefix.
		if p.Prefix != nil {
			t.Errorf("parseCesr(%q) prefix = %v, want nil", tt.qb64, *p.Prefix)
		}
		if p.Core != tt.qb64 {
			t.Errorf("parseCesr(%q) core = %q, want whole input", tt.qb64, p.Core)
		}
	}
}

func TestIssue36IndexedSigsDispatchViaParse(t *testing.T) {
	for _, tt := range issue36IndexedSigs {
		p, err := Parse(tt.qb64)
		if err != nil {
			t.Fatalf("Parse(%q) errored: %v", tt.qb64, err)
		}
		if p == nil || p.TypeName != "CESR "+tt.label {
			t.Errorf("Parse(%q) = %v, want CESR %s", tt.qb64, p, tt.label)
		}
	}
}

func TestIssue36IndexedSigRoleIsSignature(t *testing.T) {
	for _, tt := range issue36IndexedSigs {
		ch, err := Characterize(tt.qb64)
		if err != nil {
			t.Fatalf("Characterize(%q) errored: %v", tt.qb64, err)
		}
		if ch.SchemeAttr() != "cesr" {
			t.Errorf("Characterize(%q) scheme = %q, want cesr", tt.qb64, ch.SchemeAttr())
		}
		if ch.RoleAttr() != "signature" {
			t.Errorf("Characterize(%q) role = %q, want signature", tt.qb64, ch.RoleAttr())
		}
		if got := qStr(ch.Qualifiers, "algorithm"); got != tt.label {
			t.Errorf("Characterize(%q) qualifiers.algorithm = %q, want %q", tt.qb64, got, tt.label)
		}
	}
}

func TestIssue36IndexedSigLabelProjection(t *testing.T) {
	// Top strip reads "CESR, <algo> idx sig"; there is no " pubkey" to strip.
	ch, err := Characterize(issue36IndexedSigs[0].qb64)
	if err != nil {
		t.Fatalf("Characterize errored: %v", err)
	}
	if top, _ := ch.RenderLabel(false, "", "", -1); top != "CESR, Ed25519 idx sig" {
		t.Errorf("top = %q, want %q", top, "CESR, Ed25519 idx sig")
	}
}

func TestIssue36MatterVsIndexerDisambiguationByLength(t *testing.T) {
	// A 44-char 'A...' is the Matter Ed25519 SEED; an 88-char 'A...' is the
	// Indexer signature. Length must decide, not the leading char alone.
	seed := "A"
	for i := 0; i < 43; i++ {
		seed += "A"
	}
	if p, _ := parseCesr(seed); p == nil || p.TypeName != "CESR Ed25519 seed" {
		t.Errorf("parseCesr(seed) = %v, want CESR Ed25519 seed", p)
	}
	sig := issue36IndexedSigs[0].qb64
	if len(sig) != 88 || sig[0] != 'A' {
		t.Fatalf("test vector precondition failed: len=%d first=%c", len(sig), sig[0])
	}
	if p, _ := parseCesr(sig); p == nil || p.TypeName != "CESR Ed25519 idx sig" {
		t.Errorf("parseCesr(sig) = %v, want CESR Ed25519 idx sig", p)
	}
}

func TestIssue36DaterRecognizedNotRaw(t *testing.T) {
	p, err := parseCesr(issue36Dater)
	if err != nil {
		t.Fatalf("parseCesr(dater) errored: %v", err)
	}
	if p == nil {
		t.Fatal("Dater fell through to raw")
	}
	if p.TypeName != "CESR datetime" {
		t.Errorf("type = %q, want CESR datetime", p.TypeName)
	}
	if p.Core != issue36Dater {
		t.Errorf("core = %q, want whole input", p.Core)
	}
}

func TestIssue36DaterRoleIsNoneNotKey(t *testing.T) {
	ch, err := Characterize(issue36Dater)
	if err != nil {
		t.Fatalf("Characterize(dater) errored: %v", err)
	}
	if ch.SchemeAttr() != "cesr" {
		t.Errorf("scheme = %q, want cesr", ch.SchemeAttr())
	}
	// A datetime is recognized but carries NO closed-enum role — it MUST NOT
	// default to "key" (the reason we special-case it).
	if ch.Role != nil {
		t.Errorf("role = %q, want nil", *ch.Role)
	}
	if got := qStr(ch.Qualifiers, "algorithm"); got != "datetime" {
		t.Errorf("qualifiers.algorithm = %q, want datetime", got)
	}
}

func TestIssue36DaterLabelProjection(t *testing.T) {
	ch, err := Characterize(issue36Dater)
	if err != nil {
		t.Fatalf("Characterize errored: %v", err)
	}
	if top, _ := ch.RenderLabel(false, "", "", -1); top != "CESR, datetime" {
		t.Errorf("top = %q, want %q", top, "CESR, datetime")
	}
}
