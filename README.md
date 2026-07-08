# entviz-go

[![CI](https://github.com/dhh1128/entviz-go/actions/workflows/ci.yml/badge.svg)](https://github.com/dhh1128/entviz-go/actions/workflows/ci.yml)
[![Release](https://github.com/dhh1128/entviz-go/actions/workflows/release.yml/badge.svg)](https://github.com/dhh1128/entviz-go/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dhh1128/entviz-go.svg)](https://pkg.go.dev/github.com/dhh1128/entviz-go)
[![Spec](https://img.shields.io/badge/entviz%20spec-v10-informational)](https://github.com/dhh1128/entviz)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Go implementation of [entviz](https://github.com/dhh1128/entviz) (spec **v10**)
— visualize high-entropy values as comparable SVG diagrams.

## Status: certified against the v10 conformance corpus ✅

A full, self-contained implementation that passes the shared conformance corpus
at **Tier A** (render model) **+ Tier B** (canonical raster) for every render
vector, rejects every error vector, and satisfies every invariant pair
(**54/54**). What's here:

- **`core.go`** — the deterministic shared core: alphabets, tokenization +
  24-bit quant extension, the SHA-512 fingerprint, ftok median/quartile
  selection, the Oklab color rules + weighted-RGB edge selection, and grid
  selection.
- **`entropy.go`** — the format-specific parsers (hex, UUID, Ethereum w/
  EIP-55, ULID, base58 / bech32 / base32 chains, CESR, LEI, snowflake, SWHID /
  gitoid semantic-prefix fold, IPFS CID, SSH, …) + the disproof-based alphabet
  detection and large-input (head / fingerprint-middle / tail) tokenization.
- **`keccak.go`** — vendored Keccak-256 for EIP-55 checksum validation.
- **`pipeline.go`** — the SVG renderer: geometry, 24-box surround,
  fingerprint-edge cells, ellipse overlay, color bar + markers, blank-cell map,
  quartile marks, labels, borders — emitting the normative `data-*` profile.
- **`cmd/entviz-conformance`** — the conformance CLI (the stdin→stdout contract
  in the entviz repo's `compliance/README.md`).

The module depends only on the Go standard library.

## How to consume

```sh
go get github.com/dhh1128/entviz-go
```

```go
package main

import (
	"fmt"
	"os"

	entviz "github.com/dhh1128/entviz-go"
)

func main() {
	// Render(entropy, targetAR, fontSizePt, note) -> (svg, error).
	// note is *string; pass nil for no note.
	svg, err := entviz.Render("a1b2c3d4e5f6a7b8", 1.0, 12.0, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "render rejected:", err)
		os.Exit(1)
	}
	fmt.Print(svg)
}
```

`Render` rejects out-of-range parameters (font size must be 6–30 pt, aspect
ratio 0.01–100), notes that are not printable ASCII (U+0020–U+007E) or longer
than 10 characters, and Ethereum addresses whose EIP-55 mixed-case checksum is
invalid (the error names the first mismatched-case position).

`Characterize` returns the structured [entropy characterization](https://dhh1128.github.io/entviz/integration-guide/#the-characterization-model)
— the same eight fields entviz emits as `data-*` attributes on the rendered SVG:

```go
ch, err := entviz.Characterize("550e8400-e29b-41d4-a716-446655440000")
// ch.Scheme -> *"uuid", ch.Role -> *"identifier", ch.SizeBits -> 128
// ch.QualifiersJSON() / ch.PartsJSON() give the compact-JSON forms.
```

For embedding entviz across all five languages, see the
[Developer Integration Guide](https://dhh1128.github.io/entviz/integration-guide/).

## Build + test

```sh
gofmt -l .                                  # must print nothing
go vet ./...
go test ./... -race -cover                  # unit tests + corpus invariants
go build ./...
```

Conformance against the golden corpus (requires a checkout of the entviz
reference repo as a sibling `../entviz` and a Python venv with `lxml`):

```sh
go build -o /tmp/entviz-go-conformance ./cmd/entviz-conformance

# from a checkout of the entviz reference repo (sibling ../entviz):
PYTHONPATH=src:. python -m compliance.runner \
  --impl-cmd '/tmp/entviz-go-conformance' --tiers AB
# -> 54/54 vectors passed
```

## Spec compliance & versioning

The module version encodes the entviz **spec** level it is compliant with:

> **`0.<spec-major>.x`** — e.g. `0.10.x` ⇒ compliant with entviz spec **v10**
> (the same convention the Python reference and entviz-rs use, where spec v10 ↔
> `0.10.0`).

A spec bump (v10 → v11) is a **minor** release here (`0.10.x` → `0.11.0`); a
**patch** is a module-only change within a spec version. The canonical spec
level is the `SpecVersion` constant in `core.go`; the per-impl stamp emitted as
`data-entviz-lib` is `LibVersion`.

CI **surfaces spec drift**: the `conformance` job checks out the public
[entviz reference](https://github.com/dhh1128/entviz), compares its
`SPEC_VERSION` to this module's, and runs the Tier-A conformance suite. When the
reference spec is *ahead* of this module it warns loudly (without blocking
unrelated PRs); when the versions match (or this module is ahead) conformance is
a hard gate.

## Releasing

Go has no central package registry to push to — pkg.go.dev indexes the module
straight from a pushed Git tag — so a "release" here is **creating the version
tag and the GitHub release**.

Releases are **human-run** (agents must not push tags). From a clean, in-sync
`main`, bump the `LibVersion` constant in `core.go`, commit, then tag and push:

```sh
git tag v0.10.0
git push origin v0.10.0
```

The tag triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which re-runs the full gate set (gofmt + vet + `go test -race` + Tier-A
conformance), verifies the tag matches `LibVersion`, and creates the GitHub
release. pkg.go.dev then indexes the new tag automatically.

## Sister projects

- **[entviz](https://github.com/dhh1128/entviz)** — the Python reference
  implementation and the **canonical spec** (`docs/spec.md`), plus the gallery
  and the shared conformance corpus this module is certified against.
- **[entviz-rs](https://github.com/dhh1128/entviz-rs)** — the certified Rust
  port (this module mirrors it line for line).
- **[entviz-js](https://github.com/dhh1128/entviz-js)** — the certified
  TypeScript/JavaScript port.

## License

[Apache License 2.0](LICENSE). See also [`NOTICE`](NOTICE).
