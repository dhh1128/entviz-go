This repo is a port of a sister repo, https://github.com/dhh1128/entviz, which
contains the entviz spec, other important documentation, and the reference impl
of entviz in Python. The repos are intended to be sister folders on disk and
may already exist in your dev environment. New features can be added here,
but should never violate the specification or the documentation about the
entviz technology that have their definitive embodiment in the entviz repo.

This is a **conformant Go port**: the canonical algorithm and spec live in
dhh1128/entviz; this module mirrors the certified Rust port (dhh1128/entviz-rs)
line for line and is verified byte-for-byte against the shared conformance
corpus.

## Testing Protocol

This repository has an established test suite. Follow strict TDD:
1. Write one or more failing tests that capture each requirement (including
   both happy paths and its edge cases/unhappy paths) before implementing.
2. Implement until all tests pass.
3. Never commit unless all tests pass. Coverage of any code you touch
   must not decrease.

The local gates mirror CI:

```sh
gofmt -l .            # must print nothing
go vet ./...
go test ./... -race -cover
```

Conformance (requires the sibling ../entviz checkout + a Python venv with lxml):

```sh
go build -o /tmp/entviz-go-conformance ./cmd/entviz-conformance
cd ../entviz && PYTHONPATH=src:. python -m compliance.runner \
  --impl-cmd '/tmp/entviz-go-conformance' --tiers AB
# -> 54/54 vectors passed
```

## Versioning

The module version encodes the entviz **spec** level it is compliant with:

> **`0.<spec-major>.x`** — e.g. `0.10.x` ⇒ compliant with entviz spec **v10**
> (the same convention the Python reference and entviz-rs use).

The canonical spec level is the `SpecVersion` constant in `core.go`, and the
per-impl stamp emitted as `data-entviz-lib` is the `LibVersion` constant.

## CI and Documentation

This repo has CI under `.github/workflows/` (`ci.yml` runs gofmt + go vet +
`go test -race` + a Tier-A conformance job against the reference corpus;
`release.yml` is the tag-triggered GitHub-release pipeline). Treat CI as part of
the code you maintain, not an afterthought:
- Before you consider a change done, run the same gates CI runs locally.
- When you add or change behavior, keep the workflows in sync.

When writing or modifying GitHub Actions workflows, always SHA-pin every
third-party action to a node24-runtime (or composite/docker) release. Avoid
versions pinned to Node.js 16 or 20 (both deprecated by GitHub). Check the
GitHub Marketplace for each action's current release.
