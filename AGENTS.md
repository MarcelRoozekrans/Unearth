# AGENTS.md: Unearth

`unearth` is a dependency-light, read-only data-recovery and disk-forensics toolkit in pure Rust: signature
carving, filesystem-aware undelete, imaging, volume triage and an MCP server for AI agents. It ships as one
crate (library `src/lib.rs`, binary `src/main.rs`), prebuilt binaries on GitHub Releases and a Claude Code
plugin.

## Layout

- Single crate, no workspace. `ARCHITECTURE.md` has the module map.
  The authoritative list of filesystem backends is the `Volume` enum in `src/recover.rs`.
- `.claude-plugin/`, `skills/`, `.mcp.json` and `install.sh` are the plugin and installer. They are
  excluded from the published crate (`exclude` in `Cargo.toml`).
- The crate version is declared in `Cargo.toml`, `Cargo.lock`, `.claude-plugin/plugin.json`,
  `.claude-plugin/marketplace.json` and `.release-please-manifest.json`. release-please bumps all of them
  from `release-please-config.json`; never edit one by hand.
- Test fixtures are built in code (`tests/common/mod.rs`), not committed or made with `mkfs`.
- `Cargo.toml` pins `rust-version = "1.75"` and `edition = "2021"`. There is no `rust-toolchain.toml`: CI
  uses the runner's stable toolchain, so the 1.75 floor is not tested.

## Build and test

CI job `build-test` in `.github/workflows/ci.yml` runs these in order:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo llvm-cov --workspace --no-fail-fast --lcov --output-path lcov.info   # the test run, with coverage
cargo clippy --features dhat-heap --example heap_profile -- -D warnings
```

`cargo llvm-cov` needs `rustup component add rustfmt clippy llvm-tools-preview` and cargo-llvm-cov. The
Codecov upload has no gate (`fail_ci_if_error: false`, informational statuses in `codecov.yml`). This is an
exception to the org coverage rule below: neither an 80% floor nor the 1 point drop check fails a build
here, because the Rust CI does not use the `ci-baseline` workflows. Treat 80% patch coverage as the target.

Inner loop (not run by CI as such): `cargo test`, or `cargo test --test carve_test` for one integration
file. `cargo bench` runs the criterion suite in `benches/recovery.rs`; see `PERFORMANCE.md` for the dhat
profiling run. Release builds use `cargo build --release --locked` (`release.yml`).

## Conventions and gotchas

- The source device or image is opened read-only. Nothing may write back to it.
- Parsers return `Ok`/`Err` on malformed input and never panic; `tests/robustness_test.rs` fuzzes this.
  Offsets and sizes taken from disk use `saturating_add` and `saturating_mul`, every read is bounds
  checked, and an on-disk length is never a `Vec` capacity. Validate geometry before use.
- The code is `unsafe`-free by design (no `unsafe` in `src/`); keep it that way.
- Carving validators in `src/validate.rs` are conservative: `Invalid` only on a definite violation,
  `Unknown` (accepted) when unsure. More specific `SIGNATURES` entries go before a generic one with the
  same magic. New types and filesystems follow `CONTRIBUTING.md`.
- Every recovered file goes through `hash::HashingWriter` so the manifest carries its SHA-256.
- Dependencies stay minimal: `clap`, `clap_complete`, `anyhow`, `indicatif`. The JSON parser, SHA-256 and
  MCP server are hand-written on purpose; do not add a crate for them.
- `ARCHITECTURE.md` and `CONTRIBUTING.md` are the longer references. Update them when a module is added.

<!-- org-core:start sha256=08a88996bc9165f888fc0260607cfd0670cae128c323e16707c6b452ee66222d (generated from docker-nuc scripts/agents-md/org-core-personal.md; do not edit here) -->
## Org rules

These rules hold in every public MarcelRoozekrans repo.

### Commits and releases

- Conventional Commits. release-please reads them on the default branch, and the changelog sections
  in `release-please-config.json` decide which types count. The standard: `feat`, `fix`, `perf`,
  `deps` and `revert` open or update the release PR; `docs`, `test`, `refactor`, `build`, `ci`,
  `chore` and `style` do not, unless the commit is breaking or has a `Release-As:` footer. The
  release happens when that PR merges. A breaking change needs `!` or a `BREAKING CHANGE:` footer.
- A commit body never contains nested parentheses. release-please cannot parse them and silently
  drops the whole commit from the changelog, while the workflow still reports success.
- After merging a commit that should release, check that it appears in the release-please PR.

### Branches and pull requests

- Every change goes through a branch and a pull request. Never push to the default branch directly.
- A PR body says what the diff does, and nothing the diff does not do.
- Fix review findings in the PR under review, including small ones. File an issue only for a finding
  that belongs to other code, needs a design decision, is its own piece of work, or waits on
  something external.

### CI

- The .NET repos call the shared workflows of `MarcelRoozekrans/ci-baseline`, pinned to `@v1`, never
  `@main`.
- Its coverage gate fails the build when line coverage drops below the floor of 80%, and Codecov
  fails a PR that lowers project coverage by more than 1 percentage point. New code comes with
  tests.
- A repo with a lower floor documents the reason and links the issue that raises it.
<!-- org-core:end -->
