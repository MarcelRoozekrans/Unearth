# Releasing unearth

A release is a version bump on `main` plus a `v*` tag. The tag drives
everything: `release.yml` builds the binaries, and cargo-binstall derives its
download URLs from the crate version — so **the crate version and the pushed
tag must always match** (`0.4.0` ↔ `v0.4.0`).

## 1. Prepare the release on `main`

- [ ] Bump `version` in `Cargo.toml`; run `cargo build` so `Cargo.lock` follows.
- [ ] Bump the version in `.claude-plugin/plugin.json` and
      `.claude-plugin/marketplace.json` to match.
- [ ] Roll `CHANGELOG.md`: retitle `[Unreleased]` to the new version with the
      date, and add a fresh empty `[Unreleased]` section above it.
- [ ] `cargo fmt --check && cargo clippy --all-targets && cargo test` — clean.
- [ ] `cargo publish --dry-run` and check `cargo package --list` still excludes
      repo-only files (`.github`, `.claude-plugin`, `skills`, `.mcp.json`,
      `install.sh`).
- [ ] Land all of the above on `main` (PR or direct, per repo habit).

## 2. Tag — this publishes the binaries

```sh
git fetch origin
git tag -a v0.X.Y origin/main -m "unearth 0.X.Y"
git push origin v0.X.Y
```

- [ ] Watch the **Release** run under Actions until green.
- [ ] Confirm the GitHub release has **5 assets**:
      `unearth-v0.X.Y-<target>.tar.gz` (Linux gnu/musl, macOS x86_64/aarch64)
      and `...-x86_64-pc-windows-msvc.zip`.

If a build job fails and the workflow needs fixing: fix it on `main`, then
re-point the tag and force-push it — the workflow is idempotent (it skips
creating the existing release and re-uploads assets with `--clobber`).

## 3. Publish to crates.io

```sh
cargo publish
```

Needs `cargo login` with a token from <https://crates.io/settings/tokens>
(scopes: `publish-new`, `publish-update`) and a **verified email** on the
crates.io account.

## 4. Smoke-test the install paths

- [ ] `curl -fsSL https://raw.githubusercontent.com/MarcelRoozekrans/unearth/main/install.sh | sh`
      (or verify the latest-release redirect + asset URL it constructs).
- [ ] `cargo binstall unearth` — must find the new tag's assets.
- [ ] `cargo install unearth` — `unearth --version` reports the new version.
- [ ] Plugin, in Claude Code: `/plugin marketplace add MarcelRoozekrans/Unearth`
      then `/plugin install unearth@unearth-tools`.

## Known gotchas

- **Runner retirement.** The v0.4.0 release stalled because the Intel macOS job
  targeted the retired `macos-13` runner; it now cross-compiles
  `x86_64-apple-darwin` on `macos-latest`. If a matrix job sits **queued**
  while the rest run, suspect a retired runner label.
- **Repo-name casing.** The repo is `Unearth`, in-repo URLs use `unearth`;
  GitHub resolves both on `github.com`, `raw.githubusercontent.com`, and
  release downloads (verified 2026-07-17).
- **binstall pinning.** `[package.metadata.binstall]` builds
  `.../download/v{version}/...`, so publishing to crates.io without pushing the
  matching tag breaks `cargo binstall` for that version.
