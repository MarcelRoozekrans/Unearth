# Releasing unearth

Releases are automated with [release-please](https://github.com/googleapis/release-please):
commit messages on `main` in [Conventional Commits](https://www.conventionalcommits.org)
form drive the version bump and changelog, and merging the release PR does the
rest. The tag drives everything downstream, so **the crate version and the tag
always stay in lockstep** (`0.5.0` ↔ `v0.5.0`) — release-please guarantees this.

## How a release happens

1. **Land work on `main` with Conventional Commit messages.** The commits
   *inside* a PR are what release-please parses (merge-commit subjects are
   ignored), so write them as `feat: …`, `fix: …`, `perf: …`, etc.
   - `fix:`/`perf:` → patch bump, `feat:` → minor bump, a `!` or
     `BREAKING CHANGE:` footer → major bump.
   - `docs:`, `chore:`, `ci:`, `refactor:`, `test:` never trigger a release on
     their own.
2. **release-please keeps a rolling "release PR" open** (via
   `.github/workflows/release-please.yml`) that accumulates the next version:
   changelog section generated from the commits, plus version bumps in
   `Cargo.toml`, `Cargo.lock`, `.claude-plugin/plugin.json`, and
   `.claude-plugin/marketplace.json` (wired up in `release-please-config.json`).
   Edit the PR body/changelog freely before merging — hand-written notes survive.
3. **Merge the release PR.** release-please pushes the `vX.Y.Z` tag, creates the
   GitHub Release with the changelog as notes, and then dispatches
   `release.yml`, which:
   - builds and attaches the 5 prebuilt binaries
     (Linux gnu/musl, macOS x86_64/aarch64 tar.gz, Windows zip);
   - publishes to crates.io **if** the `CARGO_REGISTRY_TOKEN` repository secret
     is set (a crates.io token with publish scope, from
     <https://crates.io/settings/tokens>). Without the secret that job skips
     and you run `cargo publish` locally (needs `cargo login` and a verified
     email on the crates.io account).

## After the release

Smoke-test the install paths:

- [ ] `curl -fsSL https://raw.githubusercontent.com/MarcelRoozekrans/unearth/main/install.sh | sh`
- [ ] `cargo binstall unearth` — must find the new tag's assets.
- [ ] `cargo install unearth` — `unearth --version` reports the new version.
- [ ] Plugin, in Claude Code: `/plugin marketplace add MarcelRoozekrans/Unearth`
      then `/plugin install unearth@unearth-tools`.

## Manual release (fallback)

If the automation is unavailable, the old path still works: bump the versions
(crate + both plugin manifests), roll `CHANGELOG.md`, land it on `main`, then:

```sh
git fetch origin
git tag -a v0.X.Y origin/main -m "unearth 0.X.Y"
git push origin v0.X.Y
cargo publish
```

A manually pushed tag triggers `release.yml` directly. Afterwards update
`.release-please-manifest.json` to the released version so release-please stays
in sync.

## Known gotchas

- **CI does not run on the release PR.** release-please opens its PR with the
  default `GITHUB_TOKEN`, and GitHub suppresses workflow runs for events that
  token creates. The PR only touches versions and the changelog, so this is
  acceptable; if you want CI on it, give the action a personal access token via
  the workflow's `token` input.
- **The tag push doesn't fire `release.yml` by itself** for the same reason —
  that's why `release-please.yml` explicitly dispatches it
  (`workflow_dispatch` is exempt from the suppression). If binaries are ever
  missing after a release, re-run: `gh workflow run release.yml --ref vX.Y.Z`.
- **Runner retirement.** The v0.4.0 release stalled because the Intel macOS job
  targeted the retired `macos-13` runner; it now cross-compiles
  `x86_64-apple-darwin` on `macos-latest`. If a matrix job sits **queued**
  while the rest run, suspect a retired runner label.
- **Re-running is safe.** `release.yml` skips creating an existing release and
  re-uploads assets with `--clobber`.
- **Repo-name casing.** The repo is `Unearth`, in-repo URLs use `unearth`;
  GitHub resolves both on `github.com`, `raw.githubusercontent.com`, and
  release downloads (verified 2026-07-17).
- **Legacy changelog.** `CHANGELOG.md` entries up to 0.4.0 are hand-written
  (Keep a Changelog style); release-please prepends its generated sections
  above them. If a `## [Unreleased]` section still exists when the next release
  PR opens, fold its content into that PR's changelog section by editing the PR,
  then delete the section.
