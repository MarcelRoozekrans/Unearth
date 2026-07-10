#!/bin/sh
# filerecovery installer — download a prebuilt binary from the latest GitHub
# Release and drop it on your PATH. No Rust toolchain required.
#
#   curl -fsSL https://raw.githubusercontent.com/MarcelRoozekrans/FileRecovery/main/install.sh | sh
#
# Environment overrides:
#   FILERECOVERY_VERSION   tag to install (e.g. v0.4.0); default: latest release
#   FILERECOVERY_BIN_DIR   install directory; default: $HOME/.local/bin
#
# POSIX sh; needs curl (or wget) and tar. For Windows, download the .zip asset
# from the Releases page instead.

set -eu

REPO="MarcelRoozekrans/FileRecovery"
BIN="filerecovery"
BIN_DIR="${FILERECOVERY_BIN_DIR:-$HOME/.local/bin}"

err() {
	echo "install: $*" >&2
	exit 1
}

# --- pick a downloader --------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
	dl() { curl -fsSL "$1"; }
	dl_head_location() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
	dl() { wget -qO- "$1"; }
	dl_head_location() { wget -q -O /dev/null --max-redirect=10 "$1" 2>&1 || true; }
else
	err "need curl or wget"
fi
command -v tar >/dev/null 2>&1 || err "need tar"

# --- map OS/arch to a release target triple -----------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
	Linux)
		case "$arch" in
			x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
			*) err "no prebuilt Linux binary for '$arch'; install with 'cargo install $BIN'" ;;
		esac
		;;
	Darwin)
		case "$arch" in
			arm64 | aarch64) target="aarch64-apple-darwin" ;;
			x86_64) target="x86_64-apple-darwin" ;;
			*) err "unsupported macOS arch '$arch'" ;;
		esac
		;;
	*)
		err "unsupported OS '$os'; on Windows download the .zip from https://github.com/$REPO/releases"
		;;
esac

# --- resolve the version tag --------------------------------------------------
tag="${FILERECOVERY_VERSION:-}"
if [ -z "$tag" ]; then
	# Follow the /releases/latest redirect and read the tag from the final URL.
	final="$(dl_head_location "https://github.com/$REPO/releases/latest")" ||
		err "could not determine the latest release"
	tag="${final##*/tag/}"
	[ "$tag" != "$final" ] || err "could not parse the latest release tag from '$final'"
fi

asset="${BIN}-${tag}-${target}.tar.gz"
url="https://github.com/$REPO/releases/download/${tag}/${asset}"

# --- download, extract, install -----------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ($tag)…"
dl "$url" >"$tmp/$asset" || err "download failed: $url"
tar xzf "$tmp/$asset" -C "$tmp" || err "extract failed (corrupt or wrong asset?)"
[ -f "$tmp/$BIN" ] || err "archive did not contain '$BIN'"

mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/$BIN" "$BIN_DIR/$BIN" 2>/dev/null ||
	{ cp "$tmp/$BIN" "$BIN_DIR/$BIN" && chmod 0755 "$BIN_DIR/$BIN"; }

echo "Installed $BIN $tag to $BIN_DIR/$BIN"
case ":$PATH:" in
	*":$BIN_DIR:"*) ;;
	*) echo "Note: $BIN_DIR is not on your PATH. Add it, e.g.:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
