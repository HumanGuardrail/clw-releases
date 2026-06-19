#!/bin/sh
# install.sh — clw one-line installer (macOS / Linux), curl-pipe fallback.
#
# Usage (one-liner):
#   curl --proto '=https' --tlsv1.2 -fsSL \
#     "https://raw.githubusercontent.com/humangr-labs/clw-releases/main/install.sh" \
#     | CLW_VERSION=<version> sh
#
# PREFERRED INSTALL IS HOMEBREW, NOT THIS SCRIPT:
#   brew install humangr-labs/clw/clw
# Brew is preferred on macOS because a brew-installed (formula) binary is NOT
# Gatekeeper-quarantined, whereas a curl-downloaded binary IS — this script
# strips the quarantine attribute itself (see the macOS step below), but brew
# avoids the issue entirely. See docs/INSTALL.md.
#
# The download surface is PUBLIC and ANONYMOUS: release assets live on the public
# mirror repo humangr-labs/clw-releases as GitHub Release assets (see
# docs/DISTRIBUTION.md). No credential is needed to fetch them.
#
# What it does:
#   - detects OS (uname -s) + arch (uname -m) and maps to the release target
#     triple naming from .github/workflows/release.yml (clw-<version>-<target>);
#   - downloads the binary, the signed SHA256SUMS, and its minisign signature;
#   - verifies the minisign detached signature over SHA256SUMS FIRST — against a
#     trust-root public key EMBEDDED in this script (NOT a fetched key), then the
#     binary's SHA-256 checksum (hard fail on mismatch; NEVER skippable);
#   - on macOS, strips the com.apple.quarantine xattr from the downloaded binary
#     so Gatekeeper does not block a curl-installed CLI;
#   - installs to a no-sudo per-user prefix ($HOME/.local/bin by default),
#     idempotently (re-running upgrades in place);
#   - prints a PATH + `clw --version` next-step message.
#
# Windows is OUT OF SCOPE for this POSIX shell installer — see docs/INSTALL.md
# for the direct .exe download recipe.
#
# Contract (kept in lockstep with release.yml / docs/DISTRIBUTION.md):
#   asset basename : clw-<version>-<target>           (no ext on macOS/Linux)
#   checksums      : SHA256SUMS            (one `<hex>  <file>` line per artifact)
#   signature      : SHA256SUMS.minisig    (minisign detached over SHA256SUMS)
#   trust root     : EMBEDDED in this script (CLW_MINISIGN_PUBKEY below). The
#                    published docs/minisign.pub is NOT fetched/trusted at install
#                    time — the embedded constant IS the pin (mirror/CDN cannot
#                    swap both sig + key past it). Keep it byte-equal to the key
#                    line in docs/minisign.pub.
#   asset URL      : <base-url>/v<version>/<file>
#
# NOTE on versioning: the release pipeline publishes one GitHub Release per tag
# (v<concrete-version>) on the mirror. There is no `latest/` asset alias, so
# CLW_VERSION is REQUIRED — there is no safe default to fall back to. (Verify:
# .github/workflows/release.yml publish step + docs/DISTRIBUTION.md.)
#
# Overridable via env (CLW_VERSION is REQUIRED):
#   CLW_VERSION        REQUIRED — concrete version to install (e.g. 0.1.0). No
#                      default: the surface has no `latest` alias to resolve.
#   CLW_BASE_URL       download surface base URL (no trailing slash).
#   CLW_INSTALL_DIR    install prefix (default: $HOME/.local/bin).
#   CLW_SKIP_SIGNATURE if "1", proceed when minisign is unavailable instead of
#                      hard-failing. Checksum verification is NEVER skippable.

set -eu

# --- constants ---------------------------------------------------------------
# Public mirror repo (humangr-labs/clw-releases) GitHub Release download base.
# Assets are at <base>/v<version>/<file> — anonymous, no auth.
DEFAULT_BASE_URL="https://github.com/humangr-labs/clw-releases/releases/download"

# EMBEDDED minisign trust root (the pin). This is the production public key —
# byte-equal to docs/minisign.pub in the source repo. We verify the release
# signature against THIS embedded key, never a key fetched from the (public,
# anonymous) download surface: a mirror/CDN compromise that swapped both the
# signature AND a fetched pubkey would otherwise pass verification silently
# (trust-on-first-use). With the key pinned here, an attacker would have to
# forge a signature under the real private key, which they do not hold.
#   key id: 4B57B8B54A0E396D
# Two lines: the `untrusted comment:` line + the base64 key line, exactly as
# minisign expects in a .pub file.
MINISIGN_KEY_ID="4B57B8B54A0E396D"
CLW_MINISIGN_PUBKEY_COMMENT="untrusted comment: minisign public key ${MINISIGN_KEY_ID}"
CLW_MINISIGN_PUBKEY_LINE="RWRtOQ5KtbhXSxt24bM/T+ndWfjUDUm8c7gr8194pxnyWEUS/CTDIkm0"

# --- cleanup trap (runs on any exit, incl. set -e abort) ---------------------
TMPDIR_INSTALL=""
cleanup() {
  [ -n "$TMPDIR_INSTALL" ] && rm -rf "$TMPDIR_INSTALL" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- helpers -----------------------------------------------------------------
err() { printf 'clw-install: error: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }
info() { printf 'clw-install: %s\n' "$*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# sha256sums_hex_for <asset> <sumsfile>
# Print the leading hex digest for <asset> from a `<hex>  <file>` SHA256SUMS
# file, matched LITERALLY (a shell `case` glob, not a regex) so a version's '.'
# chars cannot act as wildcards and an unrelated entry cannot mask a mismatch.
# Defined at top level (not inline in a `$()`), which keeps the `case` arm's `)`
# out of a command substitution — some POSIX shells (e.g. bash 3.2) misparse it
# there. Prints nothing (empty) when there is no exact match.
sha256sums_hex_for() {
  _asset="$1"; _sums="$2"
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in
      *"  ${_asset}")
        printf '%s' "${_line%% *}"   # leading hex digest, up to the first space
        return 0
        ;;
    esac
  done < "$_sums"
  return 0
}

# --- preflight: required tooling --------------------------------------------
need_cmd uname
need_cmd mkdir
need_cmd chmod
need_cmd mv

# A downloader: prefer curl, fall back to wget.
DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
else
  die "need curl or wget to download the binary"
fi

# A SHA-256 checker: sha256sum (Linux) or shasum (macOS) — both emit the same
# `<hex>  <file>` format that SHA256SUMS uses.
SHA_TOOL=""
if command -v sha256sum >/dev/null 2>&1; then
  SHA_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_TOOL="shasum -a 256"
else
  die "need sha256sum or shasum to verify the download"
fi

# --- version (REQUIRED; no `latest` alias exists on the surface) ------------
# The release pipeline publishes one Release per tag (v<concrete-version>) with
# no `latest` asset pointer, so we refuse to guess a default.
if [ -z "${CLW_VERSION:-}" ]; then
  die "CLW_VERSION is not set.
  The clw mirror publishes each release under a CONCRETE version tag
  (v<version>) and has NO 'latest' alias, so a version is required.
  Set the version you want and re-run, e.g.:
      export CLW_VERSION=0.1.0
  (See the project release notes / docs/INSTALL.md for the current version.)"
fi

# --- detect OS + arch, map to the release target triple ----------------------
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "$UNAME_S" in
  Darwin) os="apple-darwin" ;;
  Linux)  os="unknown-linux-gnu" ;;
  *)
    die "unsupported OS: '$UNAME_S'. This installer supports macOS and Linux only;
  see docs/INSTALL.md for the direct Windows .exe recipe."
    ;;
esac

case "$UNAME_M" in
  arm64|aarch64) arch="aarch64" ;;
  x86_64|amd64)  arch="x86_64" ;;
  *)
    die "unsupported architecture: '$UNAME_M'. Supported: arm64/aarch64, x86_64."
    ;;
esac

TARGET="${arch}-${os}"

# --- resolve config ----------------------------------------------------------
BASE_URL="${CLW_BASE_URL:-$DEFAULT_BASE_URL}"
BASE_URL="${BASE_URL%/}"   # strip any trailing slash
VERSION="$CLW_VERSION"     # required; validated above
INSTALL_DIR="${CLW_INSTALL_DIR:-$HOME/.local/bin}"

ASSET="clw-${VERSION}-${TARGET}"
REL_DIR="${BASE_URL}/v${VERSION}"

info "target:   ${TARGET}"
info "version:  ${VERSION}"
info "asset:    ${ASSET}"
info "install:  ${INSTALL_DIR}/clw"

# --- workspace ---------------------------------------------------------------
TMPDIR_INSTALL="$(mktemp -d 2>/dev/null || mktemp -d -t clw-install)"
[ -d "$TMPDIR_INSTALL" ] || die "could not create a temp directory"

# --- download (anonymous; public mirror release assets) ----------------------
# fetch <url> <dest>
fetch() {
  _url="$1"; _dest="$2"
  if [ "$DOWNLOADER" = "curl" ]; then
    # --proto '=https' --tlsv1.2: refuse plaintext/downgrade. -f: fail on HTTP errors.
    # -L: follow GitHub's redirect to the asset CDN.
    curl --proto '=https' --tlsv1.2 -fsSL \
      -H "User-Agent: clw-install/${VERSION}" \
      -o "$_dest" "$_url"
  else
    # --https-only refuses plaintext.
    wget -q --https-only \
      --header="User-Agent: clw-install/${VERSION}" \
      -O "$_dest" "$_url"
  fi
}

info "downloading binary + checksums + signature..."
fetch "${REL_DIR}/${ASSET}"            "${TMPDIR_INSTALL}/${ASSET}" \
  || die "failed to download ${ASSET} (check version and network)"
fetch "${REL_DIR}/SHA256SUMS"          "${TMPDIR_INSTALL}/SHA256SUMS" \
  || die "failed to download SHA256SUMS"
fetch "${REL_DIR}/SHA256SUMS.minisig"  "${TMPDIR_INSTALL}/SHA256SUMS.minisig" \
  || die "failed to download SHA256SUMS.minisig"
# NOTE: we do NOT fetch minisign.pub from the download surface — the trust root
# is the EMBEDDED key (CLW_MINISIGN_PUBKEY_*), materialized just before verify.

# --- verify signature over the checksum file (before trusting the checksums) -
if command -v minisign >/dev/null 2>&1; then
  info "verifying minisign signature over SHA256SUMS (embedded trust root ${MINISIGN_KEY_ID})..."
  # Materialize the EMBEDDED pubkey into a file WE control (never a fetched one).
  # minisign reads the trust root from this -p file; because it is built from the
  # in-script constant, a swapped remote key cannot influence verification.
  printf '%s\n%s\n' \
    "$CLW_MINISIGN_PUBKEY_COMMENT" "$CLW_MINISIGN_PUBKEY_LINE" \
    > "${TMPDIR_INSTALL}/.clw-trust.pub"
  ( cd "$TMPDIR_INSTALL" && minisign -V -p .clw-trust.pub -m SHA256SUMS ) \
    || die "minisign signature verification FAILED against the embedded trust root (${MINISIGN_KEY_ID}) — refusing to install."
  info "signature OK (embedded trust root: ${MINISIGN_KEY_ID})"
else
  if [ "${CLW_SKIP_SIGNATURE:-}" = "1" ]; then
    info "WARNING: minisign not installed and CLW_SKIP_SIGNATURE=1 — proceeding on checksum only."
    info "         Install minisign and re-run to verify the signed trust chain."
  else
    die "minisign is not installed, so the signed checksum file cannot be verified.
  Install minisign (brew install minisign / apt-get install minisign) and re-run,
  or set CLW_SKIP_SIGNATURE=1 to proceed on the SHA-256 checksum alone (NOT recommended)."
  fi
fi

# --- verify the SHA-256 checksum of the binary (NEVER skippable) -------------
info "verifying SHA-256 checksum..."
# SHA256SUMS lists every published file by its basename in `<hex>  <file>` form.
# Pull our asset's digest with a LITERAL match (see sha256sums_hex_for) so a
# version's '.' chars cannot act as regex wildcards and an unrelated entry cannot
# mask a mismatch, then rebuild a clean one-entry checksum file. (Defense-in-depth:
# the minisign signature over SHA256SUMS is already verified above; this guards
# the basename match itself.)
EXPECTED_HEX="$(sha256sums_hex_for "$ASSET" "${TMPDIR_INSTALL}/SHA256SUMS")"
[ -n "$EXPECTED_HEX" ] || die "SHA256SUMS has no entry for ${ASSET} — refusing to install."

# Run the checker from the temp dir so the bare basename resolves. Rebuild the
# checksum line ourselves (clean hex + two spaces + literal basename).
printf '%s  %s\n' "$EXPECTED_HEX" "$ASSET" > "${TMPDIR_INSTALL}/.expected.sha256"
( cd "$TMPDIR_INSTALL" && $SHA_TOOL -c .expected.sha256 >/dev/null 2>&1 ) \
  || die "SHA-256 checksum MISMATCH for ${ASSET} — the download is corrupt or tampered. NOT installing."
info "checksum OK"

# --- macOS: strip Gatekeeper quarantine on the curl-downloaded binary --------
# A curl-downloaded binary is tagged com.apple.quarantine by the OS, so Gatekeeper
# would block it on first run. (A brew *formula* install is NOT quarantined — which
# is why brew is the preferred path; see docs/INSTALL.md.) Strip it post-verify.
if [ "$UNAME_S" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "${TMPDIR_INSTALL}/${ASSET}" 2>/dev/null || true
fi

# --- install (idempotent, no sudo) ------------------------------------------
mkdir -p "$INSTALL_DIR" || die "could not create install dir: $INSTALL_DIR"
chmod 0755 "${TMPDIR_INSTALL}/${ASSET}"
# Atomic-ish replace: mv over any existing binary upgrades in place.
mv -f "${TMPDIR_INSTALL}/${ASSET}" "${INSTALL_DIR}/clw" \
  || die "could not install to ${INSTALL_DIR}/clw"

info "installed clw to ${INSTALL_DIR}/clw"

# --- post-install message ----------------------------------------------------
printf '\n'
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*)
    info "${INSTALL_DIR} is already on your PATH."
    ;;
  *)
    info "NOTE: ${INSTALL_DIR} is not on your PATH. Add it, e.g.:"
    # The literal $PATH is intentional — we print a line the user pastes verbatim.
    # shellcheck disable=SC2016
    printf '    export PATH="%s:$PATH"\n' "$INSTALL_DIR"
    info "(put that line in your shell profile — see docs/INSTALL.md for per-shell detail)."
    ;;
esac
printf '\n'
info "verify with:  clw --version"
