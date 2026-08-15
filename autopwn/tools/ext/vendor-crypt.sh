#!/usr/bin/env bash
# Encrypt/decrypt the vendored external PoCs (autopwn/tools/ext/*.py) so they can
# be version-controlled in this PUBLIC repo WITHOUT redistributing readable
# third-party exploit code. Same idea as git-crypt (which has no Windows package):
# an AES-256 blob `*.py.gpg` is committed, the plaintext `*.py` stays gitignored,
# and the key lives OUTSIDE the repo.
#
# The key file is the ONLY thing that can decrypt these blobs — BACK IT UP
# (password manager / offline). Lose it and the PoCs are unrecoverable.
#
#   AUTOPWN_EXT_KEY  path to the key file (default: ~/.autopwn-secrets/ext-vendor.key)
#
# Usage:
#   ./vendor-crypt.sh lock     # (re)encrypt every ext/*.py      -> ext/*.py.gpg
#   ./vendor-crypt.sh unlock   # decrypt every ext/*.py.gpg      -> ext/*.py
set -euo pipefail

KEYFILE="${AUTOPWN_EXT_KEY:-$HOME/.autopwn-secrets/ext-vendor.key}"
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -s "$KEYFILE" ] || { echo "key file not found: $KEYFILE (set AUTOPWN_EXT_KEY)"; exit 1; }

g() { gpg --batch --yes --quiet --passphrase-file "$KEYFILE" "$@"; }

case "${1:-}" in
  lock)
    shopt -s nullglob
    for f in "$DIR"/*.py; do
      g --symmetric --cipher-algo AES256 -o "$f.gpg" "$f"
      echo "locked   $(basename "$f") -> $(basename "$f").gpg"
    done ;;
  unlock)
    shopt -s nullglob
    for f in "$DIR"/*.py.gpg; do
      out="${f%.gpg}"
      g --decrypt -o "$out" "$f"
      echo "unlocked $(basename "$f") -> $(basename "$out")"
    done ;;
  *) echo "usage: $0 {lock|unlock}"; exit 2 ;;
esac
