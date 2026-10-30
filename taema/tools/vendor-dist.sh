#!/bin/sh
# Build the vendored-crates distfile that srcpkgs/taema/template lists as its
# second distfile. The tarball carries the taema/ prefix so xbps-src extracts
# it next to the source tree (build_wrksrc=taema): taema/rust/vendor/...
# Output is deterministic: sorted entries, epoch mtimes, root ownership,
# normalized modes (checkout umasks vary), and gzip without timestamps, so
# rebuilding from an unchanged tree keeps the template checksum valid.
#
# usage: tools/vendor-dist.sh [OUTDIR]      default: taema/build/dist
# prints: "<sha256>  <path>"
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
top=$(cd "$root/.." && pwd)
version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$root/src/taema/__init__.py")
out=${1:-$root/build/dist}
mkdir -p "$out"
file=$out/taema-vendor-${version}.tar.gz
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$top" && find taema/rust/vendor \( -type f -o -type l \) | LC_ALL=C sort) > "$tmp/files"
tar --mtime='@0' --owner=0 --group=0 --numeric-owner --mode='a+rX,go-w' \
    -cf - -C "$top" -T "$tmp/files" | gzip -n > "$file"
sha256sum "$file"
