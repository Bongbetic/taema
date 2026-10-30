#!/bin/sh
# Build a taema .xbps without a void-packages checkout and index it in a local repository.
#   tools/build-xbps.sh [REPO_DIR]        default: build/repo
# Install with: sudo xbps-install --repository="$PWD/build/repo" taema
# Set XBPS_ARCH=x86_64-musl for the static musl package (needs the musl Rust
# target: rustup target add x86_64-unknown-linux-musl); the default is the
# host architecture. Packages are built only for x86_64 glibc and x86_64 musl.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$here/src/taema/__init__.py")
revision=${REVISION:-1}
repo=${1:-$here/build/repo}
# The musl builders report x86_64 from uname, so detect the libc too.
default_arch() {
    _arch=$(uname -m)
    if ldd --version 2>&1 | grep -qi musl; then
        case $_arch in *-musl) ;; *) _arch=${_arch}-musl;; esac
    fi
    printf '%s' "$_arch"
}
arch=${XBPS_ARCH:-$(default_arch)}
mkdir -p "$repo"
repo=$(cd "$repo" && pwd)
echo "building taema ${version}_${revision} for ${arch}"

# SKIP_TESTS=1 skips the suite when the first arch already ran it (vmh).
if [ -z "${SKIP_TESTS:-}" ]; then
    make -C "$here" test
fi
stage=$(mktemp -d)
eventd_stage=$(mktemp -d)
trap 'rm -rf "$stage" "$eventd_stage"' EXIT
make -C "$here" DESTDIR="$stage" XBPS_ARCH="$arch" install
install -Dm644 "$here/../LICENSE" "$stage/usr/share/licenses/taema/LICENSE"
# xbps-create picks up INSTALL and REMOVE from the root of the staged tree; these are the
# same files xbps-src installs for srcpkgs/taema.
install -m755 "$here/srcpkgs/taema/INSTALL" "$stage/INSTALL"
install -m755 "$here/srcpkgs/taema/REMOVE" "$stage/REMOVE"

pkg="taema-${version}_${revision}"
eventd_pkg="taema-eventd-${version}_${revision}"
rm -f "$repo/$pkg.$arch.xbps" "$repo/$eventd_pkg.$arch.xbps"
# The optional forwarder ships apart so installs without TAEMA_EVENTD stay lean.
mkdir -p "$eventd_stage/usr/bin"
mv "$stage/usr/bin/taema-eventd" "$eventd_stage/usr/bin/taema-eventd"
(cd "$repo" && xbps-create -A "$arch" -n "$pkg" \
    -s "Dependency-aware, self-managing cgroup v2 process scopes" \
    -D "python3>=3.11_1 iproute2>=0 util-linux>=0 sudo>=0 runit>=0 shadow>=0 tzdata>=0" \
    -l custom:PolyForm-Noncommercial-1.0.0 -H https://github.com/Bongbetic/taema \
    -m "soubarnak <soubarna@live.in>" \
    --config-files "/etc/taema/taema.toml /etc/taema/units/*.toml" \
    "$stage")
(cd "$repo" && xbps-create -A "$arch" -n "$eventd_pkg" \
    -s "Optional kernel process-event forwarder for taema" \
    -D "taema>=${version}_${revision} python3>=3.11_1" \
    -l custom:PolyForm-Noncommercial-1.0.0 -H https://github.com/Bongbetic/taema \
    -m "soubarnak <soubarna@live.in>" \
    "$eventd_stage")
XBPS_ARCH=$arch xbps-rindex -f -a "$repo/$pkg.$arch.xbps"
XBPS_ARCH=$arch xbps-rindex -f -a "$repo/$eventd_pkg.$arch.xbps"
echo "built $repo/$pkg.$arch.xbps $repo/$eventd_pkg.$arch.xbps"
