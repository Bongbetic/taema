#!/bin/sh
# Build a taema .xbps without a void-packages checkout and index it in a local repository.
#   tools/build-xbps.sh [REPO_DIR]        default: build/repo
# Install with: sudo xbps-install --repository="$PWD/build/repo" taema
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$here/src/taema/__init__.py")
revision=${REVISION:-1}
repo=${1:-$here/build/repo}
mkdir -p "$repo"
repo=$(cd "$repo" && pwd)

make -C "$here" test
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
make -C "$here" DESTDIR="$stage" install
install -Dm644 "$here/../LICENSE" "$stage/usr/share/licenses/taema/LICENSE"
# xbps-create picks up INSTALL and REMOVE from the root of the staged tree; these are the
# same files xbps-src installs for srcpkgs/taema.
install -m755 "$here/srcpkgs/taema/INSTALL" "$stage/INSTALL"
install -m755 "$here/srcpkgs/taema/REMOVE" "$stage/REMOVE"

pkg="taema-${version}_${revision}"
rm -f "$repo/$pkg.noarch.xbps"
(cd "$repo" && xbps-create -A noarch -n "$pkg" \
    -s "Dependency-aware, self-managing cgroup v2 process scopes" \
    -D "python3>=3.11_1 iproute2>=0 util-linux>=0 sudo>=0 runit>=0 shadow>=0" \
    -l custom:PolyForm-Noncommercial-1.0.0 -H https://github.com/Bongbetic/taema \
    -m "soubarnak <soubarna@live.in>" \
    --config-files "/etc/taema/taema.toml /etc/taema/units/podman.toml" \
    "$stage")
xbps-rindex -f -a "$repo/$pkg.noarch.xbps"
# The local repository is consumed by both glibc and musl test guests. Keep
# the host-architecture index above and add the musl target index as well.
XBPS_ARCH=x86_64-musl xbps-rindex -f -a "$repo/$pkg.noarch.xbps"
echo "built $repo/$pkg.noarch.xbps"
