#!/bin/sh
# taema VM harness: in-guest provisioning, run as root (via `sudo -n`) by the
# harness over SSH.  Installs the locally built package from the transferred
# repository, creates the test user, and waits for that user's daemon.
#
# Usage: provision.sh --package-dir DIR --user NAME
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
PKGDIR=
USER_NAME=
while [ $# -gt 0 ]; do
    case $1 in
        --package-dir) PKGDIR=$2; shift 2 ;;
        --user) USER_NAME=$2; shift 2 ;;
        *) echo "provision.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [ -z "$PKGDIR" ] || [ -z "$USER_NAME" ]; then
    echo "usage: provision.sh --package-dir DIR --user NAME" >&2
    exit 2
fi
if [ ! -d "$PKGDIR" ]; then
    echo "provision.sh: no such package dir: $PKGDIR" >&2
    exit 1
fi

# 1. The test user exists before the install so the package's INSTALL hook
#    picks up members with login shells; usermod below keeps it idempotent.
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd -m -s /bin/sh "$USER_NAME" || exit 1
fi

# 2. Install the package from the transferred local repository only (-i), so
#    provisioning never depends on the guest's view of the network.
xbps-install -y -i --repository="$PKGDIR" taema || {
    echo "provision.sh: package install failed" >&2
    exit 1
}

# 3. Group membership, delegated runtime dir, and harness-only sudo for
#    privileged scenario steps (this VM is disposable; the sudoers file is
#    harness-provided, never shipped by the package).
usermod -aG taema "$USER_NAME" || exit 1
uid=$(id -u "$USER_NAME")
gid=$(id -g "$USER_NAME")
install -d -m 700 -o "$uid" -g "$gid" "/run/user/$uid"
printf '%s ALL=(root) NOPASSWD: ALL\n' "$USER_NAME" > /etc/sudoers.d/taema-vm
chmod 440 /etc/sudoers.d/taema-vm

# 4. Wait for the runit service to delegate the user cgroup and for the
#    per-user daemon to answer on its socket.
n=0
while [ "$n" -lt 90 ]; do
    if su -s /bin/sh "$USER_NAME" -c "/usr/bin/taema status" >/dev/null 2>&1; then
        echo "PROVISION_OK user=$USER_NAME uid=$uid"
        exit 0
    fi
    sleep 2
    n=$((n + 1))
done
echo "provision.sh: daemon not ready after 180s" >&2
sv status /var/service/taema >&2 || true
exit 1
