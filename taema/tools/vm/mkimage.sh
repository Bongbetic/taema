#!/bin/sh
# taema VM harness: configure an extracted Void rootfs so it boots to a
# key-login admin with sshd/dhcpcd enabled.
#
# Usage: mkimage.sh ROOTFS SSH_PUBKEY
#
# Must run under `unshare -rm` (rootless user+mount namespace): every mount and
# every file written here is confined to ROOTFS.  The rootfs was extracted by
# an unprivileged user, so all files carry the builder's uid; an init fixup
# (prepended to /etc/runit/1) chowns them once, before any service starts.
set -eu
PATH=/usr/bin:/usr/sbin:/bin:/sbin
R=${1:?usage: mkimage.sh ROOTFS SSH_PUBKEY}
KEY=${2:?usage: mkimage.sh ROOTFS SSH_PUBKEY}
[ -d "$R/etc" ] || { echo "mkimage: $R is not a rootfs" >&2; exit 1; }
[ -f "$KEY" ] || { echo "mkimage: no such key: $KEY" >&2; exit 1; }

mkdir -p "$R/proc" "$R/sys" "$R/dev" "$R/run" "$R/tmp" "$R/var/service" \
         "$R/etc/sudoers.d" "$R/boot" "$R/lost+found"
mount -t proc proc "$R/proc"
mount --rbind /sys "$R/sys"
mount --rbind /dev "$R/dev"
cleanup() {
    umount -R "$R/dev" 2>/dev/null || true
    umount -R "$R/sys" 2>/dev/null || true
    umount -R "$R/proc" 2>/dev/null || true
}
trap cleanup EXIT

# DNS for the chrooted xbps-install (host resolver; the guest gets its own
# from dhcpcd at boot).
rm -f "$R/etc/resolv.conf"
if ! cp -L /etc/resolv.conf "$R/etc/resolv.conf" 2>/dev/null; then
    printf 'nameserver 1.1.1.1\n' > "$R/etc/resolv.conf"
fi

# Kernel, sshd, dhcp, and taema's runtime dependencies, all from the network
# mirror (this is the opt-in image-build step).
chroot "$R" xbps-install -S -y linux openssh dhcpcd python3 iproute2 sudo

# The harness admin: public-key only, passwordless sudo for provisioning and
# privileged scenario steps inside this disposable VM.
if ! grep -q '^vmadmin:' "$R/etc/passwd"; then
    chroot "$R" useradd -m -u 1000 -s /bin/sh vmadmin
fi
printf 'vmadmin ALL=(ALL) NOPASSWD: ALL\n' > "$R/etc/sudoers.d/vmadmin"
chmod 440 "$R/etc/sudoers.d/vmadmin"

# sshd: first value wins, so delete any active directives before appending
# ours.  Password auth stays off; access is the harness key only.
sed -i '/^[[:space:]]*\(PermitRootLogin\|PasswordAuthentication\|PubkeyAuthentication\)[[:space:]]/d' \
    "$R/etc/ssh/sshd_config"
cat >> "$R/etc/ssh/sshd_config" <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
EOF

install -d -m 700 "$R/home/vmadmin/.ssh"
cp "$KEY" "$R/home/vmadmin/.ssh/authorized_keys"
chmod 600 "$R/home/vmadmin/.ssh/authorized_keys"

ln -sf /etc/sv/sshd "$R/var/service/sshd"
ln -sf /etc/sv/dhcpcd "$R/var/service/dhcpcd"

printf 'taema-vm\n' > "$R/etc/hostname"
grep -q '[[:space:]]taema-vm$' "$R/etc/hosts" 2>/dev/null ||
    printf '127.0.0.1\tlocalhost taema-vm\n' >> "$R/etc/hosts"

# Ownership fixup: extraction ran unprivileged, so every file has the builder's
# uid on disk.  Root inside the guest can read anything anyway, but sshd
# StrictModes and sudo demand correct owners; chown everything once before
# runsvdir starts any service.  The marker lives on the disposable overlay, so
# each fresh run does exactly one pass.
cat > "$R/etc/vmh-fixup.sh" <<'EOF'
if [ ! -e /etc/vmh-fixed ]; then
    chown -R 0:0 /etc /usr /var /root /opt /srv /boot /lost+found 2>/dev/null || :
    chown 0:0 /bin /sbin /lib /lib64 /libx32 2>/dev/null || :
    if [ -d /home/vmadmin ]; then
        chown -R 1000:1000 /home/vmadmin 2>/dev/null || :
    fi
    touch /etc/vmh-fixed 2>/dev/null || :
    echo "vmh: rootfs ownership fixed" >/dev/console 2>/dev/null || :
fi
EOF
sed -i '1r /etc/vmh-fixup.sh' "$R/etc/runit/1"
rm -f "$R/etc/vmh-fixup.sh"
echo "mkimage: rootfs prepared: $R"
