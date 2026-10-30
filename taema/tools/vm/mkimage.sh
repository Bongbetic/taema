#!/bin/sh
# taema VM harness: configure an extracted Void rootfs so it boots to a
# key-login admin with sshd/dhcpcd enabled.
#
# Usage: mkimage.sh ROOTFS SSH_PUBKEY
#
# Must run under `unshare -rmfp --mount-proc=ROOTFS/proc` (rootless
# user+mount+pid namespace): unshare mounts /proc for the chroot (a user
# namespace may only mount procfs alongside its own PID namespace), and every
# mount and every file written here is confined to ROOTFS.  The rootfs was
# extracted by an unprivileged user, so all files carry the builder's uid; an
# init fixup (prepended to /etc/runit/1) chowns them once, before any service
# starts.
set -eu
PATH=/usr/bin:/usr/sbin:/bin:/sbin
R=${1:?usage: mkimage.sh ROOTFS SSH_PUBKEY}
KEY=${2:?usage: mkimage.sh ROOTFS SSH_PUBKEY}
[ -d "$R/etc" ] || { echo "mkimage: $R is not a rootfs" >&2; exit 1; }
[ -f "$KEY" ] || { echo "mkimage: no such key: $KEY" >&2; exit 1; }

mkdir -p "$R/proc" "$R/sys" "$R/dev" "$R/run" "$R/tmp" "$R/etc/sudoers.d" \
         "$R/boot" "$R/lost+found"
# /proc is mounted by unshare --mount-proc (a plain user namespace may not
# mount procfs without its own PID namespace); bind the rest here.
mount --rbind /sys "$R/sys"
mount --rbind /dev "$R/dev"
cleanup() {
    umount -R "$R/dev" 2>/dev/null || true
    umount -R "$R/sys" 2>/dev/null || true
}
trap cleanup EXIT

# DNS for the chrooted xbps-install (host resolver; the guest gets its own
# from dhcpcd at boot).
rm -f "$R/etc/resolv.conf"
if ! cp -L /etc/resolv.conf "$R/etc/resolv.conf" 2>/dev/null; then
    printf 'nameserver 1.1.1.1\n' > "$R/etc/resolv.conf"
fi

# xbps refuses repository metadata newer than itself, so update it explicitly
# first; then bring the whole rootfs up to date: the tarball's base system
# predates the current repository, and pieces it splits differently
# (kmod/libkmod, dracut's libkmod requirement) would otherwise leave broken
# combinations.  Host environment is stripped: a host TMPDIR (or XBPS_*
# override) does not exist inside the chroot and would make xbps fail with
# ENOENT while staging package scripts.
chroot "$R" env -u TMPDIR -u XBPS_ROOT -u XBPS_ARCH -u XBPS_TARGET_ARCH \
    /usr/bin/xbps-install -Syu xbps
chroot "$R" env -u TMPDIR -u XBPS_ROOT -u XBPS_ARCH -u XBPS_TARGET_ARCH \
    /usr/bin/xbps-install -Syu
chroot "$R" env -u TMPDIR -u XBPS_ROOT -u XBPS_ARCH -u XBPS_TARGET_ARCH \
    /usr/bin/xbps-install -S -y linux openssh dhcpcd python3 iproute2 sudo dbus elogind earlyoom \
    weston niri foot grim libnotify mesa-dri python3-dbus python3-gobject \
    dejavu-fonts-ttf zsh fish-shell

# Void's kernel packages build the initramfs with dracut, whose host-only
# detection inside this chroot sees the builder's hardware (and previously
# failed outright) and would omit the virtio block drivers the VM boots from.
# Rebuild a generic initramfs for every installed kernel.
for kv in "$R"/usr/lib/modules/*; do
    [ -d "$kv" ] || continue
    ver=$(basename "$kv")
    chroot "$R" env -u TMPDIR dracut -f --no-hostonly \
        "/boot/initramfs-$ver.img" "$ver"
done

# Downloaded archives are not part of the runtime system; drop them so the
# cached base image stays small.
rm -rf "$R"/var/cache/xbps/* 2>/dev/null || :

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

# Enable services persistently.  /var/service is only a symlink into /run
# (tmpfs); runit resolves it to /etc/runit/runsvdir/current -> default, so the
# durable place for enablement links is the default runlevel directory.
mkdir -p "$R/etc/runit/runsvdir/default"
ln -sf /etc/sv/sshd "$R/etc/runit/runsvdir/default/sshd"
ln -sf /etc/sv/dhcpcd "$R/etc/runit/runsvdir/default/dhcpcd"
ln -sf /etc/sv/dbus "$R/etc/runit/runsvdir/default/dbus"
ln -sf /etc/sv/elogind "$R/etc/runit/runsvdir/default/elogind"

printf 'taema-vm\n' > "$R/etc/hostname"
grep -q '[[:space:]]taema-vm$' "$R/etc/hosts" 2>/dev/null ||
    printf '127.0.0.1\tlocalhost taema-vm\n' >> "$R/etc/hosts"

# Ownership fixup: extraction ran unprivileged, so every file has the builder's
# uid on disk.  Root inside the guest can read anything anyway, but sshd
# StrictModes and sudo demand correct owners; chown everything once before
# runsvdir starts any service.  chown also clears set-user-ID/set-group-ID
# bits whenever it changes an owner (POSIX), which would leave sudo and su
# unusable ("must be owned by uid 0 and have the setuid bit set"), so the
# fixup snapshots those modes first and restores them right after the chown
# pass.  The marker lives on the disposable overlay, so each fresh run does
# exactly one pass.
cat > "$R/etc/vmh-fixup.sh" <<'EOF'
if [ ! -e /etc/vmh-fixed ]; then
    find /usr /root /opt /srv /var /etc -type f \( -perm -4000 -o -perm -2000 \) \
        -exec stat -c '%a %n' {} \; > /etc/vmh-suid.bak 2>/dev/null || :
    chown -R 0:0 /etc /usr /var /root /opt /srv /boot /lost+found 2>/dev/null || :
    chown 0:0 /bin /sbin /lib /lib64 /libx32 2>/dev/null || :
    while read -r mode path; do
        chmod "$mode" "$path" 2>/dev/null || :
    done < /etc/vmh-suid.bak 2>/dev/null || :
    rm -f /etc/vmh-suid.bak
    # the harness's privileged steps need these two unconditionally, even if
    # the snapshot pass above was unavailable
    chmod 4755 /usr/bin/sudo /usr/bin/su 2>/dev/null || :
    if [ -d /home/vmadmin ]; then
        chown -R 1000:1000 /home/vmadmin 2>/dev/null || :
    fi
    touch /etc/vmh-fixed 2>/dev/null || :
    echo "vmh: rootfs ownership fixed" >/dev/console 2>/dev/null || :
fi
EOF
if ! grep -q 'vmh-fixed' "$R/etc/runit/1"; then
    sed -i "1r $R/etc/vmh-fixup.sh" "$R/etc/runit/1"
fi
rm -f "$R/etc/vmh-fixup.sh"
echo "mkimage: rootfs prepared: $R"
