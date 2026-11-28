#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C TZ=UTC
umask 022

cd /inputs
sha256sum -c SHA256SUMS
apt-get -q -o Acquire::Retries=0 install -y --no-install-recommends /inputs/toolchain/*.deb
test "$(dpkg-query -W -f='${Version}' gcc-13)" = '13.3.0-6ubuntu2~24.04.1'
test "$(dpkg-query -W -f='${Version}' binutils)" = '2.42-4ubuntu2.11'
test "$(dpkg-query -W -f='${Version}' libc6-dev)" = '2.39-0ubuntu8.12'
test "$(dpkg-query -W -f='${Version}' linux-libc-dev)" = '6.8.0-151.151'

# The approved ELF embeds these paths in DWARF. This directory is container-only.
root=/tmp/workeros-982b8a9-bwrap-build-fh9s55xm
mkdir "$root"
mkdir "$root/deps"
for package in /inputs/addons/*.deb; do dpkg-deb -x "$package" "$root/deps"; done
tar -xJf /inputs/bubblewrap-0.12.0.tar.xz -C "$root"
export PYTHONPATH="$root/deps/usr/lib/python3/dist-packages"
export CC=gcc-13
export PKG_CONFIG_LIBDIR="$root/deps/usr/lib/x86_64-linux-gnu/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$root/deps"
# Ubuntu's libcap.pc declares an upstream lib64 directory, but the exact Ubuntu archive is in the multiarch directory.
sed -i 's@^libdir=.*@libdir=/usr/lib/x86_64-linux-gnu@' "$PKG_CONFIG_LIBDIR/libcap.pc"
cd "$root"
python3 "$root/deps/usr/bin/meson" setup build bubblewrap-0.12.0 -Dprefer_static=true -Dselinux=disabled -Dman=disabled -Dtests=false -Dbash_completion=disabled -Dzsh_completion=disabled
ninja -v -C build bwrap
cp build/bwrap /outputs/bwrap
cp bubblewrap-0.12.0/COPYING /outputs/COPYING
(cd /outputs && sha256sum -c <<'HASHES'
6865e23c7ac667d87b8805850ec1759aca3fec338eb30fec6a099f31bd8aebbf  bwrap
dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551  COPYING
HASHES
)
