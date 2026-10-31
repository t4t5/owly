#!/bin/sh
# Package Nexmon's patch and driver source. The stock CYW43455 image is read
# from the Pi during installation and is never included in this package.
set -eu
umask 022

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NEXMON=$ROOT/third_party/nexmon
DRIVER=$NEXMON/patches/driver/brcmfmac_6.18.y-nexmon
OUT=${OUT:-$ROOT/dist}
VERSION=0.1-1
ARCH=arm64

[ -f "$DRIVER/Makefile" ] || { echo "Missing Nexmon 6.18 driver source" >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }
command -v git >/dev/null || { echo "git is required to archive the pinned source" >&2; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE=$WORK/root
SOURCE=$STAGE/usr/src/owly-nexmon-rpi5-0.1/nexmon
mkdir -p "$SOURCE"
git -C "$NEXMON" archive HEAD \
  setup_env.sh LICENSE.txt \
  buildtools/gcc-arm-none-eabi-5_4-2016q2-linux-armv7l \
  buildtools/gcc-nexmon-plugin-arm \
  buildtools/flash_patch_extractor buildtools/scripts \
  patches/common patches/include \
  patches/bcm43455c0/7_45_265-28bca26-CY \
  patches/driver/brcmfmac_6.18.y-nexmon \
  firmwares/bcm43455c0/structs.common.h \
  firmwares/bcm43455c0/7_45_265-28bca26-CY \
  | tar -x -C "$SOURCE"
touch "$SOURCE/DISABLE_STATISTICS"
# Keep the vendor's binary firmware on the recipient Pi. Only the open patch,
# driver, and toolchain go into the public package.
rm "$SOURCE/firmwares/bcm43455c0/7_45_265-28bca26-CY/cyfmac43455-sdio-standard.bin"
install -D -m 644 "$NEXMON/LICENSE.txt" "$STAGE/usr/share/doc/owly-nexmon-rpi5/LICENSE.txt"
install -D -m 755 "$ROOT/packaging/raspberry-pi/nexmon-postinst" "$STAGE/DEBIAN/postinst"
install -D -m 755 "$ROOT/packaging/raspberry-pi/nexmon-prerm" "$STAGE/DEBIAN/prerm"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: owly-nexmon-rpi5
Version: $VERSION
Architecture: $ARCH
Maintainer: DatanoiseTV <DatanoiseTV@users.noreply.github.com>
Installed-Size: $(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
Depends: linux-headers-rpi-2712, build-essential, binutils, kmod, dpkg, gawk, qpdf, xxd, libgmp3-dev, zlib1g-dev, libc6:armhf, libisl23:armhf, libmpfr6:armhf, libmpc3:armhf, libstdc++6:armhf
Section: kernel
Priority: optional
Homepage: https://github.com/DatanoiseTV/owly
Description: Experimental Nexmon radio for Raspberry Pi 5 and CM5
 Builds patched CYW43455 firmware from the Pi's installed stock image and a
 6.18 driver against its running 2712 kernel. Requires firmware 7.45.265.
EOF
mkdir -p "$OUT"
PKG=$OUT/owly-nexmon-rpi5_${VERSION}_${ARCH}.deb
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$PKG" >/dev/null
echo "built $PKG"
