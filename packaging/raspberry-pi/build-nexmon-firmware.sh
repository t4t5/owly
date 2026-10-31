#!/usr/bin/env bash
# Build the pinned Nexmon firmware on an ARM64 Debian-compatible host.
set -euo pipefail

OWLY_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NEXMON=$OWLY_ROOT/third_party/nexmon
PATCH=$NEXMON/patches/bcm43455c0/7_45_265-28bca26-CY/nexmon
cd "$NEXMON"
touch DISABLE_STATISTICS
mkdir -p buildtools/armhf-compat-libs
ln -sfn "$(readlink -f /usr/lib/arm-linux-gnueabihf/libisl.so.23)" \
  buildtools/armhf-compat-libs/libisl.so.10
ln -sfn "$(readlink -f /usr/lib/arm-linux-gnueabihf/libmpfr.so.6)" \
  buildtools/armhf-compat-libs/libmpfr.so.4
set +u
source setup_env.sh
set -u
"${CC}gcc" --version
make -C buildtools/flash_patch_extractor
make -C firmwares/bcm43455c0/7_45_265-28bca26-CY
make -C "$PATCH" firmware-only
"$OWLY_ROOT/packaging/raspberry-pi/build-nexmon-deb.sh"
