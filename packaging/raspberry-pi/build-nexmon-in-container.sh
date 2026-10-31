#!/bin/sh
# Build the Nexmon firmware and its Debian package in OrbStack or Docker.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
docker build --platform linux/arm64 -f "$ROOT/packaging/raspberry-pi/Dockerfile.nexmon" \
  -t owly-nexmon-build:trixie "$ROOT/packaging/raspberry-pi"
mkdir -p "$ROOT/dist"
docker run --rm --platform linux/arm64 -v "$ROOT:/src" -w /src \
  -e OUT=/src/dist owly-nexmon-build:trixie \
  packaging/raspberry-pi/build-nexmon-firmware.sh
