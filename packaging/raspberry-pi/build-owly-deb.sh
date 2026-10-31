#!/bin/sh
# Build the ARM64 Owly package in a native ARM64 container from this checkout.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BRANCH=$(git -C "$ROOT" branch --show-current)
COMMIT=$(git -C "$ROOT" rev-parse --short=12 HEAD)
[ -n "$BRANCH" ] || BRANCH=detached
docker build --platform linux/arm64 -f "$ROOT/packaging/raspberry-pi/Dockerfile.owly" \
  -t owly-rpi5-build:bookworm "$ROOT/packaging/raspberry-pi"
mkdir -p "$ROOT/dist"
docker run --rm --platform linux/arm64 -v "$ROOT:/src" -w /src \
  -e CARGO_TARGET_DIR=/src/target-arm64 -e OUT=/src/dist \
  -e "OWLY_BUILD_BRANCH=$BRANCH" -e "OWLY_BUILD_COMMIT=$COMMIT" \
  owly-rpi5-build:bookworm packaging/package.sh deb-rpi5
