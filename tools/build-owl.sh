#!/bin/bash
# Build OWL, the userspace AWDL implementation, into upstream/owl. Touches no
# radio and needs no root; tools/stage.sh copies the binary into build/lib.
#
# Uses jedbillyb/owl, the airdrop-mt7921 fork (its -S channel-sequence
# strategies, and its fixes for iOS 26), pinned to the commit our patches were
# written against. The working tree is reset on every build, so edits made in
# upstream/owl are lost; put them in a patch.
#   owl-01-tx-rate.patch    -R RATE: data-frame PHY rate (default unchanged)
#   owl-02-awdl-addr.patch  -m MAC: the AWDL address, instead of the monitor
#                           interface's own
#   owl-03-fixed-radio.patch  -F: for a radio that can't leave -c's channel,
#                           multicast in any slot, unicast in every slot the
#                           peer is on that channel, and advertise every slot
#                           any peer is on it
#   owl-04-election-metric.patch  -E: elect the sync master by metric before
#                           counter, as Apple devices do
#   owl-05-fixed-radio-noack.patch  with -F, unicast data goes out once, with
#                           no ACK expected and so no retries
#   owl-06-fixed-radio-pin.patch  with -F, -S pin pins -c's channel, not the
#                           peer's favourite
#   owl-08-amsdu-bound.patch  refuse an A-MSDU with more subframes than the
#                           receive array has slots, instead of writing past
#                           it (tests/owl_amsdu.c)
#   owl-09-action-zero-padding.patch  accept the zero padding iPhones end
#                           some MIFs with, instead of refusing the frame and
#                           so never validating the peer (tests/owl_padding.c)
#   owl-10-addba-accept.patch  -A: answer a peer's Block Ack session request
#                           (ADDBA) with success, so it may send A-MPDUs
#                           (tests/owl_addba.c)
#   owl-11-rx-flags-init.patch  treat a missing radiotap Flags field as zero,
#                           instead of reading an uninitialized byte
#                           (tests/owl_rx_flags.c)
#   owl-12-rx-reorder.patch  with -A, hold a Block Ack session's frames until
#                           the gaps before them fill, as mac80211 does, so
#                           TCP gets them in order (src/reorder.c,
#                           tests/owl_reorder.c)
# Applied in name order: each is a diff against the tree with the previous ones.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIR=$ROOT/upstream/owl
OWL_REPO=https://github.com/jedbillyb/owl.git
. "$ROOT/pins"

# Asked of the compiler, not /usr/include: Nix keeps headers elsewhere.
echo '#include <ev.h>' | "${CC:-cc}" -E -x c - >/dev/null 2>&1 || { echo "libev headers missing (Arch: sudo pacman -S libev; Debian, Ubuntu: sudo apt install libev-dev)"; exit 1; }

if [ ! -d "$DIR/.git" ]; then
  git clone -q --recurse-submodules "$OWL_REPO" "$DIR"
fi
git -C "$DIR" fetch -q origin || true
git -C "$DIR" checkout -q -- .
# Files a patch adds (src/reorder.c) survive `checkout -- .`, and the next
# build's apply then refuses to create them again: remove them, keep build/.
git -C "$DIR" clean -fdq -e build
git -C "$DIR" -c advice.detachedHead=false checkout -q "$OWL_COMMIT"
git -C "$DIR" submodule update -q --init --recursive
for p in "$ROOT"/patches/owl-*.patch; do
  git -C "$DIR" apply "$p" || { echo "$(basename "$p") did not apply to owl@$OWL_COMMIT"; exit 1; }
done

# The policy minimum is for the bundled googletest, whose
# cmake_minimum_required predates 3.5, which CMake 4 refuses. Only the owl
# target is built: googletest fails under current GCC and isn't needed.
cmake -S "$DIR" -B "$DIR/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null
cmake --build "$DIR/build" --target owl -j"$(nproc)" >/dev/null

BIN=$DIR/build/daemon/owl
case "$("$BIN" -S intersect -R 12 -m 02:00:00:00:00:01 -F -E -A -h 2>&1 || true)" in
  *"invalid option"*|*"-R takes"*|*"-m takes"*) echo "$BIN lacks -S, -R, -m, -F, -E or -A; did the patches apply?"; exit 1 ;;
esac
echo "built $BIN: owl@${OWL_COMMIT:0:7} + $(ls "$ROOT"/patches/owl-*.patch | wc -l) patches"
