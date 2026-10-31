#!/bin/sh
# Build owly as a .deb for Debian and Ubuntu, or an .rpm for Fedora: the
# AUR's owly with its distribution's package names. Builds owlyd and the CLI
# from this checkout, stages them with packaging/install.sh, and packs that
# with dpkg-deb or rpmbuild (packaging/rpm/owly.spec). Needs no root. CI
# builds both for each owly release (.github/workflows/linux-packages.yml).
#
# tar builds owly and omdrop-owl together instead, for the AUR's
# omdrop-owl-bin: both packages' files, staged the same way, in a tarball
# for the GitHub release (.github/workflows/aur-release.yml).
#
#   packaging/package.sh deb|deb-rpi5|rpm|tar
#
# The package lands in OUT ($PWD by default). Besides Rust 1.88 or newer,
# it needs dpkg-dev for the deb, or rpm-build for the rpm.
set -eu
umask 022

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FORMAT=${1:-}
case "$FORMAT" in
  deb | deb-rpi5 | rpm | tar) ;;
  *)
    echo "usage: packaging/package.sh deb|deb-rpi5|rpm|tar" >&2
    exit 2
    ;;
esac
OUT=${OUT:-$PWD}
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}

if [ "$FORMAT" = tar ]; then
  VERSION=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml")
  [ -n "$VERSION" ] || { echo "packaging/package.sh: no workspace version in Cargo.toml" >&2; exit 1; }
  NAME=omdrop-owl-$VERSION-$(uname -m)

  (cd "$ROOT" && cargo build --release --locked -p owlyd -p owly-cli -p omdrop-owl)

  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  STAGE=$WORK/$NAME
  unset PREFIX BINDIR LIBDIR DATADIR LICENSEDIR DOCDIR HOOKDIR HELPERDIR
  # Arch keeps a package's licenses under its name.
  export LICENSEDIR=/usr/share/licenses/omdrop-owl-bin
  for pkg in owly omdrop-owl; do
    DESTDIR=$STAGE TARGET=$TARGET "$ROOT/packaging/install.sh" "$pkg"
  done
  strip --strip-unneeded "$STAGE/usr/lib/owly/owlyd" "$STAGE/usr/bin/owly" \
    "$STAGE/usr/lib/omdrop-owl/omdrop-owl"

  PKG=$OUT/$NAME.tar.gz
  tar -C "$WORK" --owner=0 --group=0 --numeric-owner -czf "$PKG" "$NAME"
  echo "built $PKG"
  exit 0
fi

# The workspace version, as the AUR's pkgver is, and the packaging's own
# revision, for a change to the packaging alone.
VERSION=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml")
RELEASE=1
if [ "$FORMAT" = deb-rpi5 ]; then
  RELEASE=2
fi
[ -n "$VERSION" ] || { echo "packaging/package.sh: no workspace version in Cargo.toml" >&2; exit 1; }

(cd "$ROOT" && cargo build --release --locked -p owlyd -p owly-cli)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE=$WORK/root
# install.sh's default paths, whatever the environment sets. Debian keeps a
# package's license with its docs.
unset PREFIX BINDIR LIBDIR DATADIR LICENSEDIR DOCDIR HOOKDIR
if [ "$FORMAT" = deb ] || [ "$FORMAT" = deb-rpi5 ]; then
  export LICENSEDIR=/usr/share/doc/owly
fi
DESTDIR=$STAGE TARGET=$TARGET "$ROOT/packaging/install.sh" owly
strip --strip-unneeded "$STAGE/usr/lib/owly/owlyd" "$STAGE/usr/bin/owly"

if [ "$FORMAT" = deb ] || [ "$FORMAT" = deb-rpi5 ]; then
  ARCH=$(dpkg --print-architecture)
  if [ "$FORMAT" = deb-rpi5 ] && [ "$ARCH" != arm64 ]; then
    echo "packaging/package.sh: deb-rpi5 requires an arm64 build host" >&2
    exit 2
  fi
  DEB_NAME=owly
  DEB_MAINTAINER='T4T5 <t4t5@hey.com>'
  DEB_DEPENDS=''
  DEB_CONFLICTS=''
  DEB_HOMEPAGE=https://github.com/t4t5/owly
  DEB_DETAIL=" AWDL in userspace, with the owlyd service and owly command line tools."
  if [ "$FORMAT" = deb-rpi5 ]; then
    DEB_NAME=owly-rpi5
    DEB_MAINTAINER='DatanoiseTV <DatanoiseTV@users.noreply.github.com>'
    DEB_DEPENDS=', bluez, owly-nexmon-rpi5 (>= 0.1)'
    DEB_CONFLICTS='Conflicts: owly\nProvides: owly\n'
    DEB_HOMEPAGE=https://github.com/DatanoiseTV/owly
    DEB_DETAIL=" The Raspberry Pi build supports onboard CYW43455 through Nexmon and can share a station connection on a supported social channel."
    install -D -m 644 "$ROOT/packaging/raspberry-pi/radio.toml" \
      "$STAGE/etc/owly/radio.toml"
  fi
  install -d "$STAGE/DEBIAN"
  install -m 755 "$ROOT/packaging/deb/postinst" "$ROOT/packaging/deb/prerm" \
    "$ROOT/packaging/deb/postrm" "$STAGE/DEBIAN/"
  # The libraries the binaries link, as dpkg-shlibdeps finds them. It wants
  # a debian/control to read, with only the source stanza, and DEBIAN/ to
  # tell where the package's root is.
  mkdir "$WORK/debian"
  printf 'Source: owly\n\nPackage: owly\nArchitecture: any\n' > "$WORK/debian/control"
  SHLIBS=$(cd "$WORK" && dpkg-shlibdeps -O "$STAGE/usr/lib/owly/owlyd" "$STAGE/usr/bin/owly" \
    | sed -n 's/^shlibs:Depends=//p')
  [ -n "$SHLIBS" ] || { echo "packaging/package.sh: dpkg-shlibdeps found no libraries" >&2; exit 1; }

  # The AUR's depends, by Debian's names: see packaging/arch/owly/PKGBUILD
  # for what each is for.
  if [ "$FORMAT" = deb-rpi5 ]; then
    printf '%s\n' /etc/owly/radio.toml > "$STAGE/DEBIAN/conffiles"
  fi
  cat > "$STAGE/DEBIAN/control" <<EOF
Package: $DEB_NAME
Version: $VERSION-$RELEASE
Architecture: $ARCH
Maintainer: $DEB_MAINTAINER
Installed-Size: $(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
Depends: $SHLIBS, dbus, systemd, polkitd, network-manager, iproute2, iputils-ping, mount$DEB_DEPENDS
Recommends: hostapd
Suggests: bluez
Section: net
Priority: optional
Homepage: $DEB_HOMEPAGE
Description: AirDrop over AWDL on Linux
$DEB_DETAIL
EOF
  if [ -n "$DEB_CONFLICTS" ]; then
    printf '%b' "$DEB_CONFLICTS" >> "$STAGE/DEBIAN/control"
  fi
  PKG=$OUT/${DEB_NAME}_$VERSION-${RELEASE}_$ARCH.deb
  dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$PKG" > /dev/null
else
  ARCH=$(uname -m)
  # %files: what install.sh installs, and the directories that are owly's.
  FILES=$WORK/files
  {
    "$ROOT/packaging/install.sh" --list owly | xargs -n1 dirname | sort -u \
      | grep '/owly$' | sed 's/^/%dir /'
    "$ROOT/packaging/install.sh" --list owly
  } > "$FILES"
  rpmbuild -bb --quiet \
    --define "_topdir $WORK/rpmbuild" \
    --define "owly_version $VERSION" \
    --define "owly_release $RELEASE" \
    --define "owly_stage $STAGE" \
    --define "owly_files $FILES" \
    "$ROOT/packaging/rpm/owly.spec"
  PKG=$OUT/owly-$VERSION-$RELEASE.$ARCH.rpm
  cp "$WORK/rpmbuild/RPMS/$ARCH/owly-$VERSION-$RELEASE.$ARCH.rpm" "$PKG"
fi
echo "built $PKG"
