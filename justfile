# Development tasks. `just` lists them.

set positional-arguments
set ignore-comments

# The owly CLI, built from this checkout
owly := "cargo run --quiet --locked -p owly-cli --"

# What `just install` installs, built together as the packages build them:
# owlyd built alone gets other features, so a different binary
release := "cargo build --release --locked -p owlyd -p owly-cli -p omdrop-owl"

[private]
default:
    @just --list

# Formatting and lints, quick enough for before each commit
check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings

# The workspace's tests
test:
    cargo test --workspace --locked

# Everything CI checks: lints, tests, portability, spec coverage, vectors, the hardware table
ci: check test
    # The portable crates on Windows and Android (owly-awdl with its driver),
    # the AirDrop core without a runtime, the userspace 7-layer stack without
    # ring's C toolchain, and the no_std AWDL core on ESP32-C3
    cargo check --locked --target x86_64-pc-windows-msvc -p owly-awdl -p owly-airdrop --all-features
    cargo check --locked --target aarch64-linux-android -p owly-awdl -p owly-airdrop --all-features
    cargo check --locked --target x86_64-pc-windows-msvc -p owly-userspace --no-default-features --features udp,usb
    cargo check --locked --target aarch64-linux-android -p owly-userspace --no-default-features --features udp,usb
    cargo check --locked -p owly-airdrop --no-default-features
    cargo check --locked -p owly-userspace --no-default-features
    cargo check --locked --target riscv32imc-unknown-none-elf -p owly-awdl
    # Every in-scope MUST in docs/ has a test or a policy entry (tests/coverage.toml)
    cargo xtask coverage
    # The committed vectors match what their generator produces
    python3 -I tests/vectors/gen_airdrop_vectors.py /dev/stdout | cmp tests/vectors/airdrop-vectors.json -
    # README's hardware table matches hardware/ and drivers.toml (`cargo xtask hardware` rewrites it)
    cargo xtask hardware --check

# Fuzz each network-facing parser (cargo-fuzz, nightly). Never at devices you don't own (SEC-9)
fuzz seconds="60":
    python3 -I fuzz/seed.py fuzz/corpus
    # cargo-fuzz builds for the triple it was itself built for, so the musl
    # build cargo-binstall fetches would build for musl, which ASan can't link
    host=$(rustc +nightly -vV | sed -n 's/^host: //p'); for target in $(cargo +nightly fuzz list); do cargo +nightly fuzz run --target "$host" "$target" -- -max_total_time={{ seconds }} -rss_limit_mb=2048; done

# Each radio mode on simulated radios (mac80211_hwsim), leaving real Wi-Fi alone (root)
hwsim:
    cargo test --locked -p owly-radio --test hwsim --config "target.'cfg(all())'.runner = 'sudo OWLY_HWSIM=1'" -- --nocapture

# Install owlyd, the owly CLI and omdrop-owl's hooks and helper, as the packages do (root)
install:
    {{ release }}
    sudo BINDIR=/usr/local/bin packaging/install.sh owly
    sudo packaging/install.sh omdrop-owl
    sudo systemctl daemon-reload
    sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
    -sudo nmcli general reload conf
    -sudo systemctl try-restart owlyd

# Remove what `just install` put in place, giving Wi-Fi back (root)
uninstall:
    -sudo /usr/lib/omdrop/omdrop-discoverable stop
    -sudo /usr/lib/omdrop/radio/down stopped
    packaging/install.sh --list omdrop-owl | sudo xargs rm -f
    -sudo rmdir /usr/lib/omdrop/radio /usr/lib/omdrop /usr/lib/omdrop-owl /usr/share/licenses/omdrop-owl
    -sudo systemctl stop owlyd
    BINDIR=/usr/local/bin packaging/install.sh --list owly | sudo xargs rm -f
    -sudo rmdir /usr/lib/owly /usr/share/doc/owly /usr/share/licenses/owly
    sudo systemctl daemon-reload
    sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
    -sudo nmcli general reload conf

# Testing with a phone: `just radio` in one terminal, then `just receive` or
# `just send` in another.

# Hold the radio until Ctrl-C, installing owlyd first when it's missing or out of date
[group('phone')]
radio *args:
    @{{ release }}
    @cmp -s "${CARGO_TARGET_DIR:-target}/release/owlyd" /usr/lib/owly/owlyd || just install
    {{ owly }} radio up "$@"

# Receive files and links into /tmp/owly-receive
[group('phone')]
receive *args:
    mkdir -p /tmp/owly-receive
    RUST_LOG=owly_airdrop=debug {{ owly }} receive --dir /tmp/owly-receive "$@"

# Send files, a link (`--url <url>`) or, by default, a test photo to the first phone that answers (or `--to <name>`)
[group('phone')]
send *args="tests/photo.png":
    {{ owly }} send "$@"

# Any other owly command: `just owly doctor`, `just owly radio peers`, `just owly test-card`
[group('phone')]
owly *args:
    {{ owly }} "$@"

# Preview README as GitHub renders it (dark by default; `just readme-preview light`)
readme-preview theme="dark":
    #!/usr/bin/env bash
    set -euo pipefail
    out=.readme-preview.html
    # Export next to the README so relative image paths keep working.
    uvx grip --export --quiet --user "$(gh api user --jq .login)" --pass "$(gh auth token)" README.md "$out"
    sed -i 's|<html lang="en">|<html lang="en" data-color-mode="{{ theme }}" data-{{ theme }}-theme="{{ theme }}">|' "$out"
    xdg-open "$out"

# Set the version in Cargo.toml, owly-radio's owly-awdl pin, Cargo.lock and the PKGBUILDs (pushing it releases)
bump version:
    #!/usr/bin/env bash
    set -euo pipefail
    new={{ version }}
    [[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a version: $new" >&2; exit 1; }
    old=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml)
    sed -i "s/^version = \"$old\"$/version = \"$new\"/" Cargo.toml
    sed -i "s/^owly-awdl = { version = \"$old\"/owly-awdl = { version = \"$new\"/" crates/owly-radio/Cargo.toml
    sed -i -e "s/^owly-awdl = { version = \"$old\"/owly-awdl = { version = \"$new\"/" -e "s/^owly-airdrop = { version = \"$old\"/owly-airdrop = { version = \"$new\"/" crates/owly-userspace/Cargo.toml
    sed -i -e "s/^pkgver=.*/pkgver=$new/" -e "s/^pkgrel=.*/pkgrel=1/" packaging/arch/*/PKGBUILD
    cargo update --workspace --quiet
    echo "$old -> $new"
    git diff --stat
