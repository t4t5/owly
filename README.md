# omdrop-owl

https://github.com/user-attachments/assets/b195ce4c-e078-49be-bc13-44a72b6dc189

AirDrop between iPhones and Linux laptops whose Wi-Fi isn't Apple's Broadcom
chip. Pairs with [omdrop](https://github.com/netmojo-systems/omdrop-plugin).

See [supported hardware](#supported-hardware).

## Install

On Arch/Omarchy ([AUR](https://aur.archlinux.org/packages/omdrop-owl)):

```sh
yay -S omdrop-owl
```

<details>
<summary>On Debian or Ubuntu (from source)</summary>

```sh
sudo apt install build-essential cmake git pkg-config dpkg-dev \
  libev-dev libpcap-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev
tools/build-deb.sh
sudo apt install ./omdrop-owl_*.deb
```

This builds OWL at the commit pinned in `pins`, with `patches/`,
and installs it root-owned into `/usr/lib/omdrop` together with
`omdrop-discoverable` and omdrop-awdl's portable tools, a polkit policy for the
helper, a NetworkManager rule keeping `awdl0`, `mon0`, `awdlibss0` and `awdlap0`
unmanaged, and a systemd `.link` file that keeps udev from changing `awdl0`'s
MAC address. `hostapd` is recommended: exclusive mode needs it on cards without
ad-hoc mode. It conflicts with `brcmfmac-awdl-dkms`: one radio backend at a time.

</details>

<details>
<summary>On Fedora (from source)</summary>

```sh
sudo dnf install rpm-build cmake gcc gcc-c++ make git libev-devel libpcap-devel libnl3-devel
tools/build-rpm.sh
sudo dnf install ./omdrop-owl-*.rpm
```

This builds the same files as the Debian package into an `.rpm` (Fedora package names;
other rpm-based distros would rename them). `sudo dnf remove omdrop-owl` removes them all.
</details>

<details>
<summary>On NixOS (flake)</summary>

```nix
inputs.omdrop-owl.url = "github:t4t5/omdrop-owl";
```

```nix
imports = [ inputs.omdrop-owl.nixosModules.default ];
services.omdrop-owl.enable = true;
```

The module installs the helper and its polkit policy, keeps NetworkManager off OWL's interfaces and udev from changing `awdl0`'s MAC address, opens TCP 8771 on `awdl0`, and stops NixOS restarting wpa_supplicant (dropping Wi-Fi) whenever OWL adds or removes an interface. omdrop finds the helper and `send-to-peer` on `PATH`.

The `interface`, `channels` and `allowUntested` options set `/etc/omdrop/infra-iface`, `/etc/omdrop/channels` and `/etc/omdrop/allow-untested`.
</details>

## Usage

omdrop-owl needs the [omdrop](https://github.com/netmojo-systems/omdrop-plugin.git) plugin (0.16.0 or newer) to work.

### On Omarchy (add it as a plugin):

```sh
omarchy plugin add https://github.com/netmojo-systems/omdrop-plugin.git
```

and turn it on from the bar.

### On other Linux systems:

The bar icon and panel are Omarchy-only. On other distros, you can use the `omdrop` CLI:

```sh
git clone https://github.com/netmojo-systems/omdrop-plugin.git
omdrop-plugin/bin/omdrop setup   # installs ~/.local/bin/omdrop and the receiver
omdrop on 10m                    # visible for 10 minutes
omdrop peers -n                  # nearby Apple devices and their names
omdrop send <device> <file>
omdrop off
```

If something doesn't work, `omdrop doctor` lists what's missing.

Received files land in `~/Downloads`.


## Supported hardware

**Status:** ✅ both directions work, ⚠️ both have worked but not reliably ([known issues](#known-issues)), ❌ tried and fails, ❓ untested\
**Modes:** *Shared* keeps Wi-Fi connected; *Exclusive* turns it off while visible ([why](#exclusive-mode))

| Card | Driver | Status | Tested on |
|---|---|---|---|
| MediaTek MT7925 | `mt7925e` | ✅ Shared | Framework 13, `14c3:0717`, Omarchy 4.0.4 (kernel 7.2.5) |
| MediaTek MT7612U (USB) | `mt76x2u` | ✅ Exclusive | `0e8d:7612` (kernel 7.2.9) |
| Realtek RTL8822BE | `rtw88_8822be` | ✅ Exclusive; shared untested | Crosshair VII Hero, `10ec:b822`, NixOS 26.11 (kernel 7.2.9) |
| Realtek RTL8852AE | `rtw89_8852ae` | ✅ Shared (opt-in) | ThinkPad P14s Gen 2a, `10ec:8852`, Ubuntu 26.04.1 (kernel 7.0) |
| Realtek RTL8852BE | `rtw89_8852be` | ✅ Shared (opt-in) | ASUS PRIME B550M-A WIFI II, `10ec:b852`, CachyOS (kernel 7.2.9) |
| Realtek RTL8852CE | `rtw89_8852ce` | ✅ Shared and exclusive (opt-in) | • Legion Slim 5 16AHP9, `10ec:c852`, Omarchy 4.0.4 (kernel 7.2.5)<br>• ThinkBook 16 G7 IML, `10ec:c852`, Ubuntu 24.04 (kernel 7.0) |
| Realtek RTL8852BU (USB) | `rtw89_8852bu` | ✅ Exclusive (opt-in), as a second card | USB adapter, `35bc:0108`, NixOS 26.05 (kernel 7.2.9) |
| Intel 9560 | `iwlwifi` | ✅ Exclusive | Lenovo 81SY, `8086:a370`, Omarchy 4.0.0 (kernel 7.2.8) |
| Intel AX200 | `iwlwifi` | ✅ Exclusive | ThinkPad X1 Yoga, `8086:2723`, NixOS 26.05 (kernel 6.19.8) |
| Intel AX201 | `iwlwifi` | ✅ Exclusive | • Ubuntu 24.04 (kernel 6.8)<br>• CachyOS (kernel 7.2.9) |
| Intel AX211 | `iwlwifi` | ✅ Exclusive | • ThinkPad X1, `8086:51f1`, Ubuntu 26.04 (kernel 7.0)<br>• XPS 9320, `8086:51f0`, Arch (kernel 7.2.3)<br>• Legion Pro 7 16IRX8H, `8086:7a70`, Omarchy 4.0.4 (kernel 7.2.3)<br>• TUXEDO InfinityBook Max 15 Gen10 (Arrow Lake), `8086:7740`, Kubuntu 26.04.1 (kernel 7.0) |
| Intel BE (Panther Lake) | `iwlwifi` | ✅ Exclusive | XPS 16, `8086:e440`, Arch (kernel 7.2) |
| Intel BE200 | `iwlwifi` | ✅ Exclusive | GEEKOM IT13 Max, `8086:272b`, Omarchy 4.0.4 (kernel 7.2.5) |
| MediaTek MT7921 | `mt7921e` | ⚠️ Exclusive, opt-in; shared fails ([#14](https://github.com/t4t5/omdrop-owl/issues/14)) | `14c3:7961`, CachyOS (kernel 7.2.9) |
| MediaTek MT7922 (RZ616) | `mt7921e` | ⚠️ Exclusive, opt-in; shared fails ([#14](https://github.com/t4t5/omdrop-owl/issues/14)) | Minisforum MS-A2, `14c3:0616`, NixOS 26.05 (kernels 6.18 and 7.2.5) |
| MediaTek MT7927 | `mt7925e` | ❌ Shared: never heard; active monitor (opt-in) sends, but receiving times out ([#44](https://github.com/t4t5/omdrop-owl/issues/44)) | TP-Link Archer TBE550E, `14c3:7927`, CachyOS (kernel 7.2.9) |
| Realtek RTL8821CE | `rtw88_8821ce` | ❌ Shared: OWL syncs but no transfer, Wi-Fi often lost after ([#60](https://github.com/t4t5/omdrop-owl/issues/60)); exclusive receives nothing | HP laptop, `10ec:c821`, Omarchy (kernel 7.2.5) |
| Qualcomm WCN6855 (QCNFA765) | `ath11k_pci` | ❌ Can't create the monitor interface both modes need ([#45](https://github.com/t4t5/omdrop-owl/issues/45)) | ThinkPad, `17cb:1103`, CachyOS (kernel 7.2.9) |
| Qualcomm WCN7850 (FastConnect 7800) | `ath12k_wifi7_pci` | ❌ Shared: receives nothing from the phone ([#40](https://github.com/t4t5/omdrop-owl/issues/40)); exclusive untested | `17cb:1107`, Fedora 44 (kernel 7.2.9) |
| Intel Dual Band Wireless-AC 7265 | `iwlwifi` | ❌ Exclusive: firmware asserts on every ad-hoc start ([#16](https://github.com/t4t5/omdrop-owl/issues/16)) | Zenbook UX305CA, `8086:095a`, Omarchy 4.0.4 (kernel 7.2.5) |
| Intel Wireless-AC 8260 | `iwlwifi` | ❌ Exclusive: firmware resets on channel 44; no transfer on 6 | NUC6i7KYK, `8086:24f3`, Home Assistant OS (kernel 6.12) |
| Intel 9260 | `iwlwifi` | ❓ Exclusive untested | — |
| Intel AX210 | `iwlwifi` | ❓ Exclusive untested | — |

One card name can cover chips that behave differently, so a report from a machine, PCI ID
(`lspci -nn`) or kernel not listed here helps too.

### Adding your card

What omdrop-owl does on each Wi-Fi driver comes from
[`userspace/owl-profiles`](userspace/owl-profiles), one line per driver, so the
`iwlwifi` line covers every Intel card. A driver with
no line falls back to the `*` line, which only runs once you opt in with
`sudo mkdir -p /etc/omdrop && echo 1 | sudo tee /etc/omdrop/allow-untested`.

Cards that can inject frames from a monitor interface while connected to Wi-Fi
are the likely candidates. Most mac80211 drivers can, but how they behave
around it varies, which is what the profile records.

1. Find your driver: `basename $(readlink /sys/class/net/<wifi>/device/driver)`.
   Put your AP on channel 6, 44 or 149.
2. Opt in (`/etc/omdrop/allow-untested`), and copy the `*` line to
   `/etc/omdrop/owl-profiles` with your driver's name. That file is read before
   the packaged table, so you can change settings without rebuilding.
3. Run `sudo tools/test-card.sh`. It walks you through a photo each way,
   watches Wi-Fi for five minutes after teardown, and writes a report.
4. To see if your card needs `reconnect yes`, run it again after
   `echo 0 | sudo tee /etc/omdrop/reconnect-after`. If Wi-Fi stops after
   teardown, it does (reload the driver to recover). Delete the file after.
5. If something fails, try the other `mon_mac` setting.
6. Open a pull request adding your line to `userspace/owl-profiles`, and paste
   the report's `summary.txt`. The other files include your router's MAC.

Cards that can't inject while connected can try `mode exclusive`, which takes Wi-Fi away for the window, through a hidden AP if the card has no ad-hoc mode (`iw phy` lists no IBSS; needs `hostapd`). A card that supports an active monitor can try `mode active-monitor` instead.

A USB adapter can run exclusive mode as a second card while the built-in one stays connected: `echo <adapter> | sudo tee /etc/omdrop/infra-iface`, then `nmcli device disconnect <adapter>`. `/etc/omdrop/channels` sets the order exclusive mode tries channels in (default `44 149 6`, or `6` for `iwlwifi`); active-monitor profiles ignore it.

`/etc/omdrop/aggregation` set to `1` or `0` turns on or off accepting the phone's Block Ack session (`owl -A`), which lets it send aggregated frames: a 30 MB upload to an MT7612U took 14 s instead of 47 s. It's on by default only for the MT7612U, as other cards haven't been measured.

## How it works

AWDL (the Wi-Fi link AirDrop runs over) is provided by [jedbillyb's OWL fork](https://github.com/jedbillyb/owl).
omdrop's receiver and sender run over
it unchanged. Discovery and transfer tools are reused from omdrop-awdl,
fetched at a pinned commit by `tools/stage.sh`.

### Shared mode

Wi-Fi stays connected on channel **6, 44 or 149**. OWL injects frames through
a monitor interface using the station's MAC, and advertises only the phone's
slots on that channel (`-S intersect`). On the MT7925, the station handles
ACKs. OWL exposes `awdl0` for omdrop's receiver and AirDrop announcements.

### Exclusive mode

No Intel card tested works in shared mode, so `iwlwifi` disconnects Wi-Fi
while the machine is visible and restores it on `stop`.

- An ad-hoc (IBSS) interface joins AWDL's BSSID to handle ACKs. Some AX211s
  need the Wi-Fi interface itself repurposed for this.
- The cell is HT20 and tries channels 44, 149 and 6 in that order, skipping any the card may not transmit on, since an iPhone gives AWDL more slots on 5 GHz. Cards that refuse a 5 GHz cell, like the Realtek RTL8822BE, end up on 6. Intel cards go straight to 6, since none has held a 5 GHz cell. Beacons every 10 seconds fix discovery after an iPhone restart.
- Cards without ad-hoc mode use a hidden AP (hostapd) with the station's MAC instead, on the same channels.
- OWL injects through a monitor interface, advertises our channel in all
  16 slots (`-S pin`), and elects its sync master by metric (`-E`). Unicast
  frames are sent once to avoid retries stalling the queue.
- The MediaTek MT7921, MT7922 and MT7612U use `mode active-monitor` instead: an active monitor carrying the station's MAC ACKs in place of the cell, on channel 6 (5 GHz first on the MT7612U) ([#24](https://github.com/t4t5/omdrop-owl/pull/24), from kmod-midori's [#13](https://github.com/t4t5/omdrop-owl/pull/13)).

## Development

The unit tests (no radio, no root, no network) run with `tools/run-tests.sh` and need [`bats`](https://github.com/bats-core/bats-core) and Python. The OWL tests (A-MSDU, padding, Block Ack) skip until `just build` has patched OWL. After pulling a new patch, run it again: a tree patched before then fails them.

`just build` assembles the same files in `build/lib`, and `just test` runs the
card test against them. On Arch, `makepkg -si` (or `just install`) builds and
installs the pacman package from the checkout.

Without the package, copy `packaging/99-omdrop-owl-unmanaged.conf` to
`/etc/NetworkManager/conf.d/` and run `sudo nmcli general reload conf`, or
NetworkManager manages OWL's interfaces and the phone never shows up. Copy
`packaging/10-omdrop-owl-awdl0.link` to `/etc/systemd/network/` too: where
udev's default MAC policy rewrites `awdl0`'s address (Ubuntu 22.04), the phone
is sent a link-local `awdl0` doesn't have and never connects.

## Known issues

- **Shared mode needs your AP on channel 6, 44 or 149.** On any other channel,
  `start` refuses and says so.
- **The MT7925 drops off Wi-Fi when the monitor interface is removed** (an
  mt76/firmware bug), so `stop` reconnects Wi-Fi straight after.
- **The MT7927 starts but is never heard.** It uses the MT7925's driver, so it runs the MT7925's shared profile without an opt-in, but its monitor interface doesn't receive the phone's frames. With an `active-monitor` line in `/etc/omdrop/owl-profiles` it's heard and can send, but the phone's uploads arrive at about 5 kB/s and time out ([#44](https://github.com/t4t5/omdrop-owl/issues/44)). Exclusive mode through the hidden AP is untested.
- **The MT7925 sends slower than it receives** (about 490 kB/s against
  1.3 MB/s): injected frames leave at most one every ~2.5 ms.
- **UFW blocks the receiver**, so the phone never sees this machine. Run
  `omdrop firewall install` to allow TCP 8771 from link-local addresses on
  `awdl0`.
- **Exclusive mode is slow on channel 6**, where Intel cards and others that refuse a 5 GHz cell run, since AWDL there gets few of the iPhone's slots: a 2.4 MB photo takes 10–17 s on an AX201.
- **The MT7921/MT7922 are unreliable.** `mt7921e` sends injected unicast at
  1 Mbit/s whatever rate is asked for, and not at all on 5 GHz, so discovery
  and the handshake often stall. Close and reopen the share sheet to retry.
