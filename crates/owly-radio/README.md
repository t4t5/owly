# owly-radio

AWDL, the Wi-Fi link AirDrop runs over, on Linux Wi-Fi cards that expose capture and injection. It's the radio under [Owly](https://github.com/t4t5/owly), and runs [owly-awdl](https://crates.io/crates/owly-awdl) over nl80211. Linux only.

- `radio::Backend` is the trait a radio service runs: `up` brings the link up (an `awdl0` interface with an IPv6 link-local address, and the AWDL peers heard on it), `down` gives Wi-Fi back, and `recover` undoes what a session left behind when its process died, from a journal.
- `injection::Injection` implements it with owly-awdl, on a monitor interface and a TAP `awdl0`, in the mode the card needs: shared, which keeps Wi-Fi connected; exclusive, with an ad-hoc cell or a hidden AP in the station's place; or active monitor.
- `firmware-monitor-shared` is the opt-in path for patched FullMAC firmware such as Nexmon on Raspberry Pi boards with supported onboard Wi-Fi. It leaves the station connected and uses a passive monitor netdev on the access point's channel. Two-way AirDrop and Wi-Fi coexistence still need hardware testing. The older `firmware-monitor` path remains available through a driver override for exclusive tests.
- `probe` finds what the card can do, without root. `quirks` holds what the probe can't detect, per driver: the `drivers.toml` packaged with the crate, with `/etc/owly/drivers.toml` read over it. `config` reads `/etc/owly/radio.toml`.
- `fake` is a backend for testing what runs on top.

Bringing the radio up needs `CAP_NET_ADMIN` and `CAP_NET_RAW`, and runs NetworkManager's `nmcli`, `ip`, `ping` and, on cards without ad-hoc mode, `hostapd`. owlyd, Owly's system service, runs it and lends the link out over D-Bus. [Owly's README](https://github.com/t4t5/owly#supported-hardware) says which cards work in which mode.

## Status

On 0.x until Owly 1.0: the API can change between minor versions.

## License

MIT
