# omdrop-awdl's tools

The sending half of Omdrop's bash and Python version, and the announcer `omdrop-discoverable` runs, from [omdrop-awdl](https://github.com/netmojo-systems/omdrop-awdl) at commit `e7891ab56957dde46f134c1991e4e4717f94d2e4` (omdrop-awdl 0.10.0, helper contract 0.10.0). They're unmodified, and under omdrop-awdl's licence, GPL-2.0-only ([LICENSE](LICENSE); omdrop-awdl's README says its userspace helpers share its patches' licence). omdrop-owl 0.3.0 and 0.4.0 shipped them from `534f91a` (0.8.1), whose `send-to-peer` predates `--url`.

| File | What it does |
|---|---|
| `send-to-peer` | picks a peer and drives `airdrop-send.py`; `omdrop send` and `omdrop peers` run it |
| `airdrop-send.py` | the AirDrop client: `/Discover`, `/Ask`, `/Upload` |
| `awdl-af-parse.py` | imported by `airdrop-send.py` |
| `awdl_identity.py` | identity, host name and record data for all of these |
| `awdl_debug.py` | imported by `airdrop-send.py` |
| `ble-airdrop-adv.py` | the BLE Continuity advert that wakes a receiver |
| `awdl-airdrop-adv.py` | unsolicited `_airdrop._tcp` announcements on `awdl0`, which `omdrop-discoverable`'s supervisor sends |
| `awdl-mdns-respond.py` | answers mDNS queries for our identity on `awdl0` |

They talk to `awdl0` through sockets and to BlueZ over D-Bus, and touch nothing below that, so they run on Owly's `awdl0` as they ran on OWL's. The omdrop-owl package installs them in `/usr/lib/omdrop`, beside `omdrop-discoverable`. Where omdrop-core is installed, Omdrop uses its own sender instead.

Change them only by copying another omdrop-awdl commit, and the helper contract with it (`CONTRACT` in `src/main.rs`). They go, with `omdrop-discoverable`, once Omdrop retires its bash and Python version.
