# Open questions

What [the spec](SPEC.md) states that hasn't been confirmed by a capture of Apple devices, or leaves undefined because nobody knows yet. Settle them with captures (`tests/captures/`) before building on them, then update the spec and drop the item here.

1. How phone numbers and email addresses are normalized before hashing (BLE-4).
2. What byte 0 (`0x40`) and the 3-byte tag of a version 3 BLE advertisement mean, and whether version 1 still wakes current iPhones (BLE-2, BLE-5).
3. The HTTP status of a `401` `/Discover` response (DISC-2).
4. Which flag bit is pipelined upload. Analysis of `sharingd` names a SupportsUPP bit "0xb", and gives `0x3FB` as an example of it, which has neither `0x004` nor `0x800` set (MDNS-4).
5. Whether macOS receivers time out an unanswered `/Ask`, and what they send then. iOS has no timeout of its own, and answers a decline with `401` (ASK-2).
6. `TransferVersion`'s type and values, and what they unlock. It's said to gate DVZip and pipelined upload (§6.3).
7. The validation record's key names, and whether it binds to the account the sender's TLS client certificate names (ID-2, TLS-3).
8. What `/SharedIdentity` and `/Error` do, and whether a receiver must serve them for current senders (HTTP-4).
9. The other keys, about 24, that Apple receivers publish in TXT, and whether any matter to Apple senders (MDNS-1).
10. Whether an identity extracted from the user's own Mac gets accepted without a prompt on their iPhone (ASK-6).
11. The layouts of the Sync Tree (20) and Bloom Filter (22) TLVs (AWDL-6), and the Service Response TLV's name codes other than those in §3.2. Whether reading a peer's Service Response TLVs would spare the sender its probe (DISC-5): an iPhone's mDNS doesn't reach a Linux node.
12. *Settled* (§6.4).
13. What `SenderIdentityAuthTag` is, and whether Contacts Only receivers need it. It changes with each transfer, and isn't the BLE advertisement's tag (§6.4).
14. What `IDSSessionID` and `ReceiverPseudonym` in the `/Discover` response, and `SenderPseudonym` and `SenderPushToken` in `/Upload`, are for (§6.3, §6.5).
15. Whether macOS receivers require the current `/Ask` form too (ASK-7).
16. Whether Apple peers need the ICMPv6 echo of OWLY-2 to learn a node's neighbor entry, or something else Owly does already teaches them.

## Sources

The spec was assembled from reverse engineering, captures (`tests/captures/`) and these sources:

- Ale Ebrahim, Tippenhauer. *Protocol Prying: Systematic Vulnerability Research in the Apple AirDrop and Android Quick Share Proximity Transfer Protocols.* CISPA, 2026. Artifact: https://zenodo.org/records/20442029 (`Airfuzz.zip`, CC BY 4.0). Its `protocol-docs/RESEARCH_DOCUMENT.md` documents a Finder → iPhone transfer captured inside `sharingd`, and a third-party sender iOS 18.1 accepted.
- Stute, Kreitschmann, Hollick. *One Billion Apples' Secret Sauce: Recipe for the Apple Wireless Direct Link Ad hoc Protocol.* MobiCom 2018.
- Stute, Narain, Mariotto, Heinrich, Kreitschmann, Noubir, Hollick. *A Billion Open Interfaces for Eve and Mallory: MitM, DoS, and Tracking Attacks on iOS and macOS Through Apple Wireless Direct Link.* USENIX Security 2019.
- Stute, Heinrich, Lorenz, Hollick. *Disrupting Continuity of Apple's Wireless Ecosystem Security.* USENIX Security 2021.
- Heinrich, Hollick, Schneider, Stute, Weinert. *PrivateDrop: Practical Privacy-Preserving Authentication for Apple AirDrop.* USENIX Security 2021.
- Martin et al. *Handoff All Your Privacy: A Review of Apple's Bluetooth Low Energy Continuity Protocol.* PETS 2019.
- Kleidermacher. *Android Quick Share support for AirDrop: a secure approach to cross-platform file sharing.* Google Security Blog, November 2025.
