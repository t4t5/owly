# AirDrop protocol specification

This document specifies AirDrop: how a device wakes nearby devices, finds the ones it may send to, asks a receiver's user for permission, and transfers files or links to it over Apple Wireless Direct Link (AWDL).

Version: 1.0. This is an independent specification. It isn't published by Apple or affiliated with Apple.

Scope: sending and receiving files and links in the Everyone and Contacts Only visibility modes. NameDrop and the other services listed as out of scope in HTTP-4 aren't specified here.

## 0. Conventions

### 0.1 Requirement language

MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119. Each normative statement has an ID such as `ASK-3` so that tests, commits and issues can cite it. IDs are stable: a removed requirement keeps its number and is marked *withdrawn*.

A field marked *reserved* is sent with the value given, or zero if none is given, and ignored on receipt. A field or key described as *not defined in this version* may appear in messages. This document gives it no meaning, and an implementation doesn't need to send it.

### 0.2 Terms

| Term | Meaning |
|---|---|
| node | a device taking part in AWDL |
| peer | another node, as seen by a node |
| sender, receiver | the two AirDrop roles. A device can take both. |
| AWDL interface | the network interface that carries a node's AWDL data traffic, `awdl0` on Apple devices |
| TU | time unit: 1024 µs |
| AW | availability window: a 16 TU period in which a node is reachable on the channel it advertises |
| slot | 4 AWs (64 TU) on one channel, an entry of the channel sequence (§3.4) |

### 0.3 Byte order

Multi-byte fields are little-endian unless marked `BE` (big-endian / network order).

## 1. Architecture

AirDrop is a stack of seven layers. Each layer can be built and tested independently.

| # | Layer | Technology |
|---|---|---|
| 7 | Archive | CPIO (odc; see UP-2) |
| 6 | Compression | gzip, or DVZip |
| 5 | Encoding | binary property list (`bplist00`) |
| 4 | Transport | HTTP/1.1 |
| 3 | Security | TLS 1.2 / 1.3 |
| 2 | Network | IPv6 link-local on the AWDL interface |
| 1 | Link | AWDL, with BLE as the wake-up trigger |

A transfer runs in three phases over two TLS connections:

```
 Sender S                                              Receiver R
 ────────                                              ──────────
 (1) DISCOVERY
 BLE advert: S's 2-byte contact hashes  ─────────────▶ scans BLE regularly;
                                                       if Everyone, or a hash matches
                                                       a contact: activate AWDL
 AWDL synchronization                   ◀────────────▶
 mDNS query _airdrop._tcp               ─────────────▶
                                        ◀───────────── SRV / TXT / AAAA

 (2) AUTHENTICATION  — TLS connection #1, per discovered service
 POST /Discover  {S's record}           ─────────────▶ if Everyone or record matches:
                                        ◀───────────── 200 {name, model, R's record if S's is valid}
 TLS teardown                                          (R appears in S's share sheet,
                                                        as a contact if R's record is valid)

 (3) DATA TRANSFER   — TLS connection #2, after the user picks R
 POST /Ask  {TransferID, files}         ─────────────▶ prompt user (blocks, 15 s timeout)
                                        ◀───────────── 200 = accepted
 POST /Upload  TransferID: <same UUID>  ─────────────▶ extract
               (DVZip|gzip of odc cpio)
                                        ◀───────────── 200
 TLS teardown
```

A link share is the same flow with no `/Upload`: the URL travels inside `/Ask`.

## 2. Trigger layer: Bluetooth LE

A receiver scans for BLE regularly. It activates AWDL and its AirDrop server only when it hears an AirDrop advertisement **and** is in Everyone mode or one of the advertised contact hashes matches a contact. A receiver that keeps AWDL and its server running doesn't need BLE. A sender does, or receivers that wait for an advertisement never become reachable.

**BLE-1** (sender, MUST) While browsing for receivers, the sender MUST transmit a BLE advertisement carrying Apple manufacturer data (company ID `0x004C`) with an AirDrop TLV, type `0x05`.

**BLE-2** The AirDrop TLV payload is 18 bytes (`0x12`). This is version 3:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 1 | reserved | `0x40` |
| 1 | 3 | tag | rotates with the advertiser's BLE address (BLE-5) |
| 4 | 4 | reserved | `00 × 4` |
| 8 | 1 | version | `0x03` |
| 9 | 8 | contact hashes | four 2-byte hashes, each the first 2 bytes of SHA-256 of the sender's Apple ID, a phone number or an email address |
| 17 | 1 | reserved | `0x00` |

The hashes are in no fixed order: a sender rotates them between advertisements with the same tag. A receiver that matches contacts MUST compare against every slot.

Version 1 has the same layout, with offsets 0–7 all zero and `0x01` at offset 8.

**BLE-3** (sender) A sender with no Apple identity MAY send zero hashes. Everyone-mode receivers wake regardless of the hashes. Contacts Only receivers won't wake at all, so such a sender can never reach them.

**BLE-4** This version doesn't specify how phone numbers and email addresses are normalized before hashing.

**BLE-5** (sender) A sender SHOULD send version 3 with a random tag, as a connectable advertisement at a 100 ms interval. With zero hashes, it wakes receivers in Everyone mode.

## 3. Link layer: AWDL

AWDL (Apple Wireless Direct Link) is a peer-to-peer 802.11 protocol. Nodes elect a master, follow its schedule of availability windows, and advertise the channel they'll be on in each slot. Peers then exchange ordinary data frames inside the windows they share. A node carries IPv6 over AWDL on its AWDL interface.

### 3.1 Addressing

**AWDL-1** All AWDL frames MUST use BSSID `00:25:00:ff:94:73`.

**AWDL-2** A node's AWDL address (the 802.11 source address it advertises) MUST equal the MAC address of its AWDL interface, and MUST NOT change while the node is visible. Peers derive its IPv6 link-local address from the AWDL address (§4), so a node whose interface has another address can't be reached.

### 3.2 Action frames

AWDL control traffic is 802.11 management action frames.

**AWDL-3** Action frame header, following the 802.11 MAC header:

| Size | Field | Value |
|---|---|---|
| 1 | category | `127` (vendor-specific) |
| 3 | OUI | `00:17:f2` |
| 1 | type | `8` (AWDL) |
| 1 | version | AWDL 1.0, major in high nibble |
| 1 | subtype | `0` = PSF (Periodic Synchronization Frame), `3` = MIF (Master Indication Frame) |
| 1 | reserved | `0` |
| 4 | phy_tx | µs timestamp at transmission |
| 4 | target_tx | µs timestamp the frame was scheduled for |

A sequence of TLVs follows the header.

**AWDL-4** TLV encoding: `type` (u8), `length` (u16), `value` (`length` bytes).

**AWDL-5** (MUST) A parser MUST accept trailing zero padding of fewer than 3 bytes after the last TLV, which some nodes add to MIFs. A nonzero remainder is a truncated TLV and MUST be rejected.

**AWDL-6** TLV types:

| Type | Name | Required |
|---|---|---|
| 2 | Service Response (mDNS records) | no, see MDNS-2 |
| 4 | Synchronization Parameters | yes |
| 5 | Election Parameters | yes |
| 6 | Service Parameters | yes |
| 7 | HT Capabilities | for HT rates |
| 12 | Data Path State | yes |
| 16 | ARPA (host name) | yes |
| 18 | Channel Sequence | yes |
| 20 | Sync Tree | no |
| 21 | Version | yes |
| 22 | Bloom Filter | no |
| 24 | Election Parameters v2 | yes |
| 0, 1, 8–11, 13–15 | (deprecated) | no, ignore |
| other | (unknown) | no, MUST be skipped by length, not rejected |

A PSF carries types 4, 5, 18, 24, 6, 7, 12 and 21, in that order. A MIF adds 16 after 7.

The layouts follow. Offsets are into the TLV's value, after its 3-byte header. The layouts of types 2, 20 and 22 aren't defined in this version.

**Synchronization Parameters (4)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 1 | next AW channel | the channel of the node's next AW |
| 1 | 2 | TX down-counter | TU to the next slot boundary |
| 3 | 1 | master channel | |
| 4 | 1 | guard time | `0` |
| 5 | 2 | AW period | `16` (TU) |
| 7 | 2 | action frame period | TU between PSFs, `110` |
| 9 | 2 | flags | reserved, `0x1800` |
| 11 | 2 | extended AW length | `16` |
| 13 | 2 | common AW length | `16` |
| 15 | 2 | remaining AW length | TU left in the current AW |
| 17 | 4 | min extension, then max extension for multicast, unicast and action frames | `3` each |
| 21 | 6 | master address | |
| 27 | 1 | presence mode | `4`: AWs per slot |
| 28 | 1 | reserved | `0` |
| 29 | 2 | next AW sequence number | |
| 31 | 2 | AP alignment | |
| 33 | | channel sequence | as in type 18 |
| | 2 | padding | `0` |

A reader needs only offsets 0–30.

**Election Parameters (5)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 1 | flags | `0` |
| 1 | 2 | ID | `0` |
| 3 | 1 | distance to the top master | |
| 4 | 1 | reserved | `0` |
| 5 | 6 | top master address | |
| 11 | 4 | top master metric | |
| 15 | 4 | own metric | |
| 19 | 2 | padding | `0` |

A node ignores type 5 from a peer that also sends type 24.

**Service Parameters (6)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 3 | reserved | `0` |
| 3 | 2 | SUI | `0` |
| 5 | 4 | bitmask | `0` |

A node sends it as zeros. A changed SUI makes peers flush their mDNS caches.

**HT Capabilities (7)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 2 | reserved | `0` |
| 2 | 2 | HT capability info | as in the 802.11 HT Capabilities element |
| 4 | 1 | A-MPDU parameters | as in the 802.11 HT Capabilities element |
| 5 | 1 or more | RX MCS mask | a bit per MCS, from MCS 0 |
| last | 2 | reserved | `0` |

**Data Path State (12)**

Flags (offset 0, 2 bytes), then the fields the flags announce, in this order:

| Flag | Size | Field |
|---|---|---|
| `0x0100` | 3 | country code |
| `0x0200` | 2 | social channel map: `0x1` channel 6, `0x2` channel 44, `0x4` channel 149 |
| `0x0001` | 8 | infrastructure BSSID and channel |
| `0x0002` | 6 | infrastructure address |
| `0x0004` | 6 | AWDL address |

Other flag bits are reserved. The TLV can end with 2 bytes of extended flags, reserved.

**ARPA (16)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 1 | flags | `3` |
| 1 | 1 | name length | *n* |
| 2 | *n* | host name | the first label, without `.local` |
| 2 + *n* | 2 | domain (BE) | `0xc00c`, a DNS name pointer to `.local` |

**Channel Sequence (18)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 1 | slot count less one | `15` |
| 1 | 1 | encoding | AWDL-10 |
| 2 | 1 | duplicate count | `0` |
| 3 | 1 | step count: AWs per slot less one | `3` |
| 4 | 2 | fill channel | `0xffff` |
| 6 | 16 × 1 or 2 | slots | AWDL-10 |
| | 3 | padding | `0` |

The slot count, duplicate count, step count and fill channel take no other values.

**Version (21)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 1 | AWDL version | major in the high nibble |
| 1 | 1 | device class | `1` macOS, `2` iOS, `8` tvOS |

**Election Parameters v2 (24)**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 6 | master address | |
| 6 | 6 | sync address | |
| 12 | 4 | master counter | |
| 16 | 4 | distance to the master | |
| 20 | 4 | master metric | |
| 24 | 4 | own metric | |
| 28 | 4 | reserved | `0` |
| 32 | 4 | reserved | `0` |
| 36 | 4 | own counter | |

### 3.3 Synchronization and election

**AWDL-7** Nodes elect a sync master by metric, with a counter to break ties. Non-masters align their AW schedule to the master's Synchronization Parameters TLV (AW period, next AW sequence number, TX down-counter).

**AWDL-8** A node SHOULD start with election metric 60 and counter 0.

**AWDL-9** A node that can't follow the master's schedule MAY raise its metric to win the election and impose its own.

**AWDL-17** (MUST) A node MUST treat a peer as valid, and give it a neighbor entry (NET-2), only once it has sent a MIF and a Version TLV with a nonzero version and device class, and MUST NOT follow it in the election before then. A valid peer that's been silent for 5 s is dropped. Data frames from a peer count as hearing it, since a peer in the middle of a transfer can go seconds between the action frames a node hears.

### 3.4 Channel sequence

**AWDL-10** The channel sequence has 16 slots, one channel per slot. Channels are encoded as *simple* (`0`, 1 byte: the channel number), *legacy* (`1`, 2 bytes: flags, then the channel number) or *opclass* (`3`, 2 bytes: the channel number, then its operating class). Channel 0 means the node is on no channel in that slot.

**AWDL-11** Social channels are 6, 44 and 149. A node MUST be present on at least one of them, and peers can only exchange data in slots where both are on the same channel.

**AWDL-12** A node MUST advertise, in each slot, only the channel it'll actually be on, and channel 0 in a slot it won't serve. A node that stays on one channel advertises that channel in the slots it serves. A peer sends into a slot it believes is shared, so a slot advertised but not served loses its frames.

### 3.5 Data frames

**AWDL-13** Data frames are 802.11 data frames whose body is LLC/SNAP (`AA AA 03`, OUI `00:17:f2`, protocol `0x0800`) followed by the AWDL data header:

| Size | Field | Value |
|---|---|---|
| 2 | head | `0x0403` |
| 2 | seq | per-node sequence number, incremented per frame |
| 2 | pad | `0x0000` |
| 2 | ethertype (BE) | `0x86DD` (IPv6) |

The IPv6 packet follows.

**AWDL-14** (receiver, MUST) A node MUST accept A-MSDU aggregated frames, and MUST bound how many subframes it unpacks per frame. The frame is a QoS data frame with the QoS control's A-MSDU bit (`0x0080`) set. Each subframe is the destination and source address, a big-endian length, then the body of AWDL-13 from the SNAP header on, padded to 4 bytes before the next.

**AWDL-15** (SHOULD) A node SHOULD accept a peer's Block Ack (ADDBA) request, which lets the peer aggregate frames and makes its uploads several times faster. The response (category 3, action 1) echoes the dialog token with status 0, immediate Block Ack, the requested TID, no A-MSDU in A-MPDUs, a window of the requested size capped at 64, and the requested timeout.

**AWDL-16** Unicast data MUST be sent only inside a shared AW, keeping clear of a 3 TU guard at the window edges. Multicast keeps a 16 TU guard and goes in slots 0 and 10. A node that stays on one channel (AWDL-12) sends multicast in any slot it serves, with the 3 TU guard, since the first AW may be all a peer spends on its channel.

**AWDL-18** (SHOULD) A peer can open a TCP connection before it's valid (AWDL-17). A node SHOULD hold a TCP SYN addressed to it from a peer that isn't valid yet, for up to 2 s, and deliver it once the peer is valid and has its neighbor entry (NET-2). Delivered earlier, its SYN-ACK has no neighbor to go to.

**AWDL-19** *withdrawn*

## 4. Network layer

**NET-1** The AWDL interface MUST have an IPv6 link-local address derived from its MAC address by modified EUI-64.

**NET-2** Peers MUST be addressed by link-local address, scoped to the AWDL interface (`fe80::…%awdl0`). A peer's link-local address and neighbor entry come from its AWDL address, not from Neighbor Discovery over the air.

**NET-3** Only IPv6 is used. A node MUST NOT depend on IPv4 being present on the AWDL interface.

**NET-4** (receiver, MUST) A receiver MUST accept TCP connections to its AirDrop port (§5) from any link-local address on the AWDL interface. A sender lists a receiver only once its `/Discover` succeeds (§6.3), so a receiver that can't be reached is absent from the sender's list, with nothing to show why.

## 5. Discovery layer: mDNS / DNS-SD

**MDNS-1** (receiver, MUST) The receiver announces a DNS-SD service on the AWDL interface, IPv6 only:

| Record | Value |
|---|---|
| Service type | `_airdrop._tcp.local.` |
| Instance name | *service ID*: 12 lowercase hex digits (6 random bytes), e.g. `3fa9c01b22de` |
| SRV target | `<hostname>.local.` |
| SRV port | the receiver's HTTPS port, conventionally `8770`. A sender that has the SRV record MUST use its port. |
| AAAA | the link-local address of the AWDL interface |
| TXT | `flags=<decimal receiver flags>` (MDNS-4). Receivers may publish further keys, which aren't defined in this version. |

**MDNS-2** Over AWDL, these records also travel in the Service Response TLV (§3.2) of action frames.

**MDNS-3** The service ID SHOULD stay the same for the whole visible session and is reused as `SenderID` in `/Discover` and `/Ask` (§6).

**MDNS-4** Receiver flags (TXT `flags`):

| Bit | Name | Meaning |
|---|---|---|
| `0x001` | SupportsURLSharing | receives links (§6.4) |
| `0x002` | SupportsDVZip | accepts DVZip uploads (§6.6) |
| `0x004` | SupportsPipelining | accepts pipelined uploads (UP-8) |
| `0x008` | SupportsMixedTypes | accepts files of different types in one transfer |
| `0x040` | SupportsIris | not defined in this version |
| `0x080` | SupportsDiscoverMaybe | serves `/Discover` |
| `0x200` | SupportsAssetBundle | not defined in this version |

Other bits are reserved.

**MDNS-5** A receiver MUST set SupportsPipelining or SupportsMixedTypes, or senders discard it as invalid. A receiver MUST NOT advertise a capability it doesn't implement. Without SupportsDVZip, senders upload gzip. Without SupportsURLSharing, a receiver gets no links: a sender offers a link to it as a `.webloc` entry in `Files` that it never uploads. A minimal receiver SHOULD therefore advertise `0x089` (SupportsURLSharing | SupportsMixedTypes | SupportsDiscoverMaybe).

**MDNS-6** (sender) A sender MUST treat an instance as reachable only after its SRV and AAAA records resolve, and SHOULD drop it when the announcement is withdrawn or expires.

**MDNS-7** (receiver, MUST) A receiver that doesn't carry its records in the Service Response TLV (MDNS-2) MUST repeat its unsolicited announcement (RFC 6762 §8.3) in bursts for the whole visible session, not only when it starts. A node sends multicast only in some slots, and a peer is on the node's channel in only some of those, so a single announcement is easily missed. How many copies a burst needs, and how far apart, depends on how the node's channel sequence overlaps its peers'.

## 6. Session layer: TLS and HTTP

### 6.1 Transport

**TLS-1** All AirDrop HTTP runs over TLS 1.2 or 1.3. Endpoints MUST NOT offer TLS 1.0. No ALPN protocol is negotiated, and sessions aren't resumed.

**TLS-2** TLS provides encryption only, not peer authentication. Receivers accept self-signed certificates, don't check host names, and accept any TLS connection in every visibility mode, Contacts Only included. Identity is carried in the record (§7); for the sender's client certificate, see TLS-3. An implementation MUST present a certificate and MUST NOT reject a peer for being self-signed.

**TLS-3** Asked for a client certificate, a sender presents one on the connection that carries `/Ask` and `/Upload`, and none on the `/Discover` connection. It's a two-certificate chain: a leaf with subject `CN=com.apple.idms.appleid.prd.<account ID>` and extended key usages client and server authentication, issued by Apple Application Integration Certification Authority, and that intermediate, issued by Apple Root CA. Whether a receiver should check it isn't defined in this version. A sender MUST NOT depend on presenting one. A receiver MUST accept connections without one, and SHOULD accept them with one.

**HTTP-1** (connections) HTTP/1.1. `/Ask` and `/Upload` MUST share one TLS connection: a receiver rejects an `/Upload` on any other (UP-6). A sender sends `/Discover` on its own connection and opens a new one for `/Ask` and `/Upload`. It can leave the `/Discover` connection open, idle, and reset it about 30 s later. A receiver MUST also accept `/Discover` followed by `/Ask` on the same connection.

**HTTP-2** All requests are `POST`. A sender SHOULD send `/Ask` with only these headers, and no `Host` or `Accept*`:

```
POST /Ask HTTP/1.1
User-Agent: AirDrop/1.0
Content-Type: application/octet-stream
Connection: keep-alive
Transfer-Encoding: chunked
```

Some senders also send `Accept`, `Accept-Language` and `Accept-Encoding`. A receiver MUST NOT require `Host` or any `Accept*` header.

**HTTP-2a** Bodies of `/Discover` and `/Ask` are sent with either `Transfer-Encoding: chunked` or `Content-Length`. A receiver MUST accept both.

**HTTP-3** Request and response bodies for `/Discover` and `/Ask` are **binary property lists** (`bplist00`).

**HTTP-4** A receiver serves seven paths:

| Path | Purpose | Section |
|---|---|---|
| `/Discover` | visibility check | §6.3 |
| `/Ask` | consent | §6.4 |
| `/Upload` | payload | §6.5 |
| `/Hello` | optional handshake between Macs | out of scope. A sender MUST NOT send it. |
| `/Exchange` | NameDrop contact exchange | out of scope |
| `/SharedIdentity` | not defined in this version | out of scope |
| `/Error` | not defined in this version | out of scope |

**HTTP-5** (receiver) A `POST` to any other path MUST get `400` with an empty body. A receiver SHOULD answer `GET` and `HEAD` with `200`.

**HTTP-6** (sender, MUST NOT) A sender MUST NOT send a request to any path outside the table above.

**HTTP-7** (receiver) Per connection, the receiver keeps one slot each for Discover, Ask and Upload, all initially empty:

- `/Discover` is accepted only when all three slots are empty, so at most once per connection.
- `/Ask` clears the Discover slot, then requires all slots empty.
- `/Upload` requires the Upload slot to be empty, and is processed only after the Ask on the same connection was accepted.

### 6.2 Plist types

Schemas below use: `string`, `bool`, `int`, `data` (raw bytes), `array<T>`, `dict`. "Req" says whether the field is required (R), optional (O), or required only in a stated condition (C).

### 6.3 `POST /Discover`

The sender asks the receiver whether it may see it. A receiver in Contacts Only mode answers only senders whose record matches one of its contacts.

**Request**

| Key | Type | Req | Notes |
|---|---|---|---|
| `SenderRecordData` | data | C | Sender's record (§7). Required for a Contacts Only receiver to match. |
| `SenderComputerName` | string | O | |
| `SenderModelName` | string | O | |
| `SenderID` | string | O | Sender's service ID (MDNS-3). |
| `TransferVersion` | | O | Not defined in this version. |

An empty dict is a valid request.

**Response**

| Key | Type | Req | Notes |
|---|---|---|---|
| `StatusCode` | int | O | `100` = Everyone mode, `200` = sender matched a contact, `401` = Contacts Only and no match. A receiver can leave it out of a response that lists the sender. |
| `ReceiverComputerName` | string | C | Display name. Present ⇔ the sender may see this receiver. |
| `IsAirDropable` | bool | O | `true` in a response that lists the sender. Not defined further in this version. |
| `ReceiverModelName` | string | O | e.g. `MacBookPro18,1`. Senders choose the receiver's icon from it. |
| `ReceiverMediaCapabilities` | data | O | UTF-8 **JSON** (not a plist), see DISC-3. |
| `ReceiverRecordData` | data | O | Receiver's record (§7). Lets the sender show it as a contact. |
| `IDSSessionID` | | O | Not defined in this version. It isn't the `TransferID`. |
| `ReceiverPseudonym` | | O | Not defined in this version. |

A sender MUST ignore response keys it doesn't know.

**DISC-1** (sender) A sender MUST list a receiver only if the response contains `ReceiverComputerName`.

**DISC-2** (receiver) A Contacts Only receiver with no match MUST respond with `StatusCode` `401` and no `ReceiverComputerName`. The HTTP status may be `200` or `401`. A sender decides by DISC-1 alone.

**DISC-3** `ReceiverMediaCapabilities` is JSON such as `{"Version": 1}`. A receiver that leaves out `Codecs` and `ContainerFormats` gets media in widely supported formats (JPEG instead of HEIC). A receiver MUST NOT advertise a codec it can't store or display.

**DISC-4** (receiver) A receiver SHOULD include `ReceiverRecordData` only when the sender's record verified, so it doesn't reveal its identity to strangers.

**DISC-5** (sender) A peer can be present on AWDL without a `_airdrop._tcp` instance the sender can resolve. A sender MAY then post `/Discover` to port `8770` at the peer's link-local address, derived from its AWDL address (NET-1), and MUST list the peer only if that `/Discover` succeeds under DISC-1. A receiver refuses connections until a sender's BLE advertisement has woken it (§2), which can take many seconds, so a sender SHOULD keep retrying `/Discover` while it advertises rather than give up at the first refusal.

### 6.4 `POST /Ask`

The sender asks permission and describes what it will send.

There are two forms. The **current form** carries `TransferID` and `TransferType`. Earlier senders send a **legacy form** without them. Senders MUST send the current form (ASK-7). Receivers MUST accept both.

An `/Ask` for one photo, in the current form (data shown as `<hex>`):

```
{
  BundleID: "com.apple.finder",
  ConvertMediaFormats: false,
  Files: [{
    FileBomPath: "./IMG_0049.HEIC",
    FileIsDirectory: false,
    FileName: "IMG_0049.HEIC",
    FileSize: 141853,
    FileType: "public.heic",
    ShouldConvertMediaFormats: false,
  }],
  Items: [],
  SenderComputerName: "Example MacBook Pro",
  SenderID: "486ac2a94ac6",
  SenderIdentityAuthTag: <0c504b>,
  SenderModelName: "MacBook Pro",
  TransferID: { id: "A3F34E01-1234-5678-ABCD-EF0123456789" },
  TransferType: { files: {} },
}
```

**Request**

| Key | Type | Req | Notes |
|---|---|---|---|
| `TransferID` | dict | R (current) | `{"id": "<UUID, uppercase>"}`. A fresh UUID per transfer. It ties `/Upload` to this `/Ask` (UP-9). |
| `TransferType` | dict | R (current) | `{"files": {}}` for a file share, `{"links": {}}` for a link share. |
| `SenderComputerName` | string | R | Shown in the prompt. |
| `SenderModelName` | string | R | |
| `SenderID` | string | R | Sender's service ID (MDNS-3). |
| `BundleID` | string | R | Originating app, e.g. `com.apple.finder`. |
| `ConvertMediaFormats` | bool | R | `false`: don't transcode. |
| `SenderRecordData` | data | C | As in `/Discover`. |
| `SenderIdentityAuthTag` | data | O | 3 bytes, different for each transfer, and not the BLE advertisement's tag (BLE-2). Not needed in Everyone mode. Its derivation isn't defined in this version. |
| `Files` | array\<dict\> | C | Required for a file share, see below. Empty with a link share. |
| `Items` | array\<string\> | C | The URLs, for a link share. Empty with a file share. The legacy form omits it. |
| `FileIcon` | data | O | Preview thumbnail, JPEG 2000, ≤ 540 px on the long side. |

A request MUST carry a non-empty `Files` or a non-empty `Items`, not both.

A link share in the current form carries `TransferType` `{"links": {}}`, the URLs in `Items` and an empty `Files`, with `BundleID` naming the app it was shared from, such as `com.apple.mobilesafari`. It can carry a `FileIcon`.

**`Files[]` entry**

| Key | Type | Req | Notes |
|---|---|---|---|
| `FileName` | string | R | Base name. |
| `FileType` | string | R | Uniform Type Identifier, e.g. `public.heic`, `public.jpeg`, `public.data` (fallback). Not a MIME type. |
| `FileSize` | int | R (current) | Uncompressed size in bytes. |
| `FileBomPath` | string | R | Path inside the `/Upload` archive: `./<FileName>`, or `./<folder>/<FileName>` for a regular file in a wrapper directory. The `./` prefix is required. |
| `FileIsDirectory` | bool | R | |
| `ShouldConvertMediaFormats` | bool | R (current) | `false`. |
| `ConvertMediaFormats` | int | legacy | `0`. The legacy form's name for the field above. |

**Response**

| Key | Type | Req |
|---|---|---|
| `ReceiverComputerName` | string | R |
| `ReceiverModelName` | string | R |

**ASK-1** `200` means accepted. Any other status, a closed connection, or no response within the sender's timeout means declined or failed, and the sender MUST NOT send `/Upload`.

**ASK-2** (receiver) A receiver that prompts its user MUST hold the `/Ask` request open until the user answers or its own timeout passes. That timeout SHOULD be 15 s. Some receivers have none, and keep the prompt up until the sender gives up (ASK-2a). On a decline, or its own timeout, a receiver SHOULD respond with `401` and close the connection, so the sender doesn't wait out its own timeout. Some senders don't treat another status, such as `403`, as a decline, and keep waiting. Some receivers send no response to a decline. Senders handle either under ASK-1.

**ASK-2a** (sender) A sender MUST time out an unanswered `/Ask` and treat it as declined. The timeout MUST be longer than 15 s, so that a slow user isn't cut off before the receiver gives up. Senders wait about 45 s, then reset the connection and report the transfer as declined.

**ASK-3** (receiver) A receiver MUST NOT accept without prompting unless the user has configured it to.

**ASK-4** (sender) For a link share, the sender MUST NOT send `/Upload`. The share is complete when `/Ask` returns `200`.

**ASK-5** (receiver) A receiver MUST treat every `FileName` and `FileBomPath` as untrusted (SEC-1). It MUST refuse an `/Ask` whose `FileBomPath` isn't `./<FileName>` or, for a regular file, `./<folder>/<FileName>`. The wrapper MUST be exactly one safe path component. The file written MUST have the name shown by the prompt.

**ASK-6** Receivers accept without prompting when the sender's record verifies as the receiver's own Apple ID (§7). No field of the request can claim this.

**ASK-7** (sender) A sender MUST send the current form. A receiver that gets an `/Ask` with `TransferID` missing, or sent as a plain string, may answer `200` without ever prompting its user, and then drop the `/Upload`.

### 6.5 `POST /Upload`

An `/Upload`'s headers:

```
POST /Upload HTTP/1.1
User-Agent: AirDrop/1.0
TransferID: A3F34E01-1234-5678-ABCD-EF0123456789
TotalBytes: 0
Content-Type: application/x-dvzip
Connection: keep-alive
Content-Length: 76166
```

A sender can also send `SenderPseudonym` (`pseud:` and base64) and `SenderPushToken` (64 hex digits). What they're for isn't defined in this version.

**UP-1** `Content-Type` is `application/x-dvzip` (DVZip, §6.6) or `application/x-cpio` (gzip).

**UP-1a** The body is sent either with `Content-Length` or with `Transfer-Encoding: chunked`. A receiver MUST accept both. Senders use both.

**UP-1b** (sender) A sender that doesn't know the receiver's TXT flags, such as one that found the receiver under DISC-5, SHOULD send DVZip.

**UP-2** The body is a compressed CPIO archive in the **odc** format (magic `070707`, 76-byte ASCII octal headers). A sender MUST send odc. A receiver MUST accept odc and SHOULD accept `newc` (magic `070701`).

**UP-2a** Archive layout, in order:

| Entry | Mode | Notes |
|---|---|---|
| `.` | `040755` (directory) | Root entry. Earlier senders leave it out. |
| `<FileBomPath>` | `0100644` (regular file) | One per `Files[]` entry, not necessarily in the order of `Files`. |
| `TRAILER!!!` | `0` | Terminator. |

A sender MUST send the `.` root entry. A receiver MUST accept archives with and without it.

For the wrapped regular-file form in ASK-5, the archive MAY include a `./<folder>` directory entry before the file. The receiver MUST save the file as `<FileName>` without retaining the wrapper directory.

**UP-3** (receiver) A receiver MUST answer `Expect: 100-continue` with `100 Continue`. Senders send it when the receiver doesn't advertise SupportsPipelining.

**UP-4** (receiver) A `Content-Type` other than the two in UP-1 → `406`, with `Connection: close`.

**UP-5** (receiver) A receiver SHOULD stream-extract rather than buffer the whole archive, and on success MUST respond `200`, `Content-Length: 0`, `Connection: close`.

**UP-6** (receiver) A receiver MUST reject an upload that doesn't follow an accepted `/Ask` on the same connection.

**UP-7** (receiver) A receiver MUST reject archive entries that aren't listed in the accepted `/Ask`, except for the wrapper directory entries in UP-2a and the metadata in UP-7a.

**UP-7a** (receiver) A sender can add AppleDouble members, named `._<name>`, that hold a file's metadata and aren't listed in the `/Ask`. A receiver SHOULD accept a `._<name>` member next to a listed item, or inside a listed directory, rather than reject the archive under UP-7, and MAY discard it.

**UP-8** (pipelining) If the receiver advertises SupportsPipelining, the sender MAY send `/Upload` before the `/Ask` response arrives. The receiver buffers the body while the prompt is up and processes it only after acceptance. On decline it MUST discard the body.

**UP-9** The `TransferID` header MUST equal `TransferID.id` from the `/Ask`. A receiver SHOULD reject an upload whose `TransferID` header doesn't match. It MUST accept an upload with no `TransferID` header when the `/Ask` used the legacy form.

**UP-10** `TotalBytes` is the sum of the files' `FileSize`, or `0`. A receiver MUST NOT rely on it.

**UP-11** (receiver) An upload is complete when the archive's `TRAILER!!!` entry has been read, whether or not the rest of the body, such as a chunked body's terminating zero-length chunk, has arrived. A receiver MUST then respond as UP-5 says rather than wait for the body to end.

### 6.6 DVZip

DVZip is a chunked compression for `/Upload`. Senders use it when the receiver advertises SupportsDVZip.

**DVZ-1** The stream is a sequence of chunks until EOF. Each chunk is a 4-byte BE length `n` followed by `n` bytes of zlib stream (RFC 1950: header, deflate data, Adler-32). A length with its top bit set (`0x80000000`) is a *stored* chunk: the next `n & 0x7fffffff` bytes are the archive's bytes as they are, not compressed. Senders store a piece that zlib doesn't shrink, so photos and videos, already compressed, are mostly stored chunks.

**DVZ-2** A sender splits the uncompressed archive into 64 KiB (65536-byte) pieces and compresses each one independently, for example at zlib level 6. Every chunk therefore decompresses on its own, and concatenating the outputs gives the archive.

**DVZ-3** (receiver) A receiver MUST accept stored chunks (DVZ-1). It MUST reject a chunk length that runs past the end of the body or exceeds its configured limit, an empty chunk, and a compressed chunk that isn't one complete zlib stream. A receiver MUST NOT assume each chunk inflates to exactly 64 KiB.

**DVZ-4** A sender switches between compressed and stored chunks within one stream as the data's compressibility changes. A receiver that advertises SupportsDVZip MUST reject a stream it can't parse under DVZ-1 rather than guess.

## 7. Identity: Contacts Only mode

**ID-1** An identity is (a) a TLS certificate and key that Apple issues for the user's Apple ID, and (b) a **validation record**: a DER-encoded CMS (RFC 5652) SignedData blob, signed by Apple and embedding its certificate chain. The record binds the identity to SHA-256 hashes of the user's verified phone numbers and email addresses. It is sent as `SenderRecordData` and `ReceiverRecordData`.

**ID-2** The record carries the hashes as `ValidatedEmailHashes` and `ValidatedPhoneHashes`, with `altDsID` and a validity date. Its full schema isn't defined in this version.

**ID-3** (receiver, Contacts Only) A receiver verifies the record's certificate chain up to Apple's root CA, hashes each identifier in the user's contacts, and answers `/Discover` with a name only if one matches.

**ID-4** (receiver, Everyone) A receiver answers every `/Discover`. A sender record, if present and valid, MAY be used to show a contact name.

**ID-5** A record MUST only be presented with the certificate it was issued for. Apple issues identities to devices signed in to an Apple ID. How any other device obtains one is out of scope.

**ID-6** Visibility modes: Receiving Off (no listener), Contacts Only, and Everyone. On iOS, Everyone reverts to Contacts Only after 10 minutes. macOS has no such timeout. A sender without an identity can reach an iPhone only inside that 10-minute window.

## 8. State machines

### 8.1 Sender

```
IDLE
 └─ user picks files/URL ──▶ BROWSING  (BLE advert on, mDNS browse on the AWDL interface)
BROWSING
 ├─ SRV+AAAA resolved ─────▶ DISCOVERING(peer)  (TLS #1, POST /Discover)
 └─ user cancels ──────────▶ IDLE
DISCOVERING(peer)
 ├─ 200 + ReceiverComputerName ─▶ LISTED(peer)   (close TLS #1)
 └─ otherwise ──────────────────▶ BROWSING       (peer hidden, close TLS #1)
LISTED(peer)
 └─ user picks peer ───────▶ ASKING  (TLS #2, POST /Ask)
ASKING
 ├─ 200, link share ───────▶ DONE
 ├─ 200, file share ───────▶ UPLOADING  (POST /Upload on TLS #2)
 └─ non-200 / timeout ─────▶ DECLINED
UPLOADING
 ├─ 200 ───────────────────▶ DONE
 └─ error ─────────────────▶ FAILED
```

### 8.2 Receiver (per TLS connection, HTTP-7)

```
CONNECTED
 ├─ /Discover ─▶ (Everyone, or record matches?)
 │                ├ yes ─▶ DISCOVERED (StatusCode 100/200 + name)
 │                └ no ──▶ DISCOVERED (StatusCode 401, no name)
 └─ /Ask ──────▶ PROMPTING
DISCOVERED
 ├─ /Discover ─▶ reject (at most once per connection)
 └─ /Ask ──────▶ PROMPTING
PROMPTING  (request held open; pipelined /Upload body buffered, not processed)
 ├─ accept ────────────▶ ACCEPTED (200)
 └─ decline / 15 s ────▶ CLOSED (non-200, buffered upload discarded)
ACCEPTED
 ├─ link share ─▶ CLOSED (offer URL to the user)
 └─ /Upload ────▶ RECEIVING ─ ok ─▶ CLOSED (200)
                            └ bad entry/IO ─▶ CLOSED (error, partial files removed)
any state
 ├─ /Upload without ACCEPTED on this connection ─▶ reject (UP-6)
 └─ unknown path ─▶ 400 (HTTP-5)
```

## 9. Security considerations

A receiver is reachable by anyone in radio range, before any authentication, so every input it gets is hostile until checked.

**SEC-1** (receiver) Extraction MUST reject absolute paths, `..` components, symlinks, hard links and device nodes, and MUST confine every write to a fresh staging directory. Files move to their destination only after the upload completes. Names MUST NOT contain control characters or bidi embeddings, overrides or isolates (U+202A–U+202E, U+2066–U+2069), which can make a name display as another. Names the host's file system would treat specially or change MUST be refused too: on Windows, for example, `:` (drive-relative paths and alternate data streams), `<>"|?*`, the device names (`CON`, `NUL`, `COM1`…) and a trailing dot or space.

**SEC-2** (receiver) Name collisions MUST NOT overwrite existing files. Suffix the name instead.

**SEC-3** (receiver) The receiver MUST enforce limits on total uncompressed size, entry count, HTTP body size and plist size. The plist limit MUST cover what a plist decodes to as well as its encoded size, since shared references let a small plist reference one large object many times. A gzip or DVZip bomb MUST fail cleanly.

**SEC-4** (receiver) Senders control `SenderComputerName`, `FileName` and the `Items` URLs. They MUST be escaped when shown in the prompt, and URLs MUST NOT be opened without user action.

**SEC-5** The 2-byte BLE hashes and the full SHA-256 contact hashes in records can be brute-forced to recover phone numbers and email addresses. Implementations MUST NOT log them alongside identifying context.

**SEC-6** (receiver) Plist parsing MUST accept only `bplist00` and MUST cap nesting depth (64; AirDrop messages nest at most 4 deep).

**SEC-7** (receiver) HTTP framing MUST be strict, per RFC 9112: reject conflicting or duplicate `Content-Length`, `Content-Length` together with chunked encoding, negative or non-hex chunk sizes, and oversized headers.

**SEC-8** (receiver) Every error path MUST return an HTTP error and keep the server running. Unknown paths, wrong state, and malformed bodies MUST never abort the process.

**SEC-9** *withdrawn*

**SEC-10** (all) A peer that stops making progress MUST NOT hold resources for good. A receiver MUST bound the connections it holds from one address, MUST end an upload that stalls or trickles, and SHOULD, when it holds as many connections as it takes, close the one that has gone longest without completing a request, but never one with an `/Ask` open. A sender MUST fail a transfer whose receiver stops reading.

**SEC-11** (all) Tables filled from what peers send, such as the AWDL peer table and the mDNS cache, MUST be bounded, and an entry its peer stops refreshing MUST age out within minutes, whatever lifetime it claims. A full AWDL peer table SHOULD make room for a new peer by dropping the one heard from longest ago, so spoofed peers can't keep a real one out.

## 10. References

- RFC 2119: Key words for use in RFCs to indicate requirement levels.
- RFC 1950: ZLIB compressed data format. RFC 1951: DEFLATE. RFC 1952: GZIP file format.
- RFC 4291: IP version 6 addressing architecture (modified EUI-64 interface identifiers).
- RFC 5246: TLS 1.2. RFC 8446: TLS 1.3.
- RFC 5652: Cryptographic Message Syntax (CMS).
- RFC 6762: Multicast DNS. RFC 6763: DNS-based service discovery.
- RFC 9110: HTTP semantics. RFC 9112: HTTP/1.1.
- IEEE Std 802.11: wireless LAN medium access control and physical layer.
- Bluetooth Core Specification: LE advertising.
- IEEE Std 1003.1 (POSIX): the `cpio` interchange format (odc).
- Apple, binary property list format (`bplist00`), as implemented by Core Foundation's `CFBinaryPList`.
- Apple, Uniform Type Identifiers.
- Apple Platform Security Guide, "AirDrop security".
