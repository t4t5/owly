# Conformance tests

The tests Owly runs against [the spec](SPEC.md). Each one cites the requirements it covers, and `cargo xtask coverage` (part of `just ci`) checks that every in-scope MUST in `tests/coverage.toml` has a test citing it, directly or through a `T-*` ID below. A test cites what it checks with a comment such as `// spec: T-DISC-1` or `// spec: ASK-7, HTTP-3`.

Layers 3–7 can be tested without a radio, by running sender and receiver on the two ends of a veth pair in a user network namespace (`crates/owly-airdrop/tests/harness`). Unlike the loopback interface, that gives them link-local addresses, multicast for mDNS and `%iface` scoping (NET-2). Layers 1–2 need a capture or a phone.

Tests MUST NOT assume an identifier normalization for the BLE and record hashes, since the spec doesn't define one (BLE-4).

**Vectors.** `tests/vectors/airdrop-vectors.json` holds byte-level vectors for normal transfers, in the style of `identity-vectors.json`, and `tests/vectors/gen_airdrop_vectors.py` regenerates it. Every implementation's parsers and encoders SHOULD pass them. They are *reconstructed* from the message shapes the spec describes, not captured from Apple devices. Real captures from a Mac → iPhone transfer SHOULD be added when available, marked `"source": "capture"`.

| ID | Covers | Given / When / Then |
|---|---|---|
| T-MDNS-1 | MDNS-1, MDNS-5 | Given a running receiver, when browsing `_airdrop._tcp` on its interface, then exactly one instance with a 12-hex-digit name, an AAAA link-local address and a TXT `flags` with bit `0x04` or `0x08` set is found. Bit `0x02` is clear unless DVZip is implemented. |
| T-MDNS-2 | MDNS-7 | Given a receiver on a link whose radio asks for a burst of 3 copies 50 ms apart with a 3 s pause, when it stays visible for 7 s, then a listener on the link hears 3 announcements per burst, at least 3 bursts, and no fewer after the first. |
| T-DISC-1 | DISC-1, HTTP-3 | Given an Everyone-mode receiver, when `/Discover` is posted with `{}`, then the response is `200` with a bplist containing `ReceiverComputerName` and `StatusCode` `100`. |
| T-DISC-2 | DISC-2, ID-3 | Given a Contacts Only receiver with no matching contacts, when `/Discover` is posted with any record, then the response has `StatusCode` `401` and no `ReceiverComputerName`. |
| T-DISC-3 | DISC-3 | `ReceiverMediaCapabilities` decodes as UTF-8 JSON with integer `Version`. |
| T-DISC-4 | HTTP-2a, HTTP-3 | Every `discover` vector is accepted, with both chunked and `Content-Length` framing. |
| T-CONN-1 | HTTP-1, HTTP-7 | `/Discover` on connection A, then `/Ask` + `/Upload` on connection B, succeeds. `/Discover` then `/Ask` + `/Upload` on one connection also succeeds. |
| T-CONN-2 | HTTP-7 | A second `/Discover` on the same connection is rejected. |
| T-ASK-1 | ASK-1, ASK-3 | Given a receiver set to prompt, when the user declines, then `/Ask` returns non-200 and a following `/Upload` is rejected. |
| T-ASK-2 | ASK-2 | Given a receiver set to prompt, when nobody answers, then `/Ask` returns non-200 after 15 s (±1 s). |
| T-ASK-3 | ASK-4 | Given a link share, when `/Ask` returns 200, then the sender sends no `/Upload` and reports success. |
| T-ASK-4 | §6.4 | The receiver parses every `ask` vector, current and legacy forms, to the `expect` fields. |
| T-ASK-5 | ASK-7 | The sender's `/Ask` for a given file decodes to the current form: `TransferID` and `TransferType` dicts, `FileSize`, `./` `FileBomPath`, `ShouldConvertMediaFormats`, `Items: []`. |
| T-ASK-6 | ASK-2a | Given a receiver that never answers `/Ask`, the sender reports "declined" after its timeout, which is longer than 15 s. |
| T-UP-1 | UP-1, UP-1a, UP-2, UP-5 | Given an accepted `/Ask`, every `upload` vector extracts to its `expect` files, byte-identical, with response `200`. The vectors cover DVZip and gzip, `Content-Length` and chunked, odc with and without the `.` root entry, and `newc`. |
| T-UP-2 | UP-3 | When `/Upload` carries `Expect: 100-continue`, then `100 Continue` is sent before the body is read. |
| T-UP-3 | UP-4 | A content type other than `application/x-dvzip` or `application/x-cpio` → `406`. |
| T-UP-4 | UP-6 | `/Upload` with no prior accepted `/Ask`, or with the `/Ask` on a different connection → rejected, nothing written. |
| T-UP-5 | UP-8 | A pipelined `/Upload` sent before a declined `/Ask` is discarded and nothing is written. |
| T-UP-6 | UP-2, UP-2a | The sender's archive for each odc `cpio` vector's files decodes to the same entries, in the same order, with the same names, modes and data. |
| T-UP-7 | UP-9 | An `/Upload` whose `TransferID` header doesn't match its current-form `/Ask` → rejected, nothing written. A legacy `/Ask` followed by an `/Upload` with no `TransferID` header → accepted. |
| T-DVZ-1 | DVZ-1, DVZ-2 | Every `dvzip` vector decodes to its `expect` output (length and SHA-256). Encoding that output gives the same number of chunks and decodes back to it. Compressed bytes aren't compared, since zlib versions differ. |
| T-DVZ-2 | DVZ-1, DVZ-3 | A stream mixing zlib and stored chunks, as an iPhone sends a photo, decodes to the archive, fed whole or a byte at a time. A stored chunk past the limit, empty, or cut short is rejected. |
| T-HTTP-1 | HTTP-5, SEC-8 | `POST /X` with a 1-byte body → `400`, and the server keeps serving. |
| T-SEC-1 | SEC-1, UP-7 | Archives containing `../x`, `/etc/x`, a symlink or an entry not in `/Ask` → rejected, staging directory removed, destination untouched. |
| T-SEC-2 | SEC-3 | A 10 MB gzip expanding past the limit → rejected without filling the disk. |
| T-SEC-3 | SEC-6 | An XML plist, and a bplist nested 200 levels deep, posted to `/Discover` → rejected with an HTTP error, server keeps serving. |
| T-SEC-4 | SEC-7 | Duplicate conflicting `Content-Length`, chunk size `-1`, and `Content-Length` far past the body each → `400`, server keeps serving. |
| T-AWDL-1 | AWDL-3, AWDL-4, AWDL-5 | A parser fed captured iPhone PSFs and MIFs (including zero-padded ones) yields all TLVs without error. |
| T-AWDL-2 | AWDL-13 | A built data frame for a given IPv6 packet matches the golden bytes. |
| T-AWDL-3 | AWDL-7, AWDL-17 | Replaying a capture of a session (`tests/captures/`), a passive node finds the capture's peers valid, follows its master, and keeps within 3 TU of the master's schedule. |
| T-AWDL-4 | MDNS-2 | Given a node whose host announces a receiver, its MIFs end with a Service Response TLV for each of the PTR, SRV and TXT records, every action frame's Service Parameters carry the SUI and the names' values, and the ARPA TLV names the SRV's target. Announced again, the SUI stays; withdrawn, or not announced for 15 s, the records go and the SUI changes. The TLVs match the golden bytes. |
| T-INTEROP-1 | all | iPhone → Linux photo, Linux → iPhone photo, Linux → iPhone link, each in Everyone mode. |
