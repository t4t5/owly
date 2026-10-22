#!/usr/bin/env python3
"""Send files over AirDrop from awdl0 to a Mac (the f0010 -> hume direction).

Browse `_airdrop._tcp` on awdl0, pick the receiver named by --to (substring of
its Discover name or its 12-hex service id; first discoverable one if absent),
then /Discover on one TLS connection and /Ask -> /Upload on a fresh one.
Several files go as one transfer: one /Ask listing them all, so the receiver
answers a single prompt, and one /Upload archive holding them all.
The Mac must be receiving (Finder > AirDrop open, or woken by BLE); it answers
/Discover only in that state, and /Ask blocks until its user accepts.

The peer must already be registered in our firmware (awdl-peer-watch.py does
it on the Mac's first frame) or every unicast we send is tossed (0x0003).

Exit: 0 sent | 2 no receiver found in --timeout | 3 declined | 4 upload failed.
Every step is timestamped to stdout so it lines up with the hold's intervals.
"""
import argparse
import io
import ipaddress
import logging
import os
import plistlib
import socket
import ssl
import sys
import threading
import time
import uuid
from http.client import HTTPSConnection

from awdl_debug import dump_protocol
from awdl_identity import IdentityError, resolve_identity

# Protocol-level lines (each request and its status, the identity in use), on
# their own logger so the `send` lines callers parse stay the only ones there.
wire = logging.getLogger('airdrop')

# Bit 0x80 of a receiver's `flags` TXT value: it answers /Discover.
SUPPORTS_DISCOVER = 0x80

# Every AWDL HTTPS connection (Discover, Ask, Upload) is built through the
# subclass below, so this is the one place a default operation timeout belongs.
# It is NOT socket.setdefaulttimeout(): that would also arm zeroconf's browser
# sockets. Reassigned from --op-timeout before any connection is opened.
#
# 021922Z: our third-leg ACK and TLS Client Hello were emitted and lost, hume
# retransmitted SYN-ACK 13 times, and TCP backed off to rto:120000 (backoff:8).
# With timeout None the client sat in that backoff for 4.5 minutes -- past the
# end of a watched hold -- instead of failing and reporting. A wedged send must
# cost seconds, not a hold.
OP_TIMEOUT = 20.0

class HTTPSConnectionAWDL(HTTPSConnection):
    """HTTPS to a peer on the AWDL interface.

    A link-local address is ambiguous without a zone, so the interface is
    appended (fe80::1 -> fe80::1%awdl0); getaddrinfo turns that into the scope
    id that sends the connection out of awdl0 and nowhere else."""
    def __init__(self, host, port, *, context, interface_name, timeout=None):
        # A zone index only means something for link-local; "::1%lo" does not resolve.
        if interface_name is not None and '%' not in host:
            ip = ipaddress.ip_address(host)
            if isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local:
                host = host + '%' + interface_name
        if timeout is None:
            timeout = OP_TIMEOUT if OP_TIMEOUT else socket.getdefaulttimeout()
        super().__init__(host, port, timeout=timeout, context=context)


class Config:
    """Who we are to a receiver, and the TLS identity that says so.

    The shared resolver selects one certificate and its matching record from
    the active window, disk identity, or separate self-signed pair."""
    def __init__(self, keys, computer_name, computer_model, service_id, interface):
        self.computer_name = computer_name
        self.computer_model = computer_model
        self.service_id = service_id
        self.interface = interface
        self.debug_verbose = False
        self.identity = resolve_identity(keys=keys, computer_name=computer_name)
        self.record_data = self.identity.record_data
        if self.record_data is not None:
            wire.debug('Apple ID validation record found (%d B)', len(self.record_data))
        else:
            wire.debug('no Apple ID validation record; sending without one')


    def get_ssl_context(self):
        """A fresh client context per connection: present our certificate,
        verify nothing about the peer's. An Everyone-mode peer's certificate is
        self-signed, and nothing here acts on who signed it. TLS 1.0 stays
        refused (Python's own floor is already 1.2).

        Apple's root CA is deliberately not loaded. It could only matter to
        verification, which is off, or to the chain OpenSSL builds for our own
        certificate -- and an Apple ID leaf is issued by an intermediate that
        is not in the store, so the leaf goes on its own either way (measured
        2026-09-25 with this machine's Apple ID certificate: the same
        one-certificate chain with and without the root loaded)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = max(ctx.minimum_version, ssl.TLSVersion.TLSv1_1)
        try:
            self.identity.load_cert_chain(ctx)
        except IdentityError as e:
            raise SystemExit(f'identity error: {e}') from None
        return ctx

    def dump(self, name, data):
        """Write explicitly requested protocol diagnostics without identity data."""
        try:
            dump_protocol(name, data, verbose=self.debug_verbose)
        except (OSError, ValueError) as exc:
            wire.warning('protocol dump skipped: %s', exc)


def interface_ipv6(name):
    """The first IPv6 address on an interface, or None."""
    import ifaddr
    for adapter in ifaddr.get_adapters():
        if adapter.name == name:
            for ip in adapter.ips:
                if ip.is_IPv6:
                    return ipaddress.IPv6Address(ip.ip[0])
    return None


class AirDropBrowser:
    """Browse `_airdrop._tcp` over IPv6 on one interface.

    Each instance that appears is resolved (SRV, TXT, addresses) and handed to
    the callback on zeroconf's browser thread; the callback gets None when the
    resolution times out. Removals and updates are ignored: nothing here acts
    on them."""
    def __init__(self, config):
        from zeroconf import IPVersion, Zeroconf
        self.ip_addr = interface_ipv6(config.interface)
        if self.ip_addr is None:
            raise RuntimeError(f'Interface {config.interface} does not have an IPv6 address')
        self.zeroconf = Zeroconf(interfaces=[str(self.ip_addr)], ip_version=IPVersion.V6Only)
        self.browser = None

    def start(self, callback_add):
        from zeroconf import ServiceBrowser, ServiceStateChange

        def changed(zeroconf, service_type, name, state_change):
            if state_change is ServiceStateChange.Added:
                wire.debug('mDNS: %s appeared', name)
                callback_add(zeroconf.get_service_info(service_type, name))

        self.browser = ServiceBrowser(self.zeroconf, '_airdrop._tcp.local.', handlers=[changed])

    def stop(self):
        self.browser.cancel()
        self.zeroconf.close()




ap = argparse.ArgumentParser()
# Optional, because --discover-only asks a peer for its name and sends nothing.
ap.add_argument('files', nargs='*', metavar='file',
                help='files to send, as one transfer the receiver accepts once')
# A web link travels in the Ask itself, the way Safari on an iPhone sends one
# to a receiver that advertises SUPPORTS_URL (2026-09-12): TransferType
# `links`, the URL in Items, no Files and no /Upload. Sent as a .webloc file
# instead, a Mac saves it to Downloads, where it opens as text (2026-10-10).
ap.add_argument('--url', action='append', default=[], metavar='URL',
                help='send this http(s) link instead of files; the receiver opens it in its browser')
ap.add_argument('--iface', default='awdl0')
ap.add_argument('--discover-only', action='store_true',
                help='ask the peer for its name over /Discover, print it, and send nothing')
ap.add_argument('--to', default=None, help='receiver: substring of its name, or 12-hex id')
ap.add_argument('--timeout', type=float, default=60, help='seconds to wait for a receiver')
ap.add_argument('--ask-timeout', type=float, default=90, help='seconds for the Mac user to accept')
ap.add_argument('--op-timeout', type=float, default=20,
                help='seconds any single Discover/Upload socket operation may block; '
                     'guards against a wedged AWDL TX path parking the client in TCP backoff')
ap.add_argument('--af-attempts', type=int, default=1, metavar='N',
                help='independent Discover attempts against the freshest matching af.log '
                     'endpoint, re-read before each; stops on the first success. Total time '
                     'is bounded by N*(op-timeout+2)')
ap.add_argument('--auth-tag', default=None, help='3 bytes hex: SenderIdentityAuthTag for the Ask (the bytes our BLE advert carries)')
ap.add_argument('--should-convert', action='store_true',
                help="set Files[].ShouldConvertMediaFormats (a real sender's key; off = one variable held)")
ap.add_argument('--direct', default=None, metavar='HOST:PORT',
                help='skip discovery; Discover/Ask/Upload this endpoint (e.g. "[::1]:8771" against a local airdrop-serve)')
ap.add_argument('--af-log', default=None,
                help='awdl-af-listen output; take the receiver from the newest AirDrop Service Response '
                     'TLVs in it (address = EUI-64 link-local of the frame source) before browsing mDNS')
ap.add_argument('--name', default='f0010', help='SenderComputerName shown in the Mac dialog')
ap.add_argument('--model', default='MacBookPro18,3', help='SenderModelName')
# The sender advertises nothing, so it has no use for a host label; kept so
# existing command lines keep working.
ap.add_argument('--host', default='f0010-awdl', help='unused by the sender')
ap.add_argument('--verbose', action='store_true',
                help='write redacted protocol dumps to the user runtime directory')
ap.add_argument('--keys', default=None,
                help="identity directory (default: invoking user's passwd home/.omdrop); "
                     'replaces the disk and self-signed keys location only')
args = ap.parse_args()
OP_TIMEOUT = args.op_timeout
if not args.discover_only and not args.files and not args.url:
    ap.error('a file or --url is required unless --discover-only')
if args.url and args.files:
    ap.error('send links and files separately: a transfer carries one or the other')
for u in args.url:
    if not u.lower().startswith(('http://', 'https://')) or any(c.isspace() for c in u):
        ap.error(f'--url {u!r}: only an http or https link with no spaces')
# The archive stores each file as "./<basename>", as sharingd does, so two
# files with one name would land as one, and which survived would be luck.
names = [os.path.basename(f) for f in args.files]
if len(set(names)) != len(names):
    ap.error('two of the files have the same name; the receiver would keep only one')
if args.discover_only and not args.direct:
    ap.error('--discover-only needs --direct HOST:PORT, the peer to ask')
# A name lookup is not a transfer: keep the debug stream off stdout so the
# caller can read the name without parsing a log.
if args.discover_only:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout,
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logging.getLogger('zeroconf').setLevel(logging.INFO)
log = logging.getLogger('send')

with open(f'/sys/class/net/{args.iface}/address') as f:
    sid = f.read().strip().replace(':', '')

try:
    config = Config(args.keys, computer_name=args.name, computer_model=args.model,
                    service_id=sid, interface=args.iface)
except IdentityError as e:
    raise SystemExit(f'identity error: {e}') from None
config.debug_verbose = args.verbose

T0 = time.monotonic()
def t():
    return f'+{time.monotonic() - T0:6.2f}s'


# What every request carries, in this order; a request's own headers replace
# a value in place (Content-Type) or follow these.
HEADERS = {
    'Content-Type': 'application/octet-stream',
    'Connection': 'keep-alive',
    'Accept': '*/*',
    'User-Agent': 'AirDrop/1.0',
    'Accept-Language': 'en-us',
    'Accept-Encoding': 'br, gzip, deflate',
}


def dvzip_encode(data, block=1 << 16):
    """Inverse of airdrop-serve.py's dvzip_decode: 4-byte big-endian header per
    block, low 31 bits = payload length, high bit = stored. A block is stored
    when zlib does not shrink it (sharingd does this for incompressible media:
    215526Z, a 22 MB video was 20 zlib blocks then 151 stored ones)."""
    import zlib
    out = bytearray()
    for i in range(0, len(data), block):
        raw = data[i:i + block]
        z = zlib.compress(raw, 6)
        if len(z) < len(raw):
            out += len(z).to_bytes(4, 'big') + z
        else:
            out += (0x80000000 | len(raw)).to_bytes(4, 'big') + raw
    return bytes(out)


class AirDropClient:
    """One receiver: /Discover, /Ask and /Upload, each a POST on http_conn,
    which is opened on first use and kept until someone replaces it."""
    def __init__(self, config, receiver):
        self.config = config
        self.receiver_host, self.receiver_port = receiver
        self.http_conn = None
        self.transfer_id = None

    def post(self, path, body, headers=None):
        """POST and read the whole answer: (status is 200, response body).

        Bytes go with a Content-Length; a file-like body makes http.client send
        it chunked, as sharingd sends /Upload. Debug dumps are opt-in."""
        name = path.strip('/').lower()
        self.config.dump(f'send_{name}_request.plist', body)
        wire.debug('POST %s', path)
        if self.http_conn is None:
            self.http_conn = HTTPSConnectionAWDL(self.receiver_host, self.receiver_port,
                                                 interface_name=self.config.interface,
                                                 context=self.config.get_ssl_context())
        self.http_conn.request('POST', path, body=body, headers={**HEADERS, **(headers or {})})
        resp = self.http_conn.getresponse()
        data = resp.read()
        self.config.dump(f'send_{name}_response.plist', data)
        wire.debug('%s answered %d %s', path, resp.status, resp.reason)
        return resp.status == 200, data

    def send_discover(self):
        """A Mac's /Discover request carries DeviceSupportFlags (and its record
        data); a legacy sender sends an empty plist. 22:13Z: an Apple-shaped Ask after an
        empty Discover still produced no UI on an iPhone."""
        body = {'DeviceSupportFlags': 111611}
        if self.config.record_data:
            body['SenderRecordData'] = self.config.record_data
        _, resp = self.post('/Discover', plistlib.dumps(body, fmt=plistlib.FMT_BINARY))
        pl = plistlib.loads(resp)
        log.info('%s DISCOVER response keys: %s', t(), sorted(pl))
        return pl.get('ReceiverComputerName')

    def send_ask(self, files):
        """The legacy /Ask form predates today's sharingd. A Mac's Ask (captured by
        our receiver, 2026-09-07) carries TransferID, TransferType, Items, per-file
        FileSize, a UTI such as public.jpeg, and a ~25 KB icon; an iPhone answered
        the legacy form with 200 Discover and then showed no UI for the Ask."""
        from PIL import Image
        uti = {'.jpg': 'public.jpeg', '.jpeg': 'public.jpeg', '.png': 'public.png', '.heic': 'public.heic',
               '.mov': 'com.apple.quicktime-movie', '.mp4': 'public.mpeg-4', '.pdf': 'com.adobe.pdf',
               '.txt': 'public.plain-text'}
        entries = []
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            entries.append({
                'FileName': os.path.basename(f),
                'FileType': uti.get(ext, 'public.data'),
                'FileSize': os.path.getsize(f),
                'FileBomPath': os.path.join('.', os.path.basename(f)),
                'FileIsDirectory': False,
                'ConvertMediaFormats': False,
            })
        # One TransferID for Ask and Upload: sharingd sends the same UUID in the Ask
        # body and the Upload's TransferID header (hume, 093540Z), and our receiver
        # files the upload under it.
        self.transfer_id = str(uuid.uuid4()).upper()
        if args.should_convert:
            for e in entries:
                e['ShouldConvertMediaFormats'] = False
        body = {
            'TransferID': {'id': self.transfer_id},
            'TransferType': {'files': {}},
            'SenderID': self.config.service_id,
            'BundleID': 'com.apple.finder',
            'SenderComputerName': self.config.computer_name,
            'SenderModelName': self.config.computer_model,
            'Items': [],
            'Files': entries,
            'ConvertMediaFormats': False,
        }
        if self.config.record_data:
            body['SenderRecordData'] = self.config.record_data
        # 09-08: hume's own Ask carries a 3-byte SenderIdentityAuthTag and its log
        # binds the HTTP sender to a BLE presence ("set the auth tag") right before
        # HELLO/ASK. First guess for the binding: the 3 bytes after 0x40 in the
        # sender's BLE AirDrop advert (ble-airdrop-adv.py --tag). --auth-tag sets it.
        if args.auth_tag:
            body['SenderIdentityAuthTag'] = bytes.fromhex(args.auth_tag)
        try:
            im = Image.open(files[0]); im.thumbnail((240, 240)); buf = io.BytesIO()
            im.convert('RGB').save(buf, 'JPEG', quality=80); body['FileIcon'] = buf.getvalue()
        except Exception:
            pass
        ok, resp = self.post('/Ask', plistlib.dumps(body, fmt=plistlib.FMT_BINARY))
        log.info('%s ASK response %d B: %s', t(), len(resp), resp[:120])
        return ok

    def send_ask_links(self, urls):
        """A links transfer: the Ask is the whole transfer. Shaped like the
        iPhone's (2026-09-12, 2026-09-24): TransferType `links`, the URLs in
        Items, and no Files, so nothing follows on /Upload."""
        self.transfer_id = str(uuid.uuid4()).upper()
        body = {
            'TransferID': {'id': self.transfer_id},
            'TransferType': {'links': {}},
            'SenderID': self.config.service_id,
            'BundleID': 'com.apple.Safari',
            'SenderComputerName': self.config.computer_name,
            'SenderModelName': self.config.computer_model,
            'Items': list(urls),
            'ConvertMediaFormats': False,
        }
        if self.config.record_data:
            body['SenderRecordData'] = self.config.record_data
        if args.auth_tag:
            body['SenderIdentityAuthTag'] = bytes.fromhex(args.auth_tag)
        ok, resp = self.post('/Ask', plistlib.dumps(body, fmt=plistlib.FMT_BINARY))
        log.info('%s ASK response %d B: %s', t(), len(resp), resp[:120])
        return ok

    def send_upload(self, files):
        """sharingd's Upload, as our receiver saw hume's (093540Z):
             Content-Type: application/x-dvzip   TotalBytes: <sum of file sizes>
             TransferID: <the Ask's UUID>        Transfer-Encoding: chunked
        body = DVZip-framed cpio archive of the files. A legacy sender's is
        application/x-cpio + gzip, which sharingd rejects (406 seen 09-07 the other
        way round). Same TLS connection as the Ask (post reuses http_conn)."""
        import libarchive
        stream = io.BytesIO()
        cwd = os.getcwd()
        with libarchive.custom_writer(stream.write, 'cpio') as archive:
            for f in files:
                # Store as "./<basename>", as sharingd does, whatever the source path.
                d, b = os.path.split(os.path.abspath(f))
                os.chdir(d)
                try:
                    archive.add_files(b)
                finally:
                    os.chdir(cwd)
        body = dvzip_encode(stream.getvalue())
        headers = {
            'Content-Type': 'application/x-dvzip',
            'TotalBytes': str(sum(os.path.getsize(f) for f in files)),
            'TransferID': self.transfer_id or str(uuid.uuid4()).upper(),
        }
        log.info('%s UPLOAD %d B dvzip (%d B cpio) TransferID %s', t(), len(body), stream.getbuffer().nbytes, headers['TransferID'])
        ok, _ = self.post('/Upload', io.BytesIO(body), headers=headers)
        return ok


found = threading.Event()
chosen = {}
lock = threading.Lock()


def on_add(info):
    """zeroconf found a `_airdrop._tcp` instance; Discover it in this thread."""
    if info is None or found.is_set():
        return
    ident = info.name.split('.')[0]
    addrs = info.parsed_addresses()
    props = {k.decode(): v.decode(errors='replace') for k, v in (info.properties or {}).items() if v is not None}
    log.info('%s advert %s host=%s port=%s addr=%s flags=%s', t(), ident, info.server, info.port,
             addrs, props.get('flags'))
    if not addrs:
        return
    if args.to and len(args.to) == 12 and args.to.lower() != ident.lower():
        return
    # --to as a MAC: only that device (000827Z: the browse Discovered f0011 while
    # the target was hume). Its AWDL link-local is the EUI-64 of the MAC.
    if args.to and ':' in args.to and ipaddress.IPv6Address(eui64_linklocal(args.to)) not in [ipaddress.IPv6Address(a.split('%')[0]) for a in addrs]:
        log.info('%s %s at %s is not --to %s; skipping', t(), ident, addrs, args.to)
        return
    flags = int(props.get('flags', SUPPORTS_DISCOVER))
    if not flags & SUPPORTS_DISCOVER:
        log.info('%s %s: no /Discover support (flags %#x); skipping', t(), ident, flags)
        return
    client = AirDropClient(config, (addrs[0], int(info.port)))
    try:
        t1 = time.monotonic()
        name = client.send_discover()
        log.info('%s DISCOVER %s -> %r (%.2fs)', t(), ident, name, time.monotonic() - t1)
    except Exception as e:  # timeouts, resets, TLS: all mean "not this one, not now"
        log.info('%s DISCOVER %s failed: %r', t(), ident, e)
        return
    if name is None:
        return
    if args.to and len(args.to) != 12 and args.to.lower() not in name.lower():
        log.info('%s %s is %r, not --to %r; skipping', t(), ident, name, args.to)
        return
    with lock:
        if found.is_set():
            return
        chosen.update(ident=ident, name=name, client=client, addr=addrs[0], port=int(info.port))
        found.set()


def eui64_linklocal(mac):
    b = bytes(int(x, 16) for x in mac.split(':'))
    b = bytes([b[0] ^ 0x02]) + b[1:3] + b'\xff\xfe' + b[3:]
    return 'fe80::' + ':'.join(f'{b[i] << 8 | b[i + 1]:x}' for i in range(0, 8, 2))


def endpoints_from_af_log(path):
    """Newest AirDrop endpoint per source MAC from awdl-af-listen output."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import importlib
    afp = importlib.import_module('awdl-af-parse')
    eps = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                rec = afp.parse_body(bytes.fromhex(parts[3]))
            except ValueError:
                continue
            ep = afp.airdrop_endpoint(rec) if rec else None
            if ep and ep['port']:
                eps[parts[2]] = dict(ep, ts=float(parts[0]), sa=parts[2])
    return sorted(eps.values(), key=lambda e: -e['ts'])


if args.direct:
    # Offline / loopback test path: no discovery, the endpoint is given.
    host, _, port = args.direct.rpartition(':')
    host = host.strip('[]')
    client = AirDropClient(config, (host, int(port)))
    try:
        t1 = time.monotonic()
        name = client.send_discover()
        log.info('%s DISCOVER %s -> %r (%.2fs)', t(), args.direct, name, time.monotonic() - t1)
    except Exception as e:
        log.info('%s DISCOVER %s failed: %r', t(), args.direct, e)
        # --discover-only silences the debug stream, so without this the
        # failure is invisible: no name, no reason, exit 2.
        if args.discover_only:
            print(f'{args.direct}: no answer ({type(e).__name__})', file=sys.stderr)
        sys.exit(2)
    if args.discover_only:
        # A peer that answers without naming itself is not an error: an iPhone
        # answers /Discover with no ReceiverComputerName unless it recognizes
        # the sender. Print nothing and exit 0, so the caller distinguishes
        # "no name offered" from "peer did not answer" (exit 2 above).
        if name:
            print(name)
        sys.exit(0)
    chosen.update(ident='direct', name=name, client=client, addr=host, port=int(port))
    found.set()

if not found.is_set() and args.af_log and os.path.exists(args.af_log):
    def freshest_af_endpoint():
        """Newest af.log endpoint matching --to, re-read before EVERY attempt so a
        rotated service id, port or host between tries is picked up rather than a
        stale one retried. --to may be a 12-hex service id (rotates per session on
        iOS), a MAC (stable for the AWDL session), or a name substring (checked
        after Discover)."""
        for ep in endpoints_from_af_log(args.af_log):
            if args.to and len(args.to) == 12 and args.to.lower() != ep['id'].lower():
                continue
            if args.to and ':' in args.to and args.to.lower() != ep['sa'].lower():
                continue
            return ep
        return None

    # 033602Z: one Discover attempt sent 9 SYNs over 20 s and drew zero SYN-ACKs,
    # while 021922Z's SYN did arrive -- the TX loss is probabilistic, so a single
    # attempt per hold measures nothing. N independent attempts turn it into a
    # rate. Bounded overall so a run can never outlive its hold.
    attempts = max(1, args.af_attempts)
    deadline = time.monotonic() + attempts * (args.op_timeout + 2)
    tried = 0
    for attempt in range(1, attempts + 1):
        if time.monotonic() >= deadline:
            log.info('%s AF attempts: time budget spent after %d/%d', t(), tried, attempts)
            break
        ep = freshest_af_endpoint()
        if ep is None:
            log.info('%s AF attempt %d/%d: no matching endpoint in %s', t(), attempt, attempts, args.af_log)
            break
        tried = attempt
        addr = eui64_linklocal(ep['sa'])
        log.info('%s AF attempt %d/%d endpoint %s from %s: [%s]:%d host=%s txt=%s (%.0fs old)',
                 t(), attempt, attempts, ep['id'], ep['sa'], addr, ep['port'], ep['host'], ep['txt'],
                 time.time() - ep['ts'])
        client = AirDropClient(config, (addr, ep['port']))
        t1 = time.monotonic()
        try:
            name = client.send_discover()
            log.info('%s AF attempt %d/%d DISCOVER %s -> %r (%.2fs)', t(), attempt, attempts,
                     ep['id'], name, time.monotonic() - t1)
        except Exception as e:
            log.info('%s AF attempt %d/%d DISCOVER %s failed: %r (%.2fs)', t(), attempt, attempts,
                     ep['id'], e, time.monotonic() - t1)
            continue
        if name is None or (args.to and len(args.to) != 12 and ':' not in args.to and args.to.lower() not in name.lower()):
            continue
        chosen.update(ident=ep['id'], name=name, client=client, addr=addr, port=ep['port'])
        found.set()
        break
    if not found.is_set():
        log.info('%s no usable AirDrop endpoint in %s after %d attempt(s); browsing mDNS',
                 t(), args.af_log, tried)

if not found.is_set():
    browser = AirDropBrowser(config)
    log.info('%s browsing _airdrop._tcp on %s from %s as %s (%s)', t(), args.iface, browser.ip_addr, sid, args.name)
    browser.start(callback_add=on_add)
    found.wait(args.timeout)
    browser.stop()
if not found.is_set():
    log.info('%s no receiver found in %.0fs', t(), args.timeout)
    sys.exit(2)

client = chosen['client']
log.info('%s FOUND %s %r at [%s]:%d; asking', t(), chosen['ident'], chosen['name'], chosen['addr'], chosen['port'])
# BEGIN ask-connection
# sharingd tears the /Discover handler down ~1 ms after answering it (hume's
# log, 09-09 04:37:41.059Z: "Tearing down handler for server" / "Removed
# handler for discovery bonjour connection"). The socket stays open at TCP
# level with nothing above TCP ever reading it again, so requeue-2's Ask was
# ACKed in full -- all 15,127 bytes, Ack=15127 -- and never dispatched, then
# timed out at +91 s. A real sender throws the Discover connection away. Do it
# unconditionally, on every discovery path: the old `if http_conn is None`
# guard only fired for --direct, which was the one path that cleared it, so
# mDNS and AF-endpoint sends silently reused a connection already dismantled.
# The Ask also blocks on the receiver's consent prompt, so it carries the long
# timeout.
if client.http_conn is not None:
    try:
        client.http_conn.close()
    except OSError:
        pass
client.http_conn = HTTPSConnectionAWDL(client.receiver_host, client.receiver_port,
                                       interface_name=config.interface, context=config.get_ssl_context())
client.http_conn.connect()
client.http_conn.sock.settimeout(args.ask_timeout)
# END ask-connection
t1 = time.monotonic()
try:
    ok = client.send_ask_links(args.url) if args.url else client.send_ask(args.files)
except Exception as e:
    log.info('%s ASK failed: %r', t(), e)
    sys.exit(3)
log.info('%s ASK -> %s (%.2fs)', t(), 'accepted' if ok else 'declined', time.monotonic() - t1)
if not ok:
    sys.exit(3)
if args.url:
    # Accepting the Ask is the delivery: the receiver now opens the link.
    what = args.url[0] if len(args.url) == 1 else f'{len(args.url)} links'
    log.info('%s LINK %s -> ok', t(), what)
    sys.exit(0)
t1 = time.monotonic()
size = sum(os.path.getsize(f) for f in args.files)
try:
    ok = client.send_upload(args.files)
except Exception as e:
    log.info('%s UPLOAD failed: %r', t(), e)
    sys.exit(4)
what = names[0] if len(names) == 1 else f'{len(names)} files'
log.info('%s UPLOAD %s -> %s (%d B, %.2fs)', t(), what, 'ok' if ok else 'FAILED', size,
         time.monotonic() - t1)
sys.exit(0 if ok else 4)
