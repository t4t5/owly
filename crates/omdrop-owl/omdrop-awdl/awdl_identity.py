"""Machine identity and tunables shared by the omdrop AWDL helpers.

Nothing here is baked in. The AWDL address, the infrastructure address and the
advertised hostname are properties of the machine this happens to run on, and
the channel knobs are properties of the room it is in: a helper that hardcodes
any of them ships one laptop's configuration to everybody. They are read from
the running system, and overridden per-machine from $OMDROP_CONF.
"""
import os
import base64
import ctypes
import fcntl
import json
from pathlib import Path
import pwd
import re
import resource
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import warnings

CONF = os.environ.get('OMDROP_CONF', '/etc/omdrop')
AWDL_IFACE = os.environ.get('OMDROP_AWDL_IFACE', 'awdl0')

# DNS labels are letters, digits and hyphen. A hostname is user-supplied text
# and goes on air inside an Arpa TLV, so anything else is dropped rather than
# encoded -- a label the peer cannot parse loses the whole service record.
_LABEL_OK = set('abcdefghijklmnopqrstuvwxyz0123456789-')


def knob(name, default):
    """One line of configuration from $OMDROP_CONF/<name>, or `default`."""
    try:
        with open(os.path.join(CONF, name)) as f:
            value = f.read().strip()
    except OSError:
        return default
    return value or default


def switch(name):
    """True when $OMDROP_CONF/<name> exists -- the diagnostic on/off files."""
    return os.path.exists(os.path.join(CONF, name))


def mac_of(iface):
    """The MAC of `iface` as six bytes."""
    with open(f'/sys/class/net/{iface}/address') as f:
        return bytes.fromhex(f.read().strip().replace(':', ''))


def infra_iface():
    """The Wi-Fi interface AWDL shares the radio with.

    Found rather than assumed: the interface is called wlan0 on a stock Arch
    install and wld0 on machines carrying a naming rule, and an AWDL setup that
    only works under one of those names is a setup that works on one laptop.
    Picks the first Broadcom FullMAC wireless netdev; override with
    $OMDROP_INFRA_IFACE or $OMDROP_CONF/infra-iface on a machine with two.
    """
    forced = os.environ.get('OMDROP_INFRA_IFACE') or knob('infra-iface', '')
    if forced:
        return forced
    for name in sorted(os.listdir('/sys/class/net')):
        if name == AWDL_IFACE:
            continue
        base = f'/sys/class/net/{name}'
        if not os.path.isdir(f'{base}/phy80211'):
            continue
        try:
            driver = os.path.basename(os.readlink(f'{base}/device/driver'))
        except OSError:
            continue
        if driver.startswith('brcmfmac'):
            return name
    return ''


def infra_mac():
    """The infrastructure MAC a PSF advertises, or six zero bytes.

    Zeros rather than an exception: the field is one TLV of a frame that is
    still worth sending, and refusing to build the frame at all because the
    STA interface went away mid-window is a worse failure than advertising an
    unset address.
    """
    iface = infra_iface()
    if iface:
        try:
            return mac_of(iface)
        except OSError:
            pass
    return b'\x00' * 6


def awdl_host():
    """The hostname this machine publishes over AWDL, without the .local.

    A Mac resolves the Arpa name out of our PSF and then queries mDNS for it,
    so the announcer, the responder and the PSF template must all agree; they
    agree by all calling this. Distinct from the system hostname because the
    name only ever resolves to an awdl0 link-local address.
    """
    forced = os.environ.get('OMDROP_AWDL_HOST') or knob('awdl-host', '')
    if forced:
        return forced.rstrip('.').removesuffix('.local')
    short = socket.gethostname().split('.')[0].lower()
    label = ''.join(c for c in short if c in _LABEL_OK).strip('-')
    return f'{label}-awdl' if label else 'omdrop-awdl'


class IdentityError(RuntimeError):
    """A named identity-selection or loading failure (never secret material)."""


_FETCH_ID = re.compile(r'[0-9a-f]{32}')
_PAYLOAD_FIELDS = {
    'certificate', 'key', 'record', 'fetch_id',
    'fetched_at', 'period_ends', 'hard_expiry',
}


def parse_settings(text):
    """Parse literal key=value lines; the last occurrence wins."""
    return dict(line.split('=', 1) for line in text.split('\n') if '=' in line)


def parse_window(text):
    fields = parse_settings(text)
    source = fields.get('source')
    if source in ('disk', 'self-signed'):
        return {'source': source}
    if source != '1password':
        return 'unparseable'
    fetch_id = fields.get('fetch_id', '')
    expiry = fields.get('hard_expiry', '')
    if not _FETCH_ID.fullmatch(fetch_id) or not re.fullmatch(r'[0-9]+', expiry):
        return 'unparseable'
    try:
        return {'source': source, 'fetch_id': fetch_id, 'hard_expiry': int(expiry)}
    except ValueError:
        return 'unparseable'


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def parse_payload(payload):
    """Decode the bounded binary frame, returning the frozen vector format."""
    if not isinstance(payload, bytes) or len(payload) > 32767:
        return 'malformed'
    try:
        magic, header, body = payload.split(b'\n', 2)
        if magic != b'OMDROP-IDENTITY 1':
            return 'malformed'
        fields = json.loads(header.decode('utf-8'), object_pairs_hook=_unique_object)
        if not isinstance(fields, dict) or set(fields) != _PAYLOAD_FIELDS:
            return 'malformed'
        if not isinstance(fields['fetch_id'], str) or not _FETCH_ID.fullmatch(fields['fetch_id']):
            return 'malformed'
        for name in ('certificate', 'key', 'record'):
            if type(fields[name]) is not int or not 1 <= fields[name] <= 16384:
                return 'malformed'
        times = [fields[name] for name in ('fetched_at', 'period_ends', 'hard_expiry')]
        if any(type(value) is not int for value in times):
            return 'malformed'
        if not times[0] <= times[1] <= times[2] or times[2] - times[0] > 86400:
            return 'malformed'
        if len(body) != sum(fields[name] for name in ('certificate', 'key', 'record')):
            return 'malformed'
        result = {name: fields[name] for name in
                  ('fetch_id', 'fetched_at', 'period_ends', 'hard_expiry')}
        offset = 0
        for name in ('certificate', 'key', 'record'):
            end = offset + fields[name]
            result[name + '_b64'] = base64.b64encode(body[offset:end]).decode('ascii')
            offset = end
        return result
    except (ValueError, UnicodeError, RecursionError):
        return 'malformed'


def select_identity(settings, window, cache, disk, self_signed, root, now):
    """Select without I/O; error precedence and results follow the contract."""
    notes = []
    if window == 'unparseable':
        return {'error': 'window-unparseable'}
    mode = window['source'] if window is not None else settings.get('identity_source', 'disk')
    if window is not None and mode == '1password':
        if window['hard_expiry'] <= now:
            return {'error': 'window-expired'}
        if cache is None:
            return {'error': 'cache-missing'}
        if cache == 'malformed':
            return {'error': 'cache-malformed'}
        if cache['fetch_id'] != window['fetch_id']:
            return {'error': 'cache-mismatch'}
        if cache['hard_expiry'] <= now:
            return {'error': 'cache-expired'}
        return {'identity': 'cache', 'record': True, 'create': False, 'warnings': []}
    if mode == 'disk':
        both = disk['certificate'] and disk['key']
        if window is not None:
            if not both:
                return {'error': 'disk-missing'}
            if not disk['match']:
                return {'error': 'disk-mismatch'}
        if both and disk['match']:
            return {'identity': 'disk', 'record': disk['record'], 'create': False, 'warnings': []}
        if both:
            notes.append('disk-mismatch')
        elif disk['certificate'] or disk['key']:
            notes.append('disk-incomplete')
    elif mode not in ('1password', 'self-signed'):
        notes.append('unknown-mode')
    if self_signed['certificate'] != self_signed['key']:
        return {'error': 'self-signed-half-pair'}
    create = not self_signed['certificate']
    if create and root:
        return {'error': 'self-signed-missing'}
    return {'identity': 'self-signed', 'record': False, 'create': create,
            'warnings': sorted(notes)}


def _protect_cache():
    """Disable core dumps before any cached secret enters this process."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if sys.platform != 'linux':
            raise IdentityError('cache-protection-unavailable')
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            raise IdentityError('cache-protection-unavailable')
    except (OSError, ValueError, AttributeError):
        raise IdentityError('cache-protection-unavailable') from None


class Identity:
    """Selected record and TLS material, with cache material kept off disk."""

    def __init__(self, source, *, certificate=None, key=None, record_data=None,
                 certificate_data=None, key_data=None):
        self.source = source
        self.record_data = record_data
        self._certificate = certificate
        self._key = key
        self._certificate_data = certificate_data
        self._key_data = key_data

    def load_cert_chain(self, ctx):
        try:
            if self.source != 'cache':
                ctx.load_cert_chain(self._certificate, self._key, password=lambda: '')
                return
            _protect_cache()
            # SSLContext requires filenames. Anonymous Linux memfds expose only
            # process-local paths and are closed even when OpenSSL rejects PEM.
            with os.fdopen(os.memfd_create('omdrop-certificate', os.MFD_CLOEXEC), 'wb') as cert:
                with os.fdopen(os.memfd_create('omdrop-key', os.MFD_CLOEXEC), 'wb') as key:
                    cert.write(self._certificate_data)
                    key.write(self._key_data)
                    cert.flush()
                    key.flush()
                    ctx.load_cert_chain(f'/proc/self/fd/{cert.fileno()}',
                                        f'/proc/self/fd/{key.fileno()}',
                                        password=lambda: '')
        except (OSError, ValueError, AttributeError, ssl.SSLError):
            raise IdentityError('identity-tls-load-failed') from None


def _invoking_user():
    root = os.geteuid() == 0
    try:
        uid = os.getuid()
        if root:
            uid = int(os.environ.get('PKEXEC_UID', os.environ.get('SUDO_UID', '0')))
        return pwd.getpwuid(uid), root
    except (ValueError, KeyError, OverflowError):
        raise IdentityError('invoking-user-invalid') from None


def _identity_paths(user, root):
    home = Path(user.pw_dir)
    if root:
        return home / '.config/omdrop/settings', Path(f'/run/user/{user.pw_uid}/omdrop/window')
    config = Path(os.environ.get('XDG_CONFIG_HOME') or home / '.config')
    runtime = Path(os.environ.get('XDG_RUNTIME_DIR') or f'/run/user/{user.pw_uid}')
    return config / 'omdrop/settings', runtime / 'omdrop/window'


def _keyctl(*args):
    return subprocess.run(['keyctl', *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, 'LC_ALL': 'C'})


def _missing_key(result):
    return (b'Required key not available' in result.stderr or
            b'Key has expired' in result.stderr or b'Key has been revoked' in result.stderr)


def _read_keyring(ring):
    found = _keyctl('search', ring, 'user', 'omdrop:identity')
    if found.returncode:
        if _missing_key(found):
            return None
        raise IdentityError('cache-unreadable')
    serial = found.stdout.strip()
    if not serial.isdigit():
        raise IdentityError('cache-unreadable')
    result = _keyctl('pipe', serial.decode('ascii'))
    if result.returncode:
        if _missing_key(result):
            return None
        raise IdentityError('cache-unreadable')
    return result.stdout


# A fresh *keyring* session confines the link needed for possessor permissions
# to the dropped child. Neither its credentials nor its links affect the parent.
_CACHE_CHILD = """
import ctypes, os, resource, subprocess, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
    sys.exit(2)
def run(*args):
    return subprocess.run(['keyctl', *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if run('link', '@u', '@s').returncode:
    sys.exit(2)
found = run('search', '@u', 'user', 'omdrop:identity')
if found.returncode:
    missing = (b'Required key not available', b'Key has expired', b'Key has been revoked')
    sys.exit(3 if any(message in found.stderr for message in missing) else 2)
serial = found.stdout.strip()
if not serial.isdigit():
    sys.exit(2)
result = run('pipe', serial.decode('ascii'))
if result.returncode:
    missing = (b'Required key not available', b'Key has expired', b'Key has been revoked')
    sys.exit(3 if any(message in result.stderr for message in missing) else 2)
sys.stdout.buffer.write(result.stdout)
"""


def _read_cache(user, root):
    _protect_cache()
    try:
        if not root:
            return _read_keyring('@u')
        # Only root acting for itself may use @u directly in this process.
        try:
            ring = '@u' if user.pw_uid == 0 else f'%:_uid.{user.pw_uid}'
            result = _read_keyring(ring)
            if result is not None:
                return result
        except IdentityError:
            pass
        result = subprocess.run(
            ['keyctl', 'session', '-', sys.executable, '-c', _CACHE_CHILD],
            user=user.pw_uid, group=user.pw_gid, extra_groups=[],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, 'LC_ALL': 'C'})
        if result.returncode == 3:
            return None
        if result.returncode:
            raise IdentityError('cache-unreadable-as-root')
        return result.stdout
    except OSError:
        raise IdentityError('cache-unreadable-as-root' if root else 'cache-unreadable') from None


# Run as the invoking user when this process is root acting for someone else.
# Every path below is in the user's home or runtime directory, so the user can
# point it anywhere with a symlink; root following it would read files the
# user cannot. A child with the user's uid, gid and no supplementary groups
# reads only what the user could read anyway.
def _as_user(user, root):
    if not root or user.pw_uid == 0:
        return {}
    return {'user': user.pw_uid, 'group': user.pw_gid, 'extra_groups': []}


_READ_CHILD = """
import sys
try:
    with open(sys.argv[1], 'rb') as handle:
        sys.stdout.buffer.write(handle.read())
except FileNotFoundError:
    sys.exit(3)
except OSError:
    sys.exit(2)
"""


def _read_user_file(path, user, root):
    """The file's bytes, read with the invoking user's permissions."""
    drop = _as_user(user, root)
    if not drop:
        return Path(path).read_bytes()
    result = subprocess.run([sys.executable, '-c', _READ_CHILD, str(path)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, **drop)
    if result.returncode == 3:
        raise FileNotFoundError(str(path))
    if result.returncode:
        raise OSError(f'cannot read {path} as uid {user.pw_uid}')
    return result.stdout


_EXISTS_CHILD = """
import os, sys
tests = {'l': os.path.lexists, 'e': os.path.exists}
print(''.join('1' if tests[m](p) else '0' for m, p in zip(sys.argv[1::2], sys.argv[2::2])))
"""


def _user_paths_exist(checks, user, root):
    """[(mode, path)] -> [bool], tested with the invoking user's permissions.

    Mode 'l' is lexists and 'e' is exists. Root walking a path the user built
    would answer whether files exist behind directories the user cannot enter.
    """
    drop = _as_user(user, root)
    if not drop:
        tests = {'l': os.path.lexists, 'e': os.path.exists}
        return [tests[mode](path) for mode, path in checks]
    argv = [arg for mode, path in checks for arg in (mode, str(path))]
    try:
        result = subprocess.run([sys.executable, '-c', _EXISTS_CHILD, *argv],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, **drop)
    except OSError:
        raise IdentityError('invoking-user-invalid') from None
    answer = result.stdout.strip()
    if result.returncode or len(answer) != len(checks) or set(answer) - {'0', '1'}:
        raise IdentityError('invoking-user-invalid')
    return [bit == '1' for bit in answer]


def _disk_matches(certificate, key, user=None, root=False):
    drop = _as_user(user, root) if user is not None else {}
    try:
        cert = subprocess.run(
            ['openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **drop)
        private = subprocess.run(
            ['openssl', 'pkey', '-in', str(key), '-passin', 'pass:', '-pubout'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **drop)
    except OSError:
        raise IdentityError('disk-validation-unavailable') from None
    return cert.returncode == private.returncode == 0 and cert.stdout == private.stdout


def _pair_state(certificate, key):
    # lexists also protects dangling symlinks from accidental replacement.
    return {'certificate': os.path.lexists(certificate), 'key': os.path.lexists(key)}


def _create_self_signed(directory, computer_name):
    certificate = directory / 'certificate.self-signed.pem'
    key = directory / 'key.self-signed.pem'
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(directory / '.identity.lock', os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = _pair_state(certificate, key)
            if state['certificate'] != state['key']:
                raise IdentityError('self-signed-half-pair')
            if state['certificate']:
                return
            with tempfile.TemporaryDirectory(prefix='.identity-', dir=directory) as temporary:
                temporary = Path(temporary)
                # Escape OpenSSL's subject separators; no shell is involved.
                name = computer_name.replace('\\', '\\\\').replace('/', '\\/')
                result = subprocess.run(
                    ['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-x509',
                     '-days', '365', '-subj', f'/CN={name}',
                     '-keyout', str(temporary / 'key.pem'),
                     '-out', str(temporary / 'certificate.pem')],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode:
                    raise IdentityError('self-signed-create-failed')
                for name in ('key.pem', 'certificate.pem'):
                    (temporary / name).chmod(0o600)
                made_key = False
                try:
                    os.link(temporary / 'key.pem', key)
                    made_key = True
                    os.link(temporary / 'certificate.pem', certificate)
                except OSError as error:
                    if made_key:
                        # Remove only our inode, not a concurrent replacement.
                        if key.stat().st_ino == (temporary / 'key.pem').stat().st_ino:
                            key.unlink()
                    if not isinstance(error, FileExistsError):
                        raise
                    state = _pair_state(certificate, key)
                    if state['certificate'] != state['key']:
                        raise IdentityError('self-signed-half-pair') from None
                    if not state['certificate']:
                        raise IdentityError('self-signed-missing') from None
    except (OSError, ValueError):
        raise IdentityError('self-signed-create-failed') from None


def resolve_identity(*, keys=None, computer_name=None, create=True):
    """Resolve for the invoking user; never fetch from 1Password or use a radio."""
    user, root = _invoking_user()
    settings_path, window_path = _identity_paths(user, root)
    try:
        settings = parse_settings(_read_user_file(settings_path, user, root).decode('utf-8'))
    except FileNotFoundError:
        settings = {}
    except (OSError, UnicodeError):
        raise IdentityError('settings-unreadable') from None
    try:
        window = parse_window(_read_user_file(window_path, user, root).decode('utf-8'))
    except FileNotFoundError:
        window = None
    except (OSError, UnicodeError):
        window = 'unparseable'
    now = int(time.time())
    if window == 'unparseable':
        raise IdentityError('window-unparseable')
    cache = None
    if window is not None and window['source'] == '1password':
        if window['hard_expiry'] <= now:
            raise IdentityError('window-expired')
        payload = _read_cache(user, root)
        cache = None if payload is None else parse_payload(payload)
    directory = (Path(keys) if keys is not None else Path(user.pw_dir) / '.omdrop') / 'keys'
    certificate, key = directory / 'certificate.pem', directory / 'key.pem'
    record = directory / 'validation_record.cms'
    self_cert, self_key = directory / 'certificate.self-signed.pem', directory / 'key.self-signed.pem'
    have = _user_paths_exist([('l', certificate), ('l', key), ('e', record),
                              ('l', self_cert), ('l', self_key)], user, root)
    disk = {'certificate': have[0], 'key': have[1], 'record': have[2], 'match': False}
    mode = window['source'] if window else settings.get('identity_source', 'disk')
    if mode == 'disk' and disk['certificate'] and disk['key']:
        disk['match'] = _disk_matches(certificate, key, user, root)
    choice = select_identity(settings, window, cache, disk,
                             {'certificate': have[3], 'key': have[4]}, root or not create, now)
    if 'error' in choice:
        raise IdentityError(choice['error'])
    for note in choice['warnings']:
        warnings.warn(note, RuntimeWarning, stacklevel=2)
    if choice['identity'] == 'cache':
        return Identity('cache', certificate_data=base64.b64decode(cache['certificate_b64']),
                        key_data=base64.b64decode(cache['key_b64']),
                        record_data=base64.b64decode(cache['record_b64']))
    if choice['identity'] == 'self-signed':
        if choice['create']:
            _create_self_signed(directory, computer_name or socket.gethostname())
        return Identity('self-signed', certificate=self_cert, key=self_key)
    try:
        record_data = _read_user_file(record, user, root) if choice['record'] else None
    except OSError:
        raise IdentityError('disk-record-unreadable') from None
    return Identity('disk', certificate=certificate, key=key, record_data=record_data)
