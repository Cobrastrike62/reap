"""Operator-side provisioning for the standalone lab agent."""
from __future__ import annotations

import datetime
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import struct
from pathlib import Path


_NATIVE_ROOT = Path(__file__).with_name('data') / 'native'
_TARGETS = {('linux', 'amd64'), ('linux', 'arm64'), ('windows', 'amd64')}
_CONFIG_MAGIC = b'REAPCFG1'
_CONFIG_MAX_SIZE = 65536
_PROFILE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$')
_HOST_LABEL = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
_SIMPLE_TARGETS = {'linux': ('linux', 'amd64'), 'linux-arm64': ('linux', 'arm64'),
                   'windows': ('windows', 'amd64')}


@dataclass(frozen=True)
class AgentProfile:
    """A ready-to-run target file and the private listener identity on this PC."""

    name: str
    callback: str
    port: int
    target: str
    executable: Path
    authkit: Path
    directory: Path
    build_version: str

    @property
    def bundle(self):
        return self.authkit

    @property
    def output(self):
        return self.executable


def _validate_callback(callback):
    if (not isinstance(callback, str) or not callback or len(callback) > 253
            or callback != callback.strip()):
        raise ValueError('Use the IP address or hostname of your Reap computer, without a URL or port.')
    try:
        address = ipaddress.ip_address(callback)
    except ValueError:
        host = callback[:-1] if callback.endswith('.') else callback
        if not all(_HOST_LABEL.fullmatch(label) for label in host.split('.')):
            raise ValueError('Use the IP address or hostname of your Reap computer, without a URL or port.') from None
    else:
        mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
        if address.is_unspecified or (mapped is not None and mapped.is_unspecified):
            raise ValueError('Use a reachable IP address for your Reap computer, not 0.0.0.0 or ::.')
        if '%' in callback:
            raise ValueError('Use an IP address without an interface name, or use a hostname.')
    return callback


def _agent_state_dir(state_dir=None):
    if state_dir is not None:
        return Path(state_dir).expanduser().absolute()
    override = os.environ.get('REAP_AGENT_HOME')
    if override:
        return Path(override).expanduser().absolute()
    return Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'reap' / 'agents'


def _safe_profile_name(name):
    if not isinstance(name, str) or not _PROFILE_NAME.fullmatch(name) or name in ('.', '..'):
        raise ValueError('Invalid agent name. Use the name printed by agent create or agent list.')
    return name


def _exclusive_write(path, contents, mode=0o600):
    # O_EXCL refuses both existing files and symlinks before touching their data.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(contents)
        path.chmod(mode)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _pack_connection(binary, callback, port, token, fingerprint):
    config = dict(version=1, connect=callback, port=port, token=token, fingerprint=fingerprint)
    contents = json.dumps(config, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    if len(contents) > _CONFIG_MAX_SIZE:
        raise ValueError('Agent connection setup is too large.')
    return binary + contents + _CONFIG_MAGIC + struct.pack('!I', len(contents))


def create_agent(callback, target='linux', output=None, port=7443, state_dir=None):
    """Create one executable; keep its listener certificate and key private locally.

    Only an address, port, token, and public certificate fingerprint are appended
    to the verified release executable. No compiler runs on this path.
    """
    from . import __version__

    callback = _validate_callback(callback)
    if target not in _SIMPLE_TARGETS:
        raise ValueError('Choose linux, linux-arm64, or windows for the target computer.')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Choose a port between 1 and 65535.')
    platform, arch = _SIMPLE_TARGETS[target]
    binary, build_version = _native_artifact(platform, arch, None)
    if build_version != __version__:
        raise ValueError('These agent files belong to another Reap version. Install the prepared Reap %s release, '
                         'then run agent create again.' % __version__)
    filename = 'reap-agent.exe' if platform == 'windows' else 'reap-agent'
    executable = (Path.cwd() / filename if output is None else Path(output).expanduser()).absolute()
    if executable.exists() or executable.is_symlink():
        raise FileExistsError('Agent file already exists: %s. Choose another name with --output.' % executable)
    executable = executable.resolve()
    if not executable.parent.is_dir():
        raise ValueError('The output folder does not exist: %s. Create it or choose another --output.' % executable.parent)
    root = _agent_state_dir(state_dir)
    if root.is_symlink():
        raise ValueError('The private agent folder must not be a symbolic link: %s' % root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    name = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-') + secrets.token_hex(4)
    directory = root / name
    directory.mkdir(mode=0o700, exist_ok=False)
    wrote_executable = False
    try:
        authkit = prepare_bundle(directory / 'authkit')
        token = (authkit / 'token.txt').read_text(encoding='utf-8').strip()
        fingerprint = (authkit / 'fingerprint.txt').read_text(encoding='utf-8').strip()
        _exclusive_write(executable, _pack_connection(binary, callback, port, token, fingerprint), 0o700)
        wrote_executable = True
        profile = dict(version=1, name=name, callback=callback, port=port, target=target,
                       executable=str(executable), authkit='authkit', build_version=build_version)
        _exclusive_write(directory / 'profile.json', (json.dumps(profile, indent=2) + '\n').encode())
        # A private, atomic pointer makes `agent listen` resume the latest setup.
        temporary = root / ('.latest-' + secrets.token_hex(4))
        try:
            _exclusive_write(temporary, (name + '\n').encode())
            temporary.replace(root / 'latest')
        finally:
            temporary.unlink(missing_ok=True)
        return AgentProfile(name, callback, port, target, executable, authkit, directory, build_version)
    except BaseException:
        if wrote_executable:
            executable.unlink(missing_ok=True)
        # This directory was created exclusively by this call and is inside root.
        shutil.rmtree(directory)
        raise


def load_agent_profile(name=None, state_dir=None):
    """Load a locally saved agent by its printed name, or the most recent one."""
    root = _agent_state_dir(state_dir)
    if root.is_symlink():
        raise ValueError('The private agent folder must not be a symbolic link: %s' % root)
    if name is None:
        latest = root / 'latest'
        if latest.is_symlink():
            raise ValueError('Saved latest agent name must not be a symbolic link.')
        try:
            name = latest.read_text(encoding='utf-8').strip()
        except FileNotFoundError:
            raise ValueError('No saved agent yet. Run agent create HOST first.') from None
    name = _safe_profile_name(name)
    directory = root / name
    path = directory / 'profile.json'
    if directory.is_symlink() or path.is_symlink():
        raise ValueError('Saved agent settings must not be symbolic links.')
    try:
        if path.stat().st_size > 65536:
            raise ValueError('Saved agent settings are too large.')
        record = json.loads(path.read_text(encoding='utf-8'))
        expected = {'version', 'name', 'callback', 'port', 'target', 'executable', 'authkit', 'build_version'}
        if (not isinstance(record, dict) or set(record) != expected
                or type(record['version']) is not int or record['version'] != 1
                or record['name'] != name or record['target'] not in _SIMPLE_TARGETS
                or type(record['port']) is not int or not 1 <= record['port'] <= 65535
                or record['authkit'] != 'authkit' or not isinstance(record['build_version'], str)
                or not record['build_version']):
            raise ValueError('Saved agent settings are invalid.')
        _validate_callback(record['callback'])
        executable = Path(record['executable'])
        if not executable.is_absolute() or '..' in executable.parts:
            raise ValueError('Saved agent output path is invalid.')
        authkit = directory / 'authkit'
        if authkit.is_symlink() or not authkit.is_dir():
            raise ValueError('Saved agent listener identity is missing or invalid.')
        for filename in ('cert.pem', 'key.pem', 'token.txt', 'fingerprint.txt'):
            item = authkit / filename
            if item.is_symlink() or not item.is_file():
                raise ValueError('Saved agent listener identity is missing or invalid.')
        return AgentProfile(name, record['callback'], record['port'], record['target'], executable,
                            authkit, directory, record['build_version'])
    except FileNotFoundError:
        raise ValueError('Cannot find saved agent %s. Run agent create HOST first.' % name) from None
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError('Saved agent settings are invalid. Create a new agent with agent create HOST.') from exc


def list_agent_profiles(state_dir=None):
    root = _agent_state_dir(state_dir)
    if not root.exists():
        return []
    # Invalid or damaged profiles surface their error rather than silently vanish.
    return [load_agent_profile(path.name, state_dir=root) for path in sorted(root.iterdir(), reverse=True)
            if path.is_dir() and _PROFILE_NAME.fullmatch(path.name)]


def _validate_executable(data, platform, arch):
    """Check the executable header without running an operator-supplied file."""
    if platform == 'linux':
        machine = {'amd64': 62, 'arm64': 183}[arch]
        if (len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01'
                or data[7] not in (0, 3)
                or struct.unpack_from('<H', data, 16)[0] not in (2, 3)
                or struct.unpack_from('<H', data, 18)[0] != machine
                or struct.unpack_from('<I', data, 20)[0] != 1):
            raise ValueError('native binary must be a Linux ELF64 %s executable' % arch)
        phoff = struct.unpack_from('<Q', data, 32)[0]
        ehsize, phsize, phcount = struct.unpack_from('<HHH', data, 52)
        if (ehsize != 64 or phsize != 56 or not phcount or phoff < ehsize
                or phoff + phsize * phcount > len(data)
                or not any(struct.unpack_from('<I', data, phoff + phsize * i)[0] == 1
                           for i in range(phcount))):
            raise ValueError('native Linux ELF executable has missing or truncated program headers')
    else:
        if len(data) < 64 or data[:2] != b'MZ':
            raise ValueError('native binary must be a Windows PE32+ amd64 executable')
        offset = struct.unpack_from('<I', data, 60)[0]
        if (offset + 24 + 112 > len(data) or data[offset:offset + 4] != b'PE\0\0'
                or struct.unpack_from('<H', data, offset + 4)[0] != 0x8664
                or struct.unpack_from('<H', data, offset + 20)[0] < 112
                or not struct.unpack_from('<H', data, offset + 22)[0] & 2
                or struct.unpack_from('<H', data, offset + 24)[0] != 0x20b):
            raise ValueError('native binary must be a Windows PE32+ amd64 executable')
        sections = struct.unpack_from('<H', data, offset + 6)[0]
        header_size = struct.unpack_from('<H', data, offset + 20)[0]
        if (not sections or offset + 24 + header_size + 40 * sections > len(data)
                or struct.unpack_from('<H', data, offset + 22)[0] & 0x2000):
            raise ValueError('native Windows PE executable has missing or truncated section headers, or is a DLL')


def _native_artifact(platform, arch, binary):
    if (platform, arch) not in _TARGETS:
        raise ValueError('native agent requires --platform linux|windows and --arch amd64|arm64 '
                         '(Windows supports amd64 only)')
    build_version = 'unverified-local'
    if binary is None:
        artifact_root = _NATIVE_ROOT
        source_root = Path(__file__).resolve().parents[1]
        if (artifact_root == Path(__file__).with_name('data') / 'native'
                and not (artifact_root / 'manifest.json').exists()
                and (source_root / 'native-agent' / 'go.mod').is_file()
                and (source_root / 'pyproject.toml').is_file()):
            artifact_root = source_root / 'native-agent' / 'dist'
        manifest_path = artifact_root / 'manifest.json'
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            artifacts = manifest['artifacts']
            if not isinstance(artifacts, list):
                raise ValueError('artifacts must be a list')
            matches = [row for row in artifacts if row.get('platform') == platform and row.get('arch') == arch]
            if len(matches) != 1:
                raise ValueError('no unique matching artifact')
            record = matches[0]
            filename = record['executable']
            if (not isinstance(filename, str) or not filename or '/' in filename or '\\' in filename or ':' in filename
                    or filename in ('.', '..')):
                raise ValueError('invalid artifact filename')
            path = artifact_root / filename
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != record['sha256']:
                raise ValueError('artifact SHA-256 mismatch')
            build_version = record.get('build_version', manifest.get('build_version'))
            if not isinstance(build_version, str) or not build_version:
                raise ValueError('artifact build version missing')
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError('Ready-to-run agent files are missing or damaged. Install a prepared Reap release. '
                             'For the advanced bundle command, maintainers can supply --binary '
                             'with a verified local release artifact (%s).' % exc) from exc
    else:
        path = Path(binary)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValueError('cannot read native --binary %s: %s' % (path, exc)) from exc
        # A copied release manifest can describe this exact local artifact. Its
        # digest binds metadata to bytes; the operator still establishes trust.
        try:
            manifest = json.loads(path.with_name('manifest.json').read_text(encoding='utf-8'))
            records = [row for row in manifest['artifacts']
                       if row.get('platform') == platform and row.get('arch') == arch
                       and row.get('executable') == path.name
                       and row.get('sha256') == hashlib.sha256(data).hexdigest()]
            if len(records) == 1:
                version = records[0].get('build_version', manifest.get('build_version'))
                if isinstance(version, str) and version:
                    build_version = version
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass
    _validate_executable(data, platform, arch)
    return data, build_version


def prepare_bundle(directory, implementation='python', platform=None, arch=None, binary=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from .data import reap_agent
    from . import __version__

    if implementation not in ('python', 'native'):
        raise ValueError('agent implementation must be python or native')
    native = None
    if implementation == 'native':
        native, build_version = _native_artifact(platform, arch, binary)
        executable = 'reap-agent.exe' if platform == 'windows' else 'reap-agent'
    elif any(value is not None for value in (platform, arch, binary)):
        raise ValueError('--platform, --arch and --binary require --type native')
    else:
        executable, build_version = 'reap_agent.py', __version__

    destination = Path(directory)
    # Never overwrite an existing identity or token.
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Reap lab agent')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    contents = {
        '.gitignore': b'*\n',
        'cert.pem': cert.public_bytes(serialization.Encoding.PEM),
        'key.pem': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()),
        'token.txt': (secrets.token_urlsafe(32) + '\n').encode(),
        'fingerprint.txt': (cert.fingerprint(hashes.SHA256()).hex() + '\n').encode(),
    }
    for filename, data in contents.items():
        path = destination / filename
        path.write_bytes(data)
        path.chmod(0o600)
    if native is not None:
        (destination / executable).write_bytes(native)
        (destination / executable).chmod(0o700)
    else:
        shutil.copyfile(reap_agent.__file__, destination / executable)
        (destination / executable).chmod(0o600)
    manifest = {'implementation': implementation, 'build_version': build_version,
                'platform': platform if native is not None else 'portable',
                'arch': arch if native is not None else 'portable', 'protocol_version': 1,
                'executable': executable,
                'sha256': hashlib.sha256((destination / executable).read_bytes()).hexdigest()}
    path = destination / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    path.chmod(0o600)
    return destination
