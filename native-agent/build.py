#!/usr/bin/env python3
"""Maintainer release build. Prepared Reap releases need no Go installation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

TOOLCHAIN = 'go1.26.9'
ROOT = Path(__file__).resolve().parent
TARGETS = [('linux', 'amd64'), ('linux', 'arm64'), ('windows', 'amd64')]


def _filename(platform, arch):
    return 'reap-agent-%s-%s%s' % (platform, arch, '.exe' if platform == 'windows' else '')


def _validate_artifact(data, platform, arch):
    """Reject wrong targets, truncated executables, and dynamic Linux builds."""
    if platform == 'linux':
        machine = {'amd64': 62, 'arm64': 183}[arch]
        if (len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01'
                or struct.unpack_from('<H', data, 18)[0] != machine):
            raise ValueError('expected a Linux %s ELF executable' % arch)
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phsize, phcount = struct.unpack_from('<HH', data, 54)
        if phsize != 56 or not phcount or phoff < 64 or phoff + phsize * phcount > len(data):
            raise ValueError('Linux executable has missing or truncated program headers')
        kinds = [struct.unpack_from('<I', data, phoff + i * phsize)[0] for i in range(phcount)]
        if 1 not in kinds or 2 in kinds or 3 in kinds:  # PT_LOAD, PT_DYNAMIC, PT_INTERP
            raise ValueError('Linux executable must be static and contain loadable segments')
    else:
        if len(data) < 64 or data[:2] != b'MZ':
            raise ValueError('expected a Windows amd64 PE executable')
        offset = struct.unpack_from('<I', data, 60)[0]
        if (offset + 24 + 112 > len(data) or data[offset:offset + 4] != b'PE\0\0'
                or struct.unpack_from('<H', data, offset + 4)[0] != 0x8664
                or struct.unpack_from('<H', data, offset + 24)[0] != 0x20b):
            raise ValueError('expected a Windows amd64 PE executable')
        sections = struct.unpack_from('<H', data, offset + 6)[0]
        header_size = struct.unpack_from('<H', data, offset + 20)[0]
        if (header_size < 112 or not sections or offset + 24 + header_size + 40 * sections > len(data)
                or not struct.unpack_from('<H', data, offset + 22)[0] & 2
                or struct.unpack_from('<H', data, offset + 22)[0] & 0x2000):
            raise ValueError('Windows executable has invalid headers or is a DLL')


def package_artifacts(output, destination, version):
    """Verify the complete release before copying any files into package data."""
    manifest_data = (output / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_data)
    if manifest.get('build_version') != version or manifest.get('protocol_version') != 1:
        raise ValueError('native release manifest does not match Reap %s / protocol 1' % version)
    records = manifest.get('artifacts')
    if not isinstance(records, list) or len(records) != len(TARGETS):
        raise ValueError('native release must contain every supported target exactly once')
    files = {}
    for platform, arch in TARGETS:
        matches = [row for row in records if row.get('platform') == platform and row.get('arch') == arch]
        if len(matches) != 1:
            raise ValueError('native release is missing a unique %s %s executable' % (platform, arch))
        record = matches[0]
        filename = _filename(platform, arch)
        if record.get('executable') != filename or record.get('build_version') != version:
            raise ValueError('invalid native release metadata for %s' % filename)
        data = (output / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != record.get('sha256'):
            raise ValueError('SHA-256 mismatch for %s' % filename)
        _validate_artifact(data, platform, arch)
        files[filename] = data
    destination.mkdir(parents=True, exist_ok=True)
    for filename, data in files.items():
        path = destination / filename
        path.write_bytes(data)
        path.chmod(0o755)
    (destination / 'manifest.json').write_bytes(manifest_data)
    print('Included ready-to-use agents in %s' % destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--source-revision', help='source revision to record when Git metadata is unavailable')
    packaging = parser.add_mutually_exclusive_group()
    packaging.add_argument('--package', action='store_true',
                           help='build and include all agents in the Python package for a prepared release')
    packaging.add_argument('--package-only', action='store_true',
                           help='include a previously built release from --output; does not require Go')
    options = parser.parse_args()
    version = re.search(r'__version__ = "([^"]+)"', (ROOT.parent / 'reap/__init__.py').read_text()).group(1)
    output = options.output.resolve()
    if options.package_only:
        try:
            package_artifacts(output, ROOT.parent / 'reap/data/native', version)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            parser.error('cannot prepare this release: %s' % exc)
        return
    try:
        actual = subprocess.check_output([options.go, 'version'], text=True).split()[2]
    except (OSError, subprocess.CalledProcessError, IndexError):
        parser.error('this maintainer build requires %s. To use Reap, install a prepared release; '
                     'Go is not needed by users.' % TOOLCHAIN)
    if actual != TOOLCHAIN:
        parser.error('build requires %s; found %s' % (TOOLCHAIN, actual))
    try:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                           text=True, stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT,
                                             text=True, stderr=subprocess.DEVNULL))
    except (OSError, subprocess.CalledProcessError):
        revision = options.source_revision or 'unknown'
        dirty = None
        if revision == 'unknown':
            print('Warning: Git metadata unavailable; source revision is unknown. '
                  'Use --source-revision to identify an extracted source archive.', file=sys.stderr)
    output.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for platform, arch in TARGETS:
        filename = _filename(platform, arch)
        env = dict(os.environ, CGO_ENABLED='0', GOOS=platform, GOARCH=arch, GOAMD64='v1',
                   GOTOOLCHAIN='local')
        subprocess.run([options.go, 'build', '-trimpath', '-buildvcs=false',
                        '-ldflags=-X main.version=' + version, '-o', str(output / filename),
                        './cmd/reap-agent'], cwd=ROOT, env=env, check=True)
        data = (output / filename).read_bytes()
        _validate_artifact(data, platform, arch)
        artifacts.append(dict(platform=platform, arch=arch, executable=filename,
                              build_version=version, sha256=hashlib.sha256(data).hexdigest(),
                              cgo_enabled=False, amd64_level='v1' if arch == 'amd64' else None))
    manifest = dict(build_version=version, source_revision=revision, source_dirty=dirty,
                    toolchain=actual, protocol_version=1, artifacts=artifacts)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(output / 'manifest.json')
    if options.package:
        package_artifacts(output, ROOT.parent / 'reap/data/native', version)


if __name__ == '__main__':
    main()
