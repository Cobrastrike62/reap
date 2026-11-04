"""Prepared releases must contain verified agents before packaging starts."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest


spec = importlib.util.spec_from_file_location('native_build', Path(__file__).resolve().parents[1] / 'native-agent/build.py')
native_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_build)


def release(tmp_path):
    source = tmp_path / 'release'
    source.mkdir()
    records = []
    for platform, arch in native_build.TARGETS:
        if platform == 'linux':
            data = bytearray(120)
            data[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<H', data, 18, 62 if arch == 'amd64' else 183)
            struct.pack_into('<Q', data, 32, 64)
            struct.pack_into('<HH', data, 54, 56, 1)
            struct.pack_into('<I', data, 64, 1)
        else:
            data = bytearray(256)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 60, 64)
            data[64:68] = b'PE\0\0'
            struct.pack_into('<HH', data, 68, 0x8664, 1)
            struct.pack_into('<HHH', data, 84, 112, 2, 0x20b)
        filename = native_build._filename(platform, arch)
        (source / filename).write_bytes(data)
        records.append(dict(platform=platform, arch=arch, executable=filename,
                            build_version='test', sha256=hashlib.sha256(data).hexdigest()))
    (source / 'manifest.json').write_text(json.dumps(dict(build_version='test', protocol_version=1, artifacts=records)))
    return source


def test_stage_complete_release_without_running_a_compiler(tmp_path, monkeypatch):
    source = release(tmp_path)
    destination = tmp_path / 'package'
    monkeypatch.setattr(native_build.subprocess, 'run', lambda *args, **kwargs: pytest.fail('packaging invoked a compiler'))
    native_build.package_artifacts(source, destination, 'test')
    assert {file.name for file in destination.iterdir()} == {file.name for file in source.iterdir()}
    for file in source.iterdir():
        assert (destination / file.name).read_bytes() == file.read_bytes()


def test_package_only_command_needs_no_compiler(tmp_path, monkeypatch):
    source = release(tmp_path)
    native_root = tmp_path / 'native-agent'
    package_root = tmp_path / 'reap'
    package_root.mkdir()
    (package_root / '__init__.py').write_text('__version__ = "test"\n')
    monkeypatch.setattr(native_build, 'ROOT', native_root)
    monkeypatch.setattr(sys, 'argv', ['build.py', '--package-only', '--output', str(source)])
    monkeypatch.setattr(native_build.subprocess, 'check_output', lambda *args, **kwargs: pytest.fail('packaging invoked a compiler'))
    native_build.main()
    assert (package_root / 'data/native/manifest.json').is_file()


@pytest.mark.parametrize('failure', ['missing', 'tampered', 'wrong-version', 'wrong-target'])
def test_invalid_release_does_not_modify_existing_package_data(tmp_path, failure):
    source = release(tmp_path)
    executable = source / 'reap-agent-linux-arm64'
    if failure == 'missing':
        executable.unlink()
    elif failure == 'tampered':
        executable.write_bytes(executable.read_bytes() + b'tampered')
    elif failure == 'wrong-target':
        executable.write_bytes((source / 'reap-agent-linux-amd64').read_bytes())
        manifest_path = source / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['artifacts'][1]['sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
    destination = tmp_path / 'package'
    destination.mkdir()
    marker = destination / 'previous-release'
    marker.write_text('preserve')
    with pytest.raises((OSError, ValueError)):
        native_build.package_artifacts(source, destination, 'new-version' if failure == 'wrong-version' else 'test')
    assert list(destination.iterdir()) == [marker]
    assert marker.read_text() == 'preserve'
