from __future__ import annotations

import hashlib
import json
import os
import stat
import struct

import pytest

from reap import agent


def elf(arch='amd64'):
    data = bytearray(120)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 2, {'amd64': 62, 'arm64': 183}[arch], 1)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, 1)
    struct.pack_into('<I', data, 64, 1)
    return bytes(data)


def pe():
    data = bytearray(256)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 64)
    data[64:68] = b'PE\0\0'
    struct.pack_into('<H', data, 68, 0x8664)
    struct.pack_into('<H', data, 70, 1)
    struct.pack_into('<HHH', data, 84, 112, 2, 0x20b)
    return bytes(data)


@pytest.mark.parametrize('platform,arch,data,filename', [
    ('linux', 'amd64', elf(), 'reap-agent'),
    ('linux', 'arm64', elf('arm64'), 'reap-agent'),
    ('windows', 'amd64', pe(), 'reap-agent.exe')])
def test_native_bundle_selection_manifest_and_permissions(tmp_path, platform, arch, data, filename):
    binary = tmp_path / 'local-build'
    binary.write_bytes(data)
    kit = agent.prepare_bundle(tmp_path / 'kit', implementation='native', platform=platform, arch=arch, binary=binary)
    assert (kit / filename).read_bytes() == data
    assert not (kit / 'reap_agent.py').exists()
    manifest = json.loads((kit / 'manifest.json').read_text())
    assert manifest == {'implementation': 'native', 'platform': platform, 'arch': arch,
                        'build_version': 'unverified-local', 'protocol_version': 1,
                        'executable': filename, 'sha256': hashlib.sha256(data).hexdigest()}
    assert 'token' not in json.dumps(manifest) and 'private' not in json.dumps(manifest)
    assert len((kit / 'token.txt').read_text().strip()) >= 32
    if os.name == 'posix':
        assert stat.S_IMODE(kit.stat().st_mode) == 0o700
        assert stat.S_IMODE((kit / filename).stat().st_mode) == 0o700
        for name in ('token.txt', 'key.pem', 'manifest.json'):
            assert stat.S_IMODE((kit / name).stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        agent.prepare_bundle(kit, implementation='native', platform=platform, arch=arch, binary=binary)


@pytest.mark.parametrize('platform,arch,data', [
    ('linux', 'amd64', elf('arm64')), ('linux', 'arm64', elf()),
    ('linux', 'amd64', pe()), ('windows', 'amd64', elf()),
    ('windows', 'amd64', b'MZ'), ('linux', 'amd64', b'#!/bin/sh\n'),
    ('windows', 'arm64', pe()), (None, 'amd64', elf()), ('linux', None, elf())])
def test_native_rejects_wrong_format_architecture_and_missing_target(tmp_path, platform, arch, data):
    binary = tmp_path / 'binary'
    binary.write_bytes(data)
    with pytest.raises(ValueError):
        agent.prepare_bundle(tmp_path / 'kit', implementation='native', platform=platform, arch=arch, binary=binary)
    assert not (tmp_path / 'kit').exists()


def release_manifest(binary, **overrides):
    record = dict(platform='linux', arch='amd64', executable=binary.name,
                  sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    record.update(overrides)
    path = binary.with_name('manifest.json')
    path.write_text(json.dumps({'build_version': '1.12.0-test', 'artifacts': [record]}))
    return path


def test_package_artifact_is_selected_relative_to_package_not_cwd(tmp_path, monkeypatch):
    root = tmp_path / 'installed-package-data'
    root.mkdir()
    binary = root / 'reap-agent-linux-amd64'
    binary.write_bytes(elf())
    release_manifest(binary)
    monkeypatch.setattr(agent, '_NATIVE_ROOT', root)
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    kit = agent.prepare_bundle(tmp_path / 'kit', implementation='native', platform='linux', arch='amd64')
    assert json.loads((kit / 'manifest.json').read_text())['build_version'] == '1.12.0-test'
    binary.write_bytes(elf() + b'tampered')
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        agent.prepare_bundle(tmp_path / 'other', implementation='native', platform='linux', arch='amd64')


@pytest.mark.parametrize('override', [{}, {'sha256': '0' * 64}, {'arch': 'arm64'}])
def test_explicit_binary_build_metadata_requires_matching_manifest(tmp_path, override):
    binary = tmp_path / 'reap-agent-linux-amd64'
    binary.write_bytes(elf())
    release_manifest(binary, **override)
    kit = agent.prepare_bundle(tmp_path / 'kit', implementation='native', platform='linux', arch='amd64', binary=binary)
    assert json.loads((kit / 'manifest.json').read_text())['build_version'] == (
        '1.12.0-test' if not override else 'unverified-local')


def test_absent_native_binary_never_falls_back_to_python(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, '_NATIVE_ROOT', tmp_path / 'missing-package-data')
    with pytest.raises(ValueError, match='supply --binary'):
        agent.prepare_bundle(tmp_path / 'kit', implementation='native', platform='linux', arch='amd64')
    assert not (tmp_path / 'kit').exists()
    with pytest.raises(ValueError, match='cannot read native --binary'):
        agent.prepare_bundle(tmp_path / 'kit', implementation='native', platform='linux', arch='amd64', binary=tmp_path / 'absent')


@pytest.mark.parametrize('platform,data', [('linux', elf()[:64]), ('windows', pe()[:200])])
def test_truncated_executable_headers_are_rejected(tmp_path, platform, data):
    binary = tmp_path / 'truncated'
    binary.write_bytes(data)
    with pytest.raises(ValueError, match='truncated'):
        agent.prepare_bundle(tmp_path / 'kit', implementation='native', platform=platform, arch='amd64', binary=binary)


def test_python_default_and_native_only_flags(tmp_path):
    kit = agent.prepare_bundle(tmp_path / 'python')
    assert (kit / 'reap_agent.py').exists()
    assert json.loads((kit / 'manifest.json').read_text())['implementation'] == 'python'
    with pytest.raises(ValueError, match='require --type native'):
        agent.prepare_bundle(tmp_path / 'bad', platform='linux')
