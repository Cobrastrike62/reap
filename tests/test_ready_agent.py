"""Ready-to-run generation keeps all private listener files on the operator."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import struct

import pytest

from reap import agent
from reap import __version__
from tests.test_native_bundle import elf, pe


@pytest.fixture
def release(tmp_path, monkeypatch):
    root = tmp_path / 'release'
    root.mkdir()
    records = []
    for platform, arch, contents in [('linux', 'amd64', elf()), ('linux', 'arm64', elf('arm64')),
                                     ('windows', 'amd64', pe())]:
        filename = 'reap-agent-%s-%s%s' % (platform, arch, '.exe' if platform == 'windows' else '')
        (root / filename).write_bytes(contents)
        records.append(dict(platform=platform, arch=arch, executable=filename,
                            sha256=hashlib.sha256(contents).hexdigest()))
    (root / 'manifest.json').write_text(json.dumps(dict(build_version=__version__, artifacts=records)))
    monkeypatch.setattr(agent, '_NATIVE_ROOT', root)
    return root


def config_from(path):
    contents = path.read_bytes()
    assert contents[-12:-4] == b'REAPCFG1'
    size = struct.unpack('!I', contents[-4:])[0]
    return json.loads(contents[-12-size:-12])


@pytest.mark.parametrize('target,filename', [('linux', 'reap-agent'), ('linux-arm64', 'reap-agent'),
                                              ('windows', 'reap-agent.exe')])
def test_create_one_file_load_profile_and_keep_listener_key_private(release, tmp_path, monkeypatch, target, filename):
    monkeypatch.chdir(tmp_path)
    state = tmp_path / 'private'
    profile = agent.create_agent('127.0.0.1', target=target, state_dir=state)
    assert profile.executable == tmp_path / filename
    assert profile.bundle == profile.authkit and profile.output == profile.executable
    assert profile.port == 7443 and profile.build_version == __version__
    assert agent.load_agent_profile(state_dir=state) == profile
    assert agent.load_agent_profile(profile.name, state_dir=state) == profile
    assert agent.list_agent_profiles(state_dir=state) == [profile]
    assert {path.name for path in tmp_path.iterdir()} == {'release', 'private', filename}
    config = config_from(profile.executable)
    assert set(config) == {'version', 'connect', 'port', 'token', 'fingerprint'}
    assert config == dict(version=1, connect='127.0.0.1', port=7443,
                          token=(profile.authkit / 'token.txt').read_text().strip(),
                          fingerprint=(profile.authkit / 'fingerprint.txt').read_text().strip())
    assert b'PRIVATE KEY' not in profile.executable.read_bytes()
    assert (profile.authkit / 'key.pem').read_bytes() not in profile.executable.read_bytes()
    if os.name == 'posix':
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
        assert stat.S_IMODE(profile.directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(profile.executable.stat().st_mode) == 0o700
        assert stat.S_IMODE((profile.directory / 'profile.json').stat().st_mode) == 0o600


def test_generation_never_overwrites_target_file_or_creates_extra_profile(release, tmp_path):
    output, state = tmp_path / 'one-agent', tmp_path / 'private'
    first = agent.create_agent('reap.example.test', output=output, state_dir=state)
    old = output.read_bytes()
    with pytest.raises(FileExistsError, match='--output'):
        agent.create_agent('reap.example.test', output=output, state_dir=state)
    assert output.read_bytes() == old
    assert agent.list_agent_profiles(state) == [first]


@pytest.mark.parametrize('callback', ['', ' http://host', 'https://host', 'host/path', 'host:7443',
                                       'host\\path', 'host\nname', '-host', 'host..example', 'host..', '.'])
def test_invalid_callback_cannot_create_output_or_state(release, tmp_path, callback):
    with pytest.raises(ValueError, match='IP address or hostname'):
        agent.create_agent(callback, output=tmp_path / 'file', state_dir=tmp_path / 'state')
    assert not (tmp_path / 'file').exists() and not (tmp_path / 'state').exists()


@pytest.mark.parametrize('options', [{'port': 0}, {'port': True}, {'port': 65536}, {'target': 'macos'}])
def test_invalid_target_and_port(release, tmp_path, options):
    with pytest.raises(ValueError):
        agent.create_agent('host', output=tmp_path / 'file', state_dir=tmp_path / 'state', **options)


@pytest.mark.parametrize('callback', ['0.0.0.0', '::', '::ffff:0.0.0.0', 'fe80::1%eth0'])
def test_wildcard_and_interface_specific_callbacks_are_rejected(release, tmp_path, callback):
    with pytest.raises(ValueError, match='reachable IP|without an interface'):
        agent.create_agent(callback, output=tmp_path / 'file', state_dir=tmp_path / 'state')


def test_outdated_prebuilt_agent_explains_prepared_release_upgrade(release, tmp_path):
    manifest = release / 'manifest.json'
    record = json.loads(manifest.read_text())
    record['build_version'] = '1.12.0'
    manifest.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='prepared Reap'):
        agent.create_agent('host', output=tmp_path / 'file', state_dir=tmp_path / 'state')
    assert not (tmp_path / 'file').exists() and not (tmp_path / 'state').exists()


def test_state_environment_and_resuming_multiple_profiles(release, tmp_path, monkeypatch):
    state = tmp_path / 'settings'
    monkeypatch.setenv('REAP_AGENT_HOME', str(state))
    one = agent.create_agent('::1', output=tmp_path / 'one', port=7444)
    two = agent.create_agent('host', output=tmp_path / 'two')
    assert agent.load_agent_profile() == two
    assert agent.load_agent_profile(one.name) == one
    assert {row.name for row in agent.list_agent_profiles()} == {one.name, two.name}


@pytest.mark.parametrize('name', ['../outside', '..', '.', '/absolute', 'C:\\outside', 'name/other', ''])
def test_profile_names_cannot_escape_state_directory(tmp_path, name):
    with pytest.raises(ValueError, match='Invalid agent name'):
        agent.load_agent_profile(name, state_dir=tmp_path)


@pytest.mark.parametrize('change', [{'authkit': '../outside'}, {'name': 'someone-else'},
                                     {'version': 999}, {'executable': '../outside'}, {'port': True}])
def test_saved_profile_validation(release, tmp_path, change):
    state = tmp_path / 'state'
    profile = agent.create_agent('host', output=tmp_path / 'file', state_dir=state)
    settings = profile.directory / 'profile.json'
    record = json.loads(settings.read_text())
    record.update(change)
    settings.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        agent.load_agent_profile(profile.name, state_dir=state)


def test_latest_pointer_cannot_escape_state_directory(tmp_path):
    (tmp_path / 'latest').write_text('../outside')
    with pytest.raises(ValueError, match='Invalid agent name'):
        agent.load_agent_profile(state_dir=tmp_path)


def test_missing_agent_explains_first_step(tmp_path):
    with pytest.raises(ValueError, match='agent create HOST'):
        agent.load_agent_profile(state_dir=tmp_path)
    assert agent.list_agent_profiles(tmp_path) == []
