"""The user-facing one-file workflow, including a real target executable."""
from __future__ import annotations

import concurrent.futures
import io
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from rich.console import Console

from reap.agent import load_agent_profile
from reap.console import ReapConsole
from tests.test_agent import unused_port, wait_listening


@pytest.fixture
def agent_console(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('REAP_AGENT_HOME', str(tmp_path / 'private-settings'))
    console = ReapConsole(str(tmp_path / 'test.reap.db'))
    output = io.StringIO()
    console.console = Console(file=output, width=200, color_system=None)
    yield console, output
    console.do_exit('')


def require_templates():
    from reap import agent
    try:
        platform, arch = ('windows', 'amd64') if os.name == 'nt' else ('linux', 'amd64')
        agent._native_artifact(platform, arch, None)
    except ValueError:
        pytest.skip('prepared agent templates are not available in this developer checkout')


def test_guided_setup_gives_copyable_instructions_and_saved_navigation(agent_console, monkeypatch):
    require_templates()
    console, output = agent_console
    answers = iter(['10.10.14.2', ''])
    monkeypatch.setattr('builtins.input', lambda prompt: next(answers))
    console.do_agent('')
    profile = load_agent_profile()
    assert profile.callback == '10.10.14.2' and profile.target == 'linux'
    assert profile.executable.name == 'reap-agent' and profile.executable.is_file()
    text = output.getvalue()
    assert 'Copy this ONE file' in text and './reap-agent' in text
    assert 'agent listen ' + profile.name in text
    assert 'token.txt' not in text and '--token-file' not in text
    console.do_agent('list')
    console.do_agent('show')
    console.do_agent('show ' + profile.name)
    assert 'Saved agents' in output.getvalue()
    assert (profile.authkit / 'token.txt').read_text().strip() not in output.getvalue()


def test_single_copied_file_connects_without_flags_or_companions(agent_console, tmp_path):
    require_templates()
    console, output = agent_console
    port = unused_port()
    target = 'windows' if os.name == 'nt' else 'linux'
    filename = 'my agent.exe' if os.name == 'nt' else 'my agent'
    console.do_agent('create 127.0.0.1 --target %s --port %s --output "%s"' % (target, port, filename))
    profile = load_agent_profile()
    target_dir = tmp_path / 'target-only-one-file'
    target_dir.mkdir()
    copied = target_dir / filename
    shutil.copyfile(profile.executable, copied)
    copied.chmod(0o700)
    assert list(target_dir.iterdir()) == [copied]
    process = None
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        listener = pool.submit(console.do_agent, 'listen')
        try:
            wait_listening(port)
            process = subprocess.Popen([str(copied)], cwd=target_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Registration includes Windows CIM/process fingerprinting, whose
            # bounded requests can take longer than the TLS connection itself.
            listener.result(timeout=90 if os.name == 'nt' else 15)
            assert console.active is not None, output.getvalue()
            session = console.sessions[console.active]
            assert session.exec('echo one-file-works').stdout.strip() == 'one-file-works'
            assert session.is_alive()
            console.do_exit('')
            assert process.wait(timeout=5) == 0, process.communicate()
            assert list(target_dir.iterdir()) == [copied]
        finally:
            if process:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


def test_help_and_invalid_setup_are_plain_and_do_not_create_files(agent_console, monkeypatch):
    console, output = agent_console
    console.do_agent('help')
    assert 'Connect another machine' in output.getvalue()
    console.do_agent('listen')
    assert 'No saved agent' in output.getvalue()
    answers = iter(['10.10.14.2', 'banana'])
    monkeypatch.setattr('builtins.input', lambda prompt: next(answers))
    console.do_agent('')
    assert 'Choose 1, 2 or 3' in output.getvalue()
    assert not Path('reap-agent').exists()


def test_existing_default_python_kit_command_still_works(agent_console, tmp_path):
    console, output = agent_console
    console.do_agent('prepare old-kit')
    assert (tmp_path / 'old-kit/reap_agent.py').is_file()
    assert 'Created kit:' in output.getvalue()
