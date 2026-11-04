"""Check a prepared wheel from a separate environment with no Go on PATH."""
from __future__ import annotations

from pathlib import Path
import os
import site
import subprocess
import sys
import tempfile
import venv
import zipfile


def main():
    downloads = Path(sys.argv[1]).resolve()
    wheels = list(downloads.glob('reap-*.whl'))
    if len(wheels) != 1:
        raise SystemExit('Expected exactly one Reap wheel in the download directory')
    with tempfile.TemporaryDirectory(prefix='reap-installed-') as directory:
        root = Path(directory)
        # Reuse installed runtime dependencies, but force Reap itself into this venv.
        venv.EnvBuilder(system_site_packages=True, with_pip=True).create(root / 'venv')
        python = root / 'venv' / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
        package_dir = Path(subprocess.check_output([str(python), '-I', '-c',
                                                   'import site; print(site.getsitepackages()[0])'], text=True).strip())
        # When this checker runs inside a venv, system_site_packages alone does
        # not expose that venv's dependencies. Reap in the new venv still wins.
        (package_dir / 'verification-dependencies.pth').write_text('\n'.join(site.getsitepackages()) + '\n', encoding='utf-8')
        subprocess.run([str(python), '-m', 'pip', 'install', '--no-deps', '--force-reinstall', str(wheels[0])],
                       cwd=root, check=True)
        driver = root / 'verify.py'
        driver.write_text('''\
import json
import os
from pathlib import Path
import struct
import sys
import reap
from reap.agent import create_agent, load_agent_profile, prepare_bundle

environment = Path(__file__).parent
assert environment / 'venv' in Path(reap.__file__).parents, reap.__file__
root = environment / sys.argv[1]
root.mkdir()
os.environ['PATH'] = str(root / 'no-compiler')
for target, platform, arch in [('linux', 'linux', 'amd64'), ('linux-arm64', 'linux', 'arm64'), ('windows', 'windows', 'amd64')]:
    target_folder = root / ('target-' + target)
    target_folder.mkdir()
    output = target_folder / ('reap-agent.exe' if target == 'windows' else 'reap-agent')
    profile = create_agent('127.0.0.1', target=target, output=output, state_dir=root / 'private')
    assert profile.build_version == reap.__version__, profile
    assert list(target_folder.iterdir()) == [output]
    data = output.read_bytes()
    assert data[-12:-4] == b'REAPCFG1'
    size = struct.unpack('!I', data[-4:])[0]
    config = json.loads(data[-12-size:-12])
    assert config['connect'] == '127.0.0.1' and config['port'] == 7443
    assert load_agent_profile(profile.name, state_dir=root / 'private').output == output
    kit = prepare_bundle(root / (platform + '-' + arch), implementation='native', platform=platform, arch=arch)
    manifest = json.loads((kit / 'manifest.json').read_text())
    assert manifest['build_version'] == reap.__version__, manifest
    assert (kit / manifest['executable']).is_file()
print('Installed Reap creates one-file agents for every target without Go or the source checkout.')
''', encoding='utf-8')
        subprocess.run([str(python), '-I', str(driver), 'wheel-output'], cwd=root, check=True)
        archives = list(downloads.glob('reap-*-ready.zip'))
        if len(archives) > 1:
            raise SystemExit('Expected at most one prepared source ZIP')
        if archives:
            extracted = root / 'extracted'
            with zipfile.ZipFile(archives[0]) as archive:
                names = archive.namelist()
                if any(Path(name).is_absolute() or '..' in Path(name).parts for name in names):
                    raise SystemExit('Unsafe source ZIP member')
                archive.extractall(extracted)
            sources = list(extracted.iterdir())
            if len(sources) != 1 or not (sources[0] / 'install.sh').is_file():
                raise SystemExit('Prepared source ZIP must contain one Reap folder with install.sh')
            env = dict(os.environ, PATH=str(python.parent), GOTOOLCHAIN='local')
            subprocess.run([str(python), '-m', 'pip', 'install', '--no-deps', '--force-reinstall', str(sources[0])],
                           cwd=root, env=env, check=True)
            subprocess.run([str(python), '-I', str(driver), 'source-output'], cwd=root, check=True)


if __name__ == '__main__':
    main()
