#!/usr/bin/env python3
"""Make a prepared source ZIP from verified agents and application source only."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    options = parser.parse_args()
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / 'reap/__init__.py').read_text()).group(1)
    spec = importlib.util.spec_from_file_location('native_release_build', ROOT / 'native-agent/build.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    # An explicit application-only allowlist keeps engagement data, environments,
    # Git metadata, and target profiles out of the ready-to-use download.
    files = [ROOT / name for name in ('pyproject.toml', 'README.md', 'USAGE.md', 'AGENT_QUICKSTART.md',
                                     'CHANGELOG.md', 'LICENSE', 'install.sh', 'native-agent/README.md')]
    files.extend(path for path in (ROOT / 'reap').rglob('*')
                 if path.is_file() and path.suffix in ('.py', '.txt', '.sql')
                 and '__pycache__' not in path.parts and 'native' not in path.relative_to(ROOT / 'reap').parts)
    for path in files:
        if not path.is_file():
            parser.error('release source is missing %s' % path)
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / ('reap-%s-ready.zip' % version)
    with tempfile.TemporaryDirectory(prefix='reap-release-check-') as directory:
        verified = Path(directory)
        builder.package_artifacts(ROOT / 'reap/data/native', verified, version)
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as target:
            prefix = 'reap-%s/' % version
            for path in sorted(files):
                target.write(path, prefix + path.relative_to(ROOT).as_posix())
            for path in sorted(verified.iterdir()):
                target.write(path, prefix + 'reap/data/native/' + path.name)
    print(archive)


if __name__ == '__main__':
    main()
