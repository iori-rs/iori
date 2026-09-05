#!/usr/bin/env python3
"""Install one official Shaka release asset after verifying its published digest."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import urllib.request

VERSION = 'v3.9.3'
ASSETS = {
    ('Darwin', 'arm64'): ('packager-osx-arm64', 'b3049e743451aab5c2cd7b1316a4ce055682c41effe06a49e2e6c95a9243d351'),
    ('Darwin', 'x86_64'): ('packager-osx-x64', '64f0fece6a5f80603d9f19b3adc70e626303feb63b459fd599132632b8e76420'),
    ('Linux', 'x86_64'): ('packager-linux-x64', '7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6'),
    ('Linux', 'aarch64'): ('packager-linux-arm64', 'd3a50cecc139b54435be1bbbfba5c0ea822d9e1e7edc3531f7821fba65ceebb0'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('target/cenc-tools/packager'))
    args = parser.parse_args()
    asset, expected = ASSETS[(platform.system(), platform.machine())]
    url = f'https://github.com/shaka-project/shaka-packager/releases/download/{VERSION}/{asset}'
    data = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit('Shaka asset digest mismatch')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp = args.output.with_suffix('.download')
    temp.write_bytes(data)
    temp.chmod(0o755)
    os.replace(temp, args.output)
    print(args.output.resolve())


if __name__ == '__main__':
    main()
