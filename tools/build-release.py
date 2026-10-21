#!/usr/bin/env python3
"""Build a release asset without loading WordPress or including site secrets."""
import argparse
from pathlib import Path
import re
from zipfile import ZipFile, ZIP_DEFLATED

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
header = (root / 'kaae-microsoft-login.php').read_text()
version = re.search(r'^ \* Version: (\d+\.\d+\.\d+)$', header, re.MULTILINE)
if not version:
    raise SystemExit('Missing stable plugin version')
files = [root / 'kaae-microsoft-login.php', root / 'README.md']
files.extend(sorted((root / 'includes').glob('*.php')))
args.output_dir.mkdir(parents=True, exist_ok=True)
destination = args.output_dir / 'kaae-microsoft-login.zip'
with ZipFile(destination, 'w', ZIP_DEFLATED) as archive:
    for source in files:
        archive.write(source, str(Path('kaae-microsoft-login') / source.relative_to(root)))
with ZipFile(destination) as archive:
    if archive.testzip() is not None:
        raise SystemExit('ZIP integrity failure')
print(f'Version {version.group(1)}: {destination}')
