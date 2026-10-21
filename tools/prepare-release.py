#!/usr/bin/env python3
"""Create a draft release in GitHub Actions; never publish or replace a release."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--package', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
version_match = re.search(r'^ \* Version: (\d+\.\d+\.\d+)$', (root / 'kaae-microsoft-login.php').read_text(), re.MULTILINE)
repository = os.environ.get('GITHUB_REPOSITORY', '')
commit = os.environ.get('GITHUB_SHA', '')
if not version_match or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[a-f0-9]{40}', commit):
    raise SystemExit('Valid plugin version, GITHUB_REPOSITORY and GITHUB_SHA are required')
if args.package.name != 'kaae-microsoft-login.zip' or not args.package.is_file():
    raise SystemExit('Expected the built kaae-microsoft-login.zip asset')
version = version_match.group(1)
tag = f'v{version}'
# Distinguish a missing release from permission/network errors. Never overwrite assets.
result = subprocess.run(['gh', 'api', f'repos/{repository}/releases', '--paginate'], capture_output=True, text=True, check=True)
# gh --paginate emits one JSON array per page; parse each without relying on page size.
decoder = json.JSONDecoder()
remaining = result.stdout.strip()
while remaining:
    page, end = decoder.raw_decode(remaining)
    if any(release.get('tag_name') == tag for release in page):
        print(f'Release {tag} already exists; leaving it unchanged. Bump the plugin version to prepare another release.')
        raise SystemExit(0)
    remaining = remaining[end:].lstrip()
notes = (
    f'KAAE Microsoft Login {version}\n\n'
    'Microsoft staff sign-in, automatic Subscriber onboarding, individual password preferences, '
    'and administrator-managed external-account password exceptions.\n\n'
    'Install the attached kaae-microsoft-login.zip through WordPress. Configure Microsoft settings '
    'separately on each site. Read the setup guide and test the sign-in paths before enabling new policies.\n\n'
    f'Source commit: {commit}\n'
    f'Setup and validation: https://github.com/{repository}/blob/{commit}/README.md\n\n'
    'This is a draft. Review it before publishing. WordPress update checks ignore draft releases.\n'
)
with tempfile.TemporaryDirectory(prefix='kaae-ms-notes-') as temporary:
    notes_path = Path(temporary) / 'notes.md'
    notes_path.write_text(notes)
    subprocess.run([
        'gh', 'release', 'create', tag, str(args.package.resolve()),
        '--repo', repository, '--target', commit, '--draft',
        '--title', f'KAAE Microsoft Login {version}', '--notes-file', str(notes_path),
    ], check=True)
print(f'Draft {tag} prepared. Publish it from GitHub Releases when approved.')
