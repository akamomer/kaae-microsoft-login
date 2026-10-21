#!/usr/bin/env python3
"""Publish the tested plugin version in GitHub Actions without replacing releases."""
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
existing = None
while remaining:
    page, end = decoder.raw_decode(remaining)
    for release in page:
        if release.get('tag_name') == tag:
            existing = release
    remaining = remaining[end:].lstrip()
if existing and not existing.get('draft', False):
    print(f'Release {tag} is already published; leaving it unchanged. Bump the plugin version for another release.')
    raise SystemExit(0)
source_commit = commit
if existing:
    source_commit = existing.get('target_commitish', '')
    if not re.fullmatch(r'[a-f0-9]{40}', source_commit):
        raise SystemExit('The existing draft must target an immutable source commit')
    if not any(asset.get('name') == 'kaae-microsoft-login.zip' and asset.get('state') == 'uploaded' and asset.get('size', 0) > 0 for asset in existing.get('assets', [])):
        raise SystemExit('The existing draft is missing its complete plugin ZIP; refusing to publish')
    if source_commit != commit:
        comparison = subprocess.run(['gh', 'api', f'repos/{repository}/compare/{source_commit}...{commit}'], capture_output=True, text=True, check=True)
        changes = json.loads(comparison.stdout)
        automation_files = {'.github/workflows/release.yml', 'tools/prepare-release.py', 'tests/release.py', 'README.md'}
        if changes.get('status') not in ('ahead', 'identical') or any(file['filename'] not in automation_files for file in changes.get('files', [])):
            raise SystemExit('Plugin code changed since this draft was built. Bump the version to publish a new package.')
notes = (
    f'KAAE Microsoft Login {version}\n\n'
    'Microsoft staff sign-in, automatic Subscriber onboarding, individual password preferences, '
    'and administrator-managed external-account password exceptions.\n\n'
    'Adds Users → KAAE Staff for administrator-delegated directory browsing, selected Subscriber enrollment, '
    'local blocking/unblocking with session revocation, and an optional Approved staff only policy. '
    'Directory browsing requires delegated User.ReadBasic.All consent. Existing access policy stays unchanged until configured.\n\n'
    'Preserves the validated WordPress redirect_to destination through Microsoft sign-in, '
    'including report filters, while keeping the registered callback and profile-linking behavior unchanged.\n\n'
    'WordPress Dashboard → Updates → Check again now refreshes GitHub release metadata immediately.\n\n'
    'Install the attached kaae-microsoft-login.zip through WordPress. Configure Microsoft settings '
    'separately on each site. Read the setup guide and test the sign-in paths before enabling new policies.\n\n'
    f'Source commit: {source_commit}\n'
    f'Setup and validation: https://github.com/{repository}/blob/{source_commit}/README.md\n\n'
    'Published after automated tests. Available through the plugin’s Check for updates and WordPress Updates.\n'
)
with tempfile.TemporaryDirectory(prefix='kaae-ms-notes-') as temporary:
    notes_path = Path(temporary) / 'notes.md'
    notes_path.write_text(notes)
    if not existing:
        # Upload the complete asset before making the release visible to WordPress.
        subprocess.run([
            'gh', 'release', 'create', tag, str(args.package.resolve()),
            '--repo', repository, '--target', commit, '--draft',
            '--title', f'KAAE Microsoft Login {version}', '--notes-file', str(notes_path),
        ], check=True)
    subprocess.run([
        'gh', 'release', 'edit', tag, '--repo', repository,
        '--draft=false', '--prerelease=false', '--latest', '--notes-file', str(notes_path),
    ], check=True)
print(f'Release {tag} published with its plugin ZIP. WordPress can now detect it.')
