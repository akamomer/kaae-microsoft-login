#!/usr/bin/env python3
"""Exercise release automation with a fake gh process, never a real GitHub call."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import re
import subprocess
import sys
import tempfile
from unittest.mock import patch

script = Path(__file__).resolve().parent.parent / 'tools' / 'prepare-release.py'
environment = {'GITHUB_REPOSITORY': 'example/plugin', 'GITHUB_SHA': 'a' * 40}
version = re.search(r'^ \* Version: (\d+\.\d+\.\d+)$', (script.parent.parent / 'kaae-microsoft-login.php').read_text(), re.MULTILINE).group(1)
with tempfile.TemporaryDirectory() as temporary:
    package = Path(temporary) / 'kaae-microsoft-login.zip'
    package.write_bytes(b'offline-test')

    def execute(fake):
        with patch.dict('os.environ', environment, clear=True), patch.object(sys, 'argv', [str(script), '--package', str(package)]), patch('subprocess.run', side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
            try:
                runpy.run_path(str(script), run_name='__main__')
            except SystemExit as error:
                if error.code not in (None, 0):
                    raise

    calls = []

    def create_and_publish(command, **kwargs):
        calls.append(command)
        if command[1] == 'api':
            return subprocess.CompletedProcess(command, 0, stdout='[]\n[]')
        if command[2] == 'create':
            assert '--draft' in command, 'Release was exposed before its ZIP finished uploading'
            assert command[command.index('--target') + 1] == environment['GITHUB_SHA']
        else:
            assert command[2] == 'edit' and '--draft=false' in command and '--latest' in command
        assert '--clobber' not in command
        return subprocess.CompletedProcess(command, 0)

    execute(create_and_publish)
    assert len(calls) == 3 and calls[1][1:3] == ['release', 'create'] and calls[2][1:3] == ['release', 'edit']
    calls.clear()

    def existing(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps([{'tag_name': 'v' + version, 'draft': False}]))

    execute(existing)
    assert len(calls) == 1, 'An existing release was modified'
    calls.clear()

    draft = {'tag_name': 'v' + version, 'draft': True, 'target_commitish': environment['GITHUB_SHA'], 'assets': [{'name': 'kaae-microsoft-login.zip', 'state': 'uploaded', 'size': 123}]}

    def publish_existing(command, **kwargs):
        calls.append(command)
        if command[1] == 'api':
            if '/compare/' in command[2]:
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps({'status': 'ahead', 'files': [{'filename': 'tools/prepare-release.py'}]}))
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps([draft]))
        assert command[1:3] == ['release', 'edit'] and '--draft=false' in command and '--latest' in command
        assert '--clobber' not in command
        return subprocess.CompletedProcess(command, 0)

    execute(publish_existing)
    assert len(calls) == 2, 'Existing complete draft was not published directly'
    calls.clear()
    draft['target_commitish'] = 'b' * 40
    execute(publish_existing)
    assert len(calls) == 3 and '/compare/' in calls[1][2], 'Automation-only draft change was not verified'
    calls.clear()

    def reject_runtime_change(command, **kwargs):
        if command[1] == 'api' and '/compare/' in command[2]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({'status': 'ahead', 'files': [{'filename': 'includes/class-kaae-login.php'}]}))
        return publish_existing(command, **kwargs)

    try:
        execute(reject_runtime_change)
    except SystemExit as error:
        assert error.code not in (None, 0)
    else:
        raise AssertionError('Outdated draft with runtime changes was published')
    assert len(calls) == 2
    calls.clear()
    draft['assets'] = []
    try:
        execute(publish_existing)
    except SystemExit as error:
        assert error.code not in (None, 0)
    else:
        raise AssertionError('Draft missing ZIP was published')
    assert len(calls) == 1
    calls.clear()

    def denied(command, **kwargs):
        calls.append(command)
        raise subprocess.CalledProcessError(1, command)

    try:
        execute(denied)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('GitHub API failure was ignored')
    assert len(calls) == 1, 'Release creation continued after API failure'
    calls.clear()

    def upload_failed(command, **kwargs):
        calls.append(command)
        if command[1] == 'api':
            return subprocess.CompletedProcess(command, 0, stdout='[]')
        raise subprocess.CalledProcessError(1, command)

    try:
        execute(upload_failed)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('Failed asset upload was ignored')
    assert len(calls) == 2 and calls[-1][2] == 'create', 'Incomplete upload was published'

print('8 offline release scenarios passed: upload before publication, immutable published versions, verified drafts, and failure handling.')
