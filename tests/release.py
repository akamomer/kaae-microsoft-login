#!/usr/bin/env python3
"""Exercise release automation with a fake gh process, never a real GitHub call."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from unittest.mock import patch

script = Path(__file__).resolve().parent.parent / 'tools' / 'prepare-release.py'
environment = {'GITHUB_REPOSITORY': 'example/plugin', 'GITHUB_SHA': 'a' * 40}
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

    def create_draft(command, **kwargs):
        calls.append(command)
        if command[1] == 'api':
            return subprocess.CompletedProcess(command, 0, stdout='[]\n[]')
        assert '--draft' in command, 'A published release was requested'
        assert command[command.index('--target') + 1] == environment['GITHUB_SHA']
        assert '--clobber' not in command
        return subprocess.CompletedProcess(command, 0)

    execute(create_draft)
    assert len(calls) == 2 and calls[1][1:3] == ['release', 'create']
    calls.clear()

    def existing(command, **kwargs):
        calls.append(command)
        header = (script.parent.parent / 'kaae-microsoft-login.php').read_text()
        import re
        version = re.search(r'^ \* Version: (\d+\.\d+\.\d+)$', header, re.MULTILINE).group(1)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps([{'tag_name': 'v' + version}]))

    execute(existing)
    assert len(calls) == 1, 'An existing release was modified'
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

print('3 offline release scenarios passed: draft creation, existing-release preservation, and API failure.')
