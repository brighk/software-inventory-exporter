"""End-to-end fixture: HTTP, replacement, deletion, failure retention, responsiveness.
Run after cargo build: python3 tests/smoke.py target/debug/software-inventory-exporter
Requires Python standard library only. Does not modify host installations.
"""
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

binary = pathlib.Path(sys.argv[1]).resolve()

def wait_for(check, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if check():
                return
        except (OSError, KeyError):
            pass
        time.sleep(0.05)
    raise AssertionError("condition timed out")

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    meta = root / 'python' / 'demo-1.dist-info'
    meta.mkdir(parents=True)
    metadata = meta / 'METADATA'
    metadata.write_text('Name: demo\nVersion: 1.0\n')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    config = root / 'config.toml'
    config.write_text(f'''listen = "127.0.0.1:{port}"
interval_seconds = 1
timeout_seconds = 1
[[collectors]]
id = "test-python"
kind = "python"
path = {json.dumps(str(meta.parent))}
''')
    def get(path):
        return urllib.request.urlopen(f'http://127.0.0.1:{port}{path}', timeout=1)
    def state():
        with get('/inventory') as response:
            return json.load(response)['collectors']['test-python']
    with subprocess.Popen([str(binary), '--config', str(config), 'serve'], stderr=subprocess.PIPE) as server:
        try:
            wait_for(lambda: state()['success'])
            with get('/metrics') as response:
                assert 'version=0.0.4' in response.headers['Content-Type']
                assert b'version="1.0"' in response.read()
            with get('/readyz') as response:
                assert response.status == 200
            initial_id = state()['software'][0]['installation_id']
            metadata.write_text('Name: demo\nVersion: 2.0\n')
            wait_for(lambda: state()['software'][0]['version'] == '2.0')
            assert state()['software'][0]['installation_id'] == initial_id
            metadata.write_text('broken metadata')
            wait_for(lambda: not state()['success'])
            assert state()['software'][0]['version'] == '2.0'
            with get('/metrics') as response:
                assert b'host_software_collector_success{scope="test-python",source="python"} 0' in response.read()
            metadata.unlink()
            meta.rmdir()
            wait_for(lambda: state()['success'] and state()['software'] == [])
            with get('/metrics') as response:
                assert b'name="demo"' not in response.read()
            try:
                get('/missing')
            except urllib.error.HTTPError as error:
                assert error.code == 404
            else:
                raise AssertionError('expected 404')
        finally:
            server.terminate()
            server.wait(timeout=5)
    # A failed collector produces structured JSON and exit code 2.
    meta.parent.rmdir()
    result = subprocess.run([str(binary), '--config', str(config), 'scan'], capture_output=True, text=True)
    assert result.returncode == 2
    assert not json.loads(result.stdout)['collectors']['test-python']['success']
print('HTTP and CLI smoke tests passed')
