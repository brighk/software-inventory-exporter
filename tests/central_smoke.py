"""Mac/Linux integration test: central API, durable agent, Arch assessment fixtures."""
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

binary = str(pathlib.Path(sys.argv[1]).resolve())

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    upload_token = 'u' * 40
    read_token = 'r' * 40
    credentials = root / 'credentials.json'
    credentials.write_text(json.dumps({'read_token': read_token, 'hosts': {'arch-test': upload_token}}))
    database = root / 'inventory.db'
    fake_pacman = root / 'pacman'
    fake_pacman.write_text("#!/bin/sh\nprintf 'demo 1-1\\n'\n")
    fake_pacman.chmod(0o755)
    config = root / 'config.toml'
    config.write_text('interval_seconds=1\n[[collectors]]\nid="os"\nkind="pacman"\npath=' + json.dumps(str(fake_pacman)) + '\n')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    state = root / 'state.json'
    env = dict(os.environ, INVENTORY_TOKEN=upload_token)
    agent = [binary, '--config', str(config), 'agent', '--server', origin, '--host-id', 'arch-test',
             '--hostname', 'fixture', '--os', 'arch', '--os-version', 'rolling', '--state', str(state), '--once']

    def request(path, token=read_token, payload=None):
        req = urllib.request.Request(origin + path, headers={'Authorization': 'Bearer ' + token},
                                     data=None if payload is None else json.dumps(payload).encode())
        if payload is not None:
            req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=3) as response:
            return json.load(response)

    def expect_status(status, path, token=read_token, payload=None):
        try:
            request(path, token, payload)
        except urllib.error.HTTPError as error:
            assert error.code == status, (error.code, error.read())
        else:
            raise AssertionError(f'expected {status}')

    def run_agent(success=True):
        result = subprocess.run(agent, env=env, capture_output=True, text=True, timeout=10)
        assert (result.returncode == 0) == success, result.stderr

    # Persist a snapshot while server is unavailable. Restart must send the same payload.
    run_agent(False)
    pending = json.loads(state.read_text())['pending']
    assert pending['sequence'] == 1
    fake_pacman.write_text("#!/bin/sh\nprintf 'demo 2-1\\n'\n")
    with subprocess.Popen([binary, 'server', '--database', str(database), '--credentials', str(credentials),
                           '--listen', f'127.0.0.1:{port}'], stderr=subprocess.PIPE) as server:
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    request('/v1/hosts')
                    break
                except OSError:
                    assert time.monotonic() < deadline, 'server failed to start'
                    time.sleep(.05)
            expect_status(401, '/v1/hosts', upload_token)
            expect_status(401, '/v1/inventory', read_token, pending)
            forged = json.loads(json.dumps(pending))
            forged['host']['id'] = 'another-host'
            expect_status(401, '/v1/inventory', upload_token, forged)
            run_agent()
            assert request('/v1/installations')['installations'][0]['version'] == '1-1'
            assert request('/v1/inventory', upload_token, pending)['duplicate']
            forged = json.loads(json.dumps(pending))
            forged['host']['hostname'] = 'different'
            expect_status(409, '/v1/inventory', upload_token, forged)
            assert request('/v1/findings')['assessments'][0]['status'] == 'not_assessed'
            feed = root / 'feed.json'
            feed.write_text(json.dumps([dict(name='AVG-TEST', packages=['demo'], status='Fixed', severity='High',
                                             affected='1-1', fixed='2-1', issues=['CVE-TEST'])]))
            assess = [binary, 'assess', '--database', str(database), '--feed-file', str(feed), '--once']
            subprocess.run(assess, check=True, capture_output=True, timeout=10)
            assert request('/v1/findings')['assessments'][0]['status'] == 'affected'
            assert request('/v1/assessment-status')['success']
            run_agent()
            assert request('/v1/installations?host_id=arch-test&name=demo')['installations'][0]['version'] == '2-1'
            assert request('/v1/findings')['assessments'][0]['status'] == 'not_assessed'
            subprocess.run(assess, check=True, capture_output=True, timeout=10)
            assert request('/v1/findings')['assessments'][0]['status'] == 'no_known_match'
            # Repeat version: assessment becomes pending because the inventory sequence advanced.
            run_agent()
            assert request('/v1/findings')['assessments'][0]['status'] == 'pending'
            subprocess.run(assess, check=True, capture_output=True, timeout=10)
            feed.write_text('broken')
            assert subprocess.run(assess, capture_output=True, timeout=10).returncode != 0
            assert not request('/v1/assessment-status')['success']
            assert request('/v1/assessment-status')['last_success'] is not None
            fake_pacman.write_text('#!/bin/sh\nexit 1\n')
            run_agent(False)
            row = request('/v1/installations')['installations'][0]
            assert row['version'] == '2-1' and not row['collector_success']
            assert request('/v1/findings')['assessments'][0]['status'] == 'stale_inventory'
            assert not request('/v1/collectors?host_id=arch-test')['collectors'][0]['success']
            fake_pacman.write_text('#!/bin/sh\nexit 0\n')
            run_agent()
            assert request('/v1/installations')['installations'] == []
            assert request('/v1/findings')['assessments'] == []
            expect_status(400, '/v1/installations?limit=1001')
            invalid = json.loads(json.dumps(pending))
            invalid['sequence'] = 999
            invalid['inventory']['schema_version'] = 99
            expect_status(400, '/v1/inventory', upload_token, invalid)
            assert request('/v1/hosts')['hosts'][0]['last_sequence'] == 5
        finally:
            server.terminate()
            server.wait(timeout=5)
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM scans').fetchone()[0] == 5
    assert json.loads(state.read_text())['pending'] is None
print('Central API, durable submission, and Arch assessment smoke tests passed')
