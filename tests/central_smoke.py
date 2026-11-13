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
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Fake NVD CVE API 2.0. mode 'ok' serves a record; '429' simulates rate limiting.
nvd = {'mode': 'ok', 'requests': []}


class FakeNvd(BaseHTTPRequestHandler):
    def do_GET(self):
        cve = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)['cveId'][0]
        nvd['requests'].append(cve)
        if nvd['mode'] == 'flaky':
            nvd['mode'] = 'ok'  # fail once, then recover
            self.send_response(503)
            self.end_headers()
            return
        if nvd['mode'] == '429':
            self.send_response(429)
            self.end_headers()
            return
        body = json.dumps({'totalResults': 1, 'vulnerabilities': [{'cve': {
            'id': cve, 'vulnStatus': 'Analyzed', 'descriptions': [{'lang': 'en', 'value': 'test'}],
            'metrics': {'cvssMetricV31': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {
                'version': '3.1', 'baseScore': 9.8, 'baseSeverity': 'CRITICAL', 'vectorString': 'CVSS:3.1/AV:N'}}]}}}]})
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


nvd_server = ThreadingHTTPServer(('127.0.0.1', 0), FakeNvd)
threading.Thread(target=nvd_server.serve_forever, daemon=True).start()
nvd_url = f'http://127.0.0.1:{nvd_server.server_address[1]}/rest/json/cves/2.0'

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
                                             affected='1-1', fixed='2-1', issues=['CVE-TEST', 'CVE-2024-12345'])]))
            assess = [binary, 'assess', '--database', str(database), '--feed-file', str(feed), '--once',
                      '--nvd-url', nvd_url]
            subprocess.run(assess, check=True, capture_output=True, timeout=10)
            assert request('/v1/findings')['assessments'][0]['status'] == 'affected'
            # Status filtering happens in SQL, so pagination sees only matching rows.
            assert len(request('/v1/findings?status=affected,needs_review')['assessments']) == 1
            assert request('/v1/findings?status=no_known_match')['assessments'] == []
            expect_status(400, '/v1/findings?status=bogus')
            expect_status(400, '/v1/installations?status=affected')
            expect_status(401, '/metrics', upload_token)
            req = urllib.request.Request(origin + '/metrics', headers={'Authorization': 'Bearer ' + read_token})
            with urllib.request.urlopen(req, timeout=3) as response:
                metrics = response.read().decode()
            assert 'software_inventory_package_info{host_id="arch-test",hostname="fixture",collector="os",name="demo",version="1-1",status="affected"} 1' in metrics, metrics
            assert 'advisory="AVG-TEST"' in metrics and 'fixed_version="2-1",patch_available="true"' in metrics, metrics
            assert 'software_inventory_assessment_success 1' in metrics, metrics
            assert request('/v1/assessment-status')['success']
            # NVD enrichment: only the valid CVE ID is looked up; score shows in API and metrics.
            assert nvd['requests'] == ['CVE-2024-12345'], nvd['requests']
            cvss = request('/v1/findings?status=affected')['assessments'][0]['findings'][0]['cvss']
            assert (cvss['cve'], cvss['score'], cvss['severity'], cvss['primary']) == ('CVE-2024-12345', 9.8, 'CRITICAL', True), cvss
            with urllib.request.urlopen(req, timeout=3) as response:
                metrics = response.read().decode()
            assert 'cvss_score="9.8",cvss_severity="CRITICAL",cvss_version="3.1",cvss_cve="CVE-2024-12345"' in metrics, metrics
            assert 'software_inventory_vulnerability_cvss_score{host_id="arch-test",hostname="fixture",name="demo",version="1-1",advisory="AVG-TEST"} 9.8' in metrics, metrics
            assert 'software_inventory_nvd_success 1' in metrics and 'software_inventory_nvd_pending_cves 0' in metrics, metrics
            # Cached: a second pass makes no request.
            subprocess.run(assess, check=True, capture_output=True, timeout=10)
            assert len(nvd['requests']) == 1, nvd['requests']
            # Forced refresh while rate limited: pass fails visibly, cached score is kept.
            nvd['mode'] = '429'
            time.sleep(2.1)  # timestamps are whole seconds
            result = subprocess.run(assess + ['--nvd-refresh-seconds', '1'], capture_output=True, text=True, timeout=10)
            assert result.returncode != 0 and '429' in result.stderr, result.stderr
            assert len(nvd['requests']) == 2, nvd['requests']
            assert request('/v1/findings?status=affected')['assessments'][0]['findings'][0]['cvss']['score'] == 9.8
            with urllib.request.urlopen(req, timeout=3) as response:
                assert 'software_inventory_nvd_success 0' in response.read().decode()
            # A transient 503 is retried for the same CVE instead of ending the pass.
            nvd['mode'] = 'flaky'
            time.sleep(2.1)
            result = subprocess.run(assess + ['--nvd-refresh-seconds', '1'], capture_output=True, text=True, timeout=30)
            assert result.returncode == 0 and 'NVD attempt 1' in result.stderr, result.stderr
            assert len(nvd['requests']) == 4, nvd['requests']
            with urllib.request.urlopen(req, timeout=3) as response:
                assert 'software_inventory_nvd_success 1' in response.read().decode()
            run_agent()
            assert request('/v1/installations?host_id=arch-test&name=demo')['installations'][0]['version'] == '2-1'
            assert request('/v1/findings')['assessments'][0]['status'] == 'not_assessed'
            subprocess.run(assess, check=True, capture_output=True, timeout=10)
            assert request('/v1/findings')['assessments'][0]['status'] == 'no_known_match'
            assert request('/v1/findings?status=affected')['assessments'] == []
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
