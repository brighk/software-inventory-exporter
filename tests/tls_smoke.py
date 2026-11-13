"""Agent HTTPS test: a server certificate from a private CA is rejected by default and
accepted with --ca-cert. Requires the openssl CLI. Usage: tls_smoke.py <binary>"""
import json
import os
import pathlib
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

binary = str(pathlib.Path(sys.argv[1]).resolve())
received = []


class FakeServer(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        received.append(body)
        reply = json.dumps({'accepted': True, 'sequence': body['sequence'], 'duplicate': False}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


def openssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Test CA',
            '-keyout', 'ca.key', '-out', 'ca.pem', cwd=root)
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
            '-keyout', 'server.key', '-out', 'server.csr', cwd=root)
    (root / 'san.ext').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
            '-days', '1', '-extfile', 'san.ext', '-out', 'server.pem', cwd=root)

    server = ThreadingHTTPServer(('127.0.0.1', 0), FakeServer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    pacman = root / 'pacman'
    pacman.write_text("#!/bin/sh\nprintf 'demo 1-1\\n'\n")
    pacman.chmod(0o755)
    config = root / 'config.toml'
    config.write_text('[[collectors]]\nid="os"\nkind="pacman"\npath=' + json.dumps(str(pacman)) + '\n')
    agent = [binary, '--config', str(config), 'agent', '--server', f'https://localhost:{server.server_address[1]}',
             '--host-id', 'tls-test', '--hostname', 'fixture', '--os', 'arch', '--os-version', 'rolling',
             '--state', str(root / 'state.json'), '--once']
    env = dict(os.environ, INVENTORY_TOKEN='t' * 40)

    untrusted = subprocess.run(agent, env=env, capture_output=True, text=True, timeout=30)
    assert untrusted.returncode != 0 and not received, untrusted.stderr
    # The pending snapshot is retained and delivered once the CA is trusted.
    trusted = subprocess.run(agent + ['--ca-cert', str(root / 'ca.pem')], env=env, capture_output=True,
                             text=True, timeout=30)
    assert trusted.returncode == 0, trusted.stderr
    assert len(received) == 1 and received[0]['sequence'] == 1, received
    empty = root / 'empty.pem'
    empty.write_text('')
    bad = subprocess.run(agent + ['--ca-cert', str(empty)], env=env, capture_output=True, text=True, timeout=30)
    assert bad.returncode != 0 and 'no certificates' in bad.stderr, bad.stderr
    server.shutdown()

print('Agent TLS and custom CA smoke tests passed')
