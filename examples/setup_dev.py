"""Create an isolated local development setup in dev-data/. Never overwrites existing data.

Generates a read token, an upload token for host dev-01 and a synthetic npm package to
inventory. See docs/operations.md#local-development.
"""
import json
import pathlib
import secrets

root = pathlib.Path('dev-data').resolve()
root.mkdir(mode=0o700)
credentials = {'read_token': secrets.token_hex(32), 'hosts': {'dev-01': secrets.token_hex(32)}}
path = root / 'credentials.json'
path.write_text(json.dumps(credentials, indent=2) + '\n')
path.chmod(0o600)
modules = root / 'node_modules' / 'demo'
modules.mkdir(parents=True)
(modules / 'package.json').write_text('{"name":"demo","version":"1.0.0"}\n')
(root / 'dev.toml').write_text('interval_seconds = 15\n[[collectors]]\nid = "dev-node"\nkind = "npm"\npath = '
                               + json.dumps(str(modules.parent)) + '\n')
print('Created dev-data/ with credentials and a synthetic npm installation.')
print('Next: docs/operations.md#local-development')
