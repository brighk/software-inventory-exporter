"""Create an isolated macOS/Linux development setup. Never overwrites existing data."""
import json
import pathlib
import secrets

root = pathlib.Path('dev-data').resolve()
root.mkdir(mode=0o700)
credentials = {'read_token': secrets.token_hex(32), 'hosts': {'mac-dev': secrets.token_hex(32), 'arch-01': secrets.token_hex(32)}}
path = root / 'credentials.json'
path.write_text(json.dumps(credentials, indent=2) + '\n')
path.chmod(0o600)
modules = root / 'node_modules' / 'demo'
modules.mkdir(parents=True)
(modules / 'package.json').write_text('{"name":"demo","version":"1.0.0"}\n')
(root / 'mac.toml').write_text('interval_seconds = 15\n[[collectors]]\nid = "dev-node"\nkind = "npm"\npath = ' + json.dumps(str(modules.parent)) + '\n')
print('Created dev-data with credentials and a synthetic npm installation.')
print('Follow docs/central-inventory.md to start the server and agent.')
