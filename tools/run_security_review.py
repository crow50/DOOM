#!/usr/bin/env python3
"""Run the container suite in a disposable copy, with unique images/volumes.

Never reads the operator's .env, secrets, uploads or backups. Logs redact the
generated test secrets. Always removes only this run's Compose project.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import re
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        parser.error('output must be outside the source tree')
    output.mkdir(parents=True, exist_ok=False)
    project = 'doomreview-' + uuid.uuid4().hex[:12]
    results = []
    with tempfile.TemporaryDirectory(prefix=project + '-') as temp:
        work = Path(temp) / 'source'
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
            '.git', '.env', 'secrets', 'uploads', 'backups', 'certs',
            '__pycache__', '.pytest_cache', '.venv'))
        http, https = free_port(), free_port()
        while http == https:
            https = free_port()
        override = work / 'review.yml'
        override.write_text(f'''services:
  caddy:
    ports: !override
      - "127.0.0.1:{http}:80"
      - "127.0.0.1:{https}:443"
    environment:
      HTTPS_PORT: "{https}"
  web:
    image: {project}-web
  test:
    image: {project}-test
''')
        compose = ['docker', 'compose', '-p', project, '-f', 'docker-compose.yml', '-f', 'review.yml']
        # Retain transport credentials for Docker, not application configuration
        # or Compose overrides inherited from the operator's environment.
        env = {key: value for key, value in os.environ.items() if key in (
            'PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
            'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'SSH_AUTH_SOCK',
            'XDG_RUNTIME_DIR', 'LANG', 'TMPDIR')}
        env['COMPOSE_PROJECT_NAME'] = project

        def run(name, command):
            try:
                result = subprocess.run(command, cwd=work, env=env, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        timeout=1200)
                log, code = result.stdout, result.returncode
            except subprocess.TimeoutExpired as exc:
                raw = exc.stdout or ''
                log = raw.decode(errors='replace') if isinstance(raw, bytes) else raw
                log += '\nTIMEOUT: verification did not complete.\n'
                code = 124
            for secret in (work / 'secrets').glob('*'):
                if secret.is_file() and secret.name != 'redis.conf':
                    value = secret.read_text().strip()
                    if value:
                        log = log.replace(value, '[redacted test secret]')
            (output / f'{name}.txt').write_text(log)
            results.append({'name': name, 'exit_code': code})
            print(f'{name}: exit {code}', flush=True)
            return code == 0

        try:
            if not run('init', ['make', 'init']):
                return 1
            config = work / '.env'
            lines = config.read_text().splitlines()
            lines = [f'PUBLIC_BASE_URL=https://localhost:{https}' if line.startswith('PUBLIC_BASE_URL=') else line for line in lines]
            config.write_text('\n'.join(lines) + '\n')
            if not run('start', compose + ['up', '-d', '--build', '--wait']):
                return 1
            for target in ('upgrade', 'seed', 'test', 'verify-db-roles', 'verify-secrets', 'verify-test-count'):
                if not run(target, ['make', 'COMPOSE=' + ' '.join(compose), target]):
                    return 1
            certificate = subprocess.check_output(compose + ['exec', '-T', 'caddy',
                'cat', '/data/caddy/pki/authorities/local/root.crt'], cwd=work, env=env)
            ca = work / 'review-ca.crt'
            ca.write_bytes(certificate)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
            probes = []
            for path in ('/healthz', '/login'):
                with opener.open(f'https://localhost:{https}{path}', timeout=15) as response:
                    headers = dict(response.headers)
                    cookie = response.headers.get('Set-Cookie', '')
                    if path == '/login':
                        assert cookie.startswith('__Host-doom_session=')
                        assert all(flag in cookie for flag in ('Secure', 'HttpOnly', 'Path=/', 'SameSite=Lax'))
                    assert response.status == 200
                    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
                    assert response.headers.get('Strict-Transport-Security')
                    headers = {k: re.sub(r'^([^=]+=)[^;]+', r'\1[redacted]', v)
                               if k.lower() == 'set-cookie' else v for k, v in headers.items()}
                    probes.append({'path': path, 'status': response.status, 'headers': headers})
            (output / 'proxy.json').write_text(json.dumps(probes, indent=2) + '\n')
            results.append({'name': 'proxy', 'exit_code': 0})
            ids = subprocess.check_output(compose + ['ps', '-q'], cwd=work, env=env, text=True).split()
            containers = json.loads(subprocess.check_output(['docker', 'inspect', *ids], cwd=work, env=env))
            sanitized = []
            for container in containers:
                config = container['HostConfig']
                ports = container['NetworkSettings']['Ports']
                assert all(binding['HostIp'] == '127.0.0.1' for entries in ports.values()
                           for binding in (entries or []))
                sanitized.append({'name': container['Name'], 'image': container['Image'],
                    'ports': ports, 'user': container['Config']['User'],
                    'read_only': config['ReadonlyRootfs'], 'cap_drop': config['CapDrop'],
                    'security_opt': config['SecurityOpt']})
            (output / 'deployment.json').write_text(json.dumps(sanitized, indent=2) + '\n')
            run('images', compose + ['images', '--format', 'json'])
            run('ports', compose + ['ps', '--format', 'json'])
            return 0
        finally:
            cleaned = run('cleanup', compose + ['down', '--volumes', '--remove-orphans'])
            (output / 'results.json').write_text(json.dumps({'project': project, 'checks': results}, indent=2) + '\n')
            if not cleaned:
                return 1


if __name__ == '__main__':
    raise SystemExit(main())
