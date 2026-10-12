"""Run regression checks with isolated synthetic data and export reviewable evidence."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'evidence'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    checks = []
    with tempfile.TemporaryDirectory(prefix='aegis-verify-') as temp:
        for name in ['smoke_test', 'test_pdf_scan', 'test_api_abuse']:
            storage = Path(temp) / name
            env = {**os.environ, 'AEGIS_STORAGE_DIR': str(storage)}
            run = subprocess.run([sys.executable, str(ROOT / 'backend/scripts' / (name + '.py'))], env=env, text=True, capture_output=True)
            output = (run.stdout + run.stderr).replace(str(ROOT), '<repository>').replace(temp, '<temporary-storage>')
            (OUT / (name + '.txt')).write_text(output, encoding='utf-8')
            checks.append({'name': name, 'passed': run.returncode == 0, 'exit_code': run.returncode})
            print(('PASS' if run.returncode == 0 else 'FAIL') + ' ' + name, flush=True)

        os.environ['AEGIS_STORAGE_DIR'] = str(Path(temp) / 'api-contract')
        sys.path.insert(0, str(ROOT / 'backend'))
        from fastapi.testclient import TestClient
        from main import app

        def clean(value):
            if isinstance(value, str):
                return value.replace(temp, '<temporary-storage>').replace(str(ROOT), '<repository>')
            if isinstance(value, list):
                return [clean(item) for item in value]
            if isinstance(value, dict):
                return {key: clean(item) for key, item in value.items()}
            return value

        def fetch(client, method, path, **kwargs):
            response = client.request(method, '/api/v1' + path, **kwargs)
            assert response.status_code == 200, (path, response.status_code)
            body = response.json()
            assert body['code'] == 200, path
            return body['data']

        with TestClient(app) as client:
            demo = fetch(client, 'POST', '/demo/reset')
            project_id = demo['project_id']
            result = fetch(client, 'GET', f"/redteam/runs/{demo['redteam']['run_id']}/result")
            assert result['summary']['total_cases'] == 7
            assert result['summary']['passed'] == 7
            checks.append({'name': 'demo_reset_and_7_synthetic_cases', 'passed': True})
            (OUT / 'demo-result.json').write_text(json.dumps(clean(result), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

            policy = fetch(client, 'GET', '/policies/P-API-001')
            config = dict(policy['config'])
            config['threshold'] = 3
            fetch(client, 'PUT', '/policies/P-API-001', json={'enabled': True, 'decision': 'alert_only', 'config': config})
            decisions = []
            for i in range(3):
                event = fetch(client, 'POST', '/events', json={
                    'project_id': project_id, 'actor_id': 'contract-test-actor', 'action': 'api.request',
                    'resource_type': 'api', 'resource_path': f'/api/v1/files/missing_{i}',
                    'context': {'status_code': 404},
                })
                decisions.append(event['decision'])
            assert decisions == ['allow', 'allow', 'alert_only'], decisions
            fetch(client, 'PUT', '/policies/P-API-001', json={'enabled': policy['enabled'], 'decision': policy['decision'], 'config': policy['config']})
            checks.append({'name': 'configurable_api_threshold', 'passed': True, 'threshold': 3, 'decisions': decisions})
            alert = fetch(client, 'GET', '/alerts/' + event['alert_id'])
            assert alert['category'] == 'api_abuse' and alert['evidence']
            (OUT / 'api-threshold-alert.json').write_text(json.dumps(clean(alert), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

            report = client.get(f"/api/v1/redteam/runs/{demo['redteam']['run_id']}/report.md")
            assert report.status_code == 200 and '7' in report.text
            (OUT / 'redteam-report.md').write_text(clean(report.text), encoding='utf-8')
            checks.append({'name': 'markdown_report_export', 'passed': True})
            for route in ['/console/', '/console/app.js', '/console/styles.css', '/docs', '/openapi.json']:
                assert client.get(route).status_code == 200, route
            checks.append({'name': 'console_assets_and_openapi', 'passed': True})
            (OUT / 'openapi.json').write_text(json.dumps(app.openapi(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    source_files = sorted(p for base in ['backend', 'frontend', 'scripts'] for p in (ROOT / base).rglob('*')
                          if p.is_file() and p.suffix in {'.py', '.js', '.html', '.css', '.txt'} and 'storage' not in p.parts and '__pycache__' not in p.parts and '.venv' not in p.parts)
    manifest = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    (OUT / 'source-sha256.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    summary = {'verified_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
               'python': platform.python_version(), 'platform': platform.system(), 'checks': checks,
               'all_passed': all(item['passed'] for item in checks),
               'scope': 'Local functional regression with synthetic inputs, not security effectiveness or load testing.'}
    (OUT / 'verification.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    raise SystemExit(0 if summary['all_passed'] else 1)


if __name__ == '__main__':
    main()
