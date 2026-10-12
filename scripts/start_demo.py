"""Start the local console; use --seed to create deterministic synthetic demo data."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
import webbrowser


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--seed', action='store_true', help='reset the synthetic demo project and default policies')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    base = f'http://127.0.0.1:{args.port}'
    root = Path(__file__).resolve().parents[1]
    # Avoid resetting some other service that is already using this port.
    try:
        with urlopen(base + '/api/v1/health', timeout=1):
            raise SystemExit('Port already serves an API. Choose another port with --port.')
    except (URLError, TimeoutError):
        pass
    process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', str(args.port)], cwd=root / 'backend', env=os.environ.copy())
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise SystemExit('Backend did not start.')
            try:
                with urlopen(base + '/api/v1/health', timeout=1):
                    break
            except (URLError, TimeoutError):
                time.sleep(0.1)
        else:
            raise SystemExit('Backend startup timed out.')
        if args.seed:
            with urlopen(Request(base + '/api/v1/demo/reset', method='POST'), timeout=30) as response:
                if response.status != 200:
                    raise SystemExit('Demo initialization failed.')
        print('Console:', base + '/console/', flush=True)
        print('OpenAPI:', base + '/docs', flush=True)
        if not args.no_browser:
            webbrowser.open(base + '/console/')
        process.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
