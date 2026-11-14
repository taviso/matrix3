#!/usr/bin/env python3
"""Local CSP testbench for matrix³.

    python3 tools/csptest.py [port]
"""

import html
import http.server
import os
import sys
import urllib.parse
from http import HTTPStatus
from pathlib import Path

os.chdir(Path(__file__).resolve().parent)

class Handler(http.server.SimpleHTTPRequestHandler):
    current_csp = ''

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/':
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            csp = '\n'.join(qs['csp']) if 'csp' in qs else Handler.current_csp
            return self._render(csp)
        elif parsed.path == '/reset':
            Handler.current_csp = ''
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header('Location', '/')
            self.end_headers()
            return
        elif self.path.startswith('/redirect'):
            query = urllib.parse.urlsplit(self.path).query
            target = urllib.parse.parse_qs(query).get('to', ['https://cdn.jsdelivr.net/npm/d3/+esm'])[0]
            self.send_response(HTTPStatus.FOUND)
            self.send_header('Location', target)
            self.end_headers()
            return
        elif self.path == '/sw.js':
            body = Path('sw.js').read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Service-Worker-Allowed', '/')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))

        if self.path == '/apply':
            Handler.current_csp = data.get('preset', data.get('csp', ['']))[0]
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header('Location', '/')
            self.end_headers()
        elif self.path == '/report':
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _render(self, csp):
        body = Path('index.html').read_text().replace('{{csp}}', html.escape(csp)).encode('utf-8')
        self.send_response(HTTPStatus.OK)
        lines = [line.strip() for line in csp.split('\n') if line.strip()]
        for line in (lines or ['']):
            self.send_header('Content-Security-Policy', line.encode('utf-8').decode('latin-1'))
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Expires', '0')
        super().end_headers()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    with http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler) as server:
        print(f'CSP testbench at http://127.0.0.1:{port}/')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
