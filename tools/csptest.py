#!/usr/bin/env python3
"""Local CSP testbench for matrix³.

    python3 tools/csptest.py [port]
"""

import html
import http.server
import json
import os
import sys
import urllib.parse
from http import HTTPStatus
from pathlib import Path

os.chdir(Path(__file__).resolve().parent)

class Handler(http.server.SimpleHTTPRequestHandler):
    current_csp = ''
    last_nav_cookie = ''
    last_subresource_cookie = ''

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
        elif self.path.startswith('/cookie-echo'):
            return self._cookie_echo()
        elif self.path == '/sw.js':
            body = Path('sw.js').read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Service-Worker-Allowed', '/')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif parsed.path == '/dot.png':
            Handler.last_subresource_cookie = self.headers.get('Cookie', '')
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))

        if self.path == '/apply':
            Handler.current_csp = data.get('preset', data.get('csp', ['']))[0]
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header('Location', '/')
            self.end_headers()
        elif self.path.startswith('/cookie-echo'):
            return self._cookie_echo()
        elif self.path == '/report':
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _cookie_echo(self):
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        cookie_hdr = self.headers.get('Cookie', '')
        if 'record' in qs:
            Handler.last_subresource_cookie = cookie_hdr
        body = json.dumps({
            'cookie': cookie_hdr,
            'method': self.command,
            'last_nav_cookie': Handler.last_nav_cookie,
            'last_subresource_cookie': Handler.last_subresource_cookie,
        }).encode('utf-8')
        self.send_response(HTTPStatus.OK)
        if 'set' in qs:
            self.send_header('Set-Cookie', 'http_default=1; Path=/')
            self.send_header('Set-Cookie', 'http_lax=1; Path=/; SameSite=Lax')
            self.send_header('Set-Cookie', 'http_strict=1; Path=/; SameSite=Strict')
            self.send_header('Set-Cookie', 'http_only=1; Path=/; HttpOnly')
        if 'set_from_sub' in qs:
            self.send_header('Set-Cookie', f"sub_cookie={qs['set_from_sub'][0]}; Path=/")
        if 'cors' in qs and self.headers.get('Origin'):
            self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin'))
            self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _render(self, csp):
        Handler.last_nav_cookie = self.headers.get('Cookie', '')
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
