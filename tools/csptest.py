#!/usr/bin/env python3
"""Local CSP testbench for matrix³.

    python3 tools/csptest.py [port]
"""

import contextlib
import html
import http.server
import json
import os
import socket
import sys
import threading
import urllib.parse
from http import HTTPStatus
from pathlib import Path

os.chdir(Path(__file__).resolve().parent)

class Handler(http.server.SimpleHTTPRequestHandler):
    current_csp = ''
    current_headers = ''
    last_nav_cookie = ''
    last_subresource_cookie = ''

    @staticmethod
    def _clean_header(text):
        return text.replace('\r', '').replace('\n', '').encode('utf-8').decode('latin-1')

    @classmethod
    def _parse_query_headers(cls, qs):
        pairs = []
        for name, val in zip(qs.get('hdr', []), qs.get('value', [])):
            if name.strip():
                pairs.append((cls._clean_header(name.strip()), cls._clean_header(val)))
        for key, names in qs.items():
            if key.startswith('hdr[') and key.endswith(']'):
                idx = key[4:-1]
                for name, val in zip(names, qs.get(f'value[{idx}]', [])):
                    if name.strip():
                        pairs.append((cls._clean_header(name.strip()), cls._clean_header(val)))
        return pairs

    @classmethod
    def _parse_header_lines(cls, raw):
        pairs = []
        for line in raw.split('\n'):
            if ':' in line:
                name, val = line.split(':', 1)
                if name.strip():
                    pairs.append((cls._clean_header(name.strip()), cls._clean_header(val.strip())))
        return pairs

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/':
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            csp = '\n'.join(qs['csp']) if 'csp' in qs else Handler.current_csp
            extra_headers = '\n'.join(qs['headers']) if 'headers' in qs else Handler.current_headers
            return self._render(csp, extra_headers)
        elif parsed.path == '/reset':
            Handler.current_csp = ''
            Handler.current_headers = ''
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
        elif parsed.path == '/quit':
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'ok\n')
            self.wfile.flush()
            threading.Timer(0.1, self.server.shutdown).start()
            return
        elif parsed.path == '/dot.png':
            Handler.last_subresource_cookie = self.headers.get('Cookie', '')
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))

        if self.path == '/apply':
            Handler.current_csp = data.get('preset', data.get('csp', ['']))[0]
            Handler.current_headers = data.get('headers', [''])[0]
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

    def _render(self, csp, extra_headers=''):
        Handler.last_nav_cookie = self.headers.get('Cookie', '')
        body = (
            Path('index.html')
            .read_text()
            .replace('{{csp}}', html.escape(csp))
            .replace('{{headers}}', html.escape(extra_headers))
            .encode('utf-8')
        )
        self.send_response(HTTPStatus.OK)
        lines = [line.strip() for line in csp.split('\n') if line.strip()]
        for line in (lines or ['']):
            self.send_header('Content-Security-Policy', self._clean_header(line))
        for name, val in self._parse_header_lines(extra_headers):
            self.send_header(name, val)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
        for name, val in self._parse_query_headers(qs):
            self.send_header(name, val)
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Expires', '0')
        super().end_headers()

class DualStackServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        with contextlib.suppress(Exception):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        return super().server_bind()


def create_server(port):
    try:
        return DualStackServer(('::', port), Handler)
    except OSError:
        return http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    with create_server(port) as server:
        actual = server.server_address[1]
        print(f'CSP testbench at http://127.0.0.1:{actual}/ and http://[::1]:{actual}/')
        print(f'PORT={actual}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
