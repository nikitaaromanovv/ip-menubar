"""Bounded HTTPS transport using macOS curl; no shell and no implicit proxy fallback.

A child process provides a hard boundary around DNS/TLS/read deadlines. All
response content is bounded and no cookies, user curl config or credentials load.
"""
from dataclasses import dataclass
import json
import os
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit

# A fixed, minimal environment: the user's shell variables (CURL_CA_BUNDLE,
# SSL_CERT_FILE, SSLKEYLOGFILE, *_proxy) must not change TLS or routing.
CURL_ENV = {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
CURL_ERRORS = {5: 'DNS прокси', 6: 'DNS: имя не разрешено', 7: 'Соединение не установлено',
               28: 'Истекло время ожидания', 35: 'Ошибка TLS', 60: 'Ошибка сертификата',
               63: 'Превышен лимит ответа', 97: 'Прокси отклонил соединение'}


@dataclass(frozen=True)
class Response:
    ok: bool = False
    status: int = 0
    body: bytes = b''
    error: str = ''
    dns_ms: float = 0
    total_ms: float = 0
    local_ip: str = ''
    remote_ip: str = ''
    retry_after: int = 0
    received: int = 0
    complete: bool = False


def site_url(value):
    value = value.strip()
    if '://' not in value:
        value = 'https://' + value
    parts = urlsplit(value)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise ValueError('Нужен HTTPS-адрес без логина и пароля')
    if parts.port not in (None, 443):
        raise ValueError('Поддерживается только порт 443')
    host = parts.hostname.encode('idna').decode('ascii')
    if any(c.isspace() for c in host) or host.startswith('-'):
        raise ValueError('Некорректный адрес')
    if ':' in host:
        host = '[' + host + ']'
    return urlunsplit(('https', host, '/', '', ''))


# Plain-HTTP endpoints with fixed, well-known answers (captive-portal checks). Only these
# may be fetched without TLS: a changed answer shows that something on the path rewrites
# unencrypted traffic.
PLAIN_HTTP = {'http://www.gstatic.com/generate_204': (204, b''),
              'http://detectportal.firefox.com/success.txt': (200, b'success\n')}


def fetch(url, proxy='', *, head=False, limit=16384, deadline=4, headers=()):
    scheme = urlsplit(url).scheme
    if scheme != 'https' and url not in PLAIN_HTTP:
        raise ValueError('HTTPS required')
    # Output files prevent an unbounded response accumulating in Python memory.
    with tempfile.TemporaryDirectory(prefix='ip-menubar-http-') as folder:
        body_path = os.path.join(folder, 'body')
        header_path = os.path.join(folder, 'headers')
        args = ['/usr/bin/curl', '--disable', '--silent', '--show-error',
                '--proto', '=https' if scheme == 'https' else '=http',
                '--max-time', str(deadline), '--connect-timeout', '2',
                '--max-filesize', str(1048576 if head else limit), '--output', body_path, '--dump-header', header_path,
                '--write-out', '%{json}', '--user-agent', 'IP-Menubar/1.3',
                '--proxy', proxy, '--noproxy', '' if proxy else '*']
        if head:
            args.append('--head')
        for header in headers:
            args.extend(['--header', header])
        args.extend(['--url', url])
        try:
            result = subprocess.run(args, capture_output=True, timeout=deadline + .5, env=CURL_ENV)
            meta = json.loads(result.stdout)
            status = int(meta.get('http_code', 0))
            error = CURL_ERRORS.get(result.returncode, 'Ошибка HTTPS' if result.returncode else '')
            if result.returncode == 56 and b'Maximum file size exceeded' in result.stderr:
                error = 'Превышен лимит ответа'
            if status == 407:
                error = 'Прокси требует авторизацию'
            body = b''
            if os.path.exists(body_path):
                with open(body_path, 'rb') as stream:
                    body = stream.read(limit + 1)
            if len(body) > limit:
                error, body = 'Превышен лимит ответа', b''
            retry_after = 0
            if status in (429, 503):
                retry_after = 300
                try:
                    with open(header_path, 'r', encoding='latin1') as headers:
                        for line in headers:
                            if line.lower().startswith('retry-after:'):
                                value = line.split(':', 1)[1].strip()
                                if value.isdigit():
                                    retry_after = min(86400, max(1, int(value)))
                except OSError:
                    pass
            return Response(not error, status, body, error,
                            float(meta.get('time_namelookup', 0)) * 1000,
                            float(meta.get('time_total', 0)) * 1000,
                            meta.get('local_ip', ''), meta.get('remote_ip', ''), retry_after)
        except (subprocess.TimeoutExpired, OSError, ValueError, TypeError):
            return Response(error='Превышено время проверки')


def fetch_sample(url, proxy='', *, limit=102400, deadline=8):
    """GET up to `limit` bytes and stop. Unlike --max-filesize, a large declared
    Content-Length does not abort the transfer before any byte is received."""
    if urlsplit(url).scheme != 'https':
        raise ValueError('HTTPS required')
    with tempfile.TemporaryDirectory(prefix='ip-menubar-sample-') as folder:
        body_path = os.path.join(folder, 'body')
        header_path = os.path.join(folder, 'headers')
        args = ['/usr/bin/curl', '--disable', '--silent', '--show-error',
                '--proto', '=https', '--max-time', str(deadline), '--connect-timeout', '2',
                '--output', body_path, '--dump-header', header_path, '--write-out', '%{json}', '--user-agent', 'IP-Menubar/1.3',
                '--proxy', proxy, '--noproxy', '' if proxy else '*', '--url', url]
        started = time.monotonic()
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CURL_ENV)
        except OSError:
            return Response(error='curl недоступен')
        reached = False
        try:
            while process.poll() is None:
                try:
                    if os.path.getsize(body_path) >= limit:
                        reached = True
                        process.kill()
                        break
                except OSError:
                    pass
                if time.monotonic() - started > deadline + .5:
                    process.kill()
                    break
                time.sleep(.05)
            stdout, _ = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout = b''
        elapsed = (time.monotonic() - started) * 1000
        try:
            received = os.path.getsize(body_path)
        except OSError:
            received = 0
        if reached or (received >= limit):
            return Response(True, last_status(header_path), b'', '', 0, elapsed,
                            received=min(received, limit), complete=True)
        try:
            meta = json.loads(stdout)
        except (ValueError, TypeError):
            meta = {}
        status = int(meta.get('http_code', 0) or 0) or last_status(header_path)
        code = process.returncode if process.returncode and process.returncode > 0 else 0
        error = CURL_ERRORS.get(code, 'Ошибка HTTPS' if code else '')
        if not meta and not error:
            error = 'Превышено время проверки'
        if status == 407:
            error = 'Прокси требует авторизацию'
        return Response(not error, status, b'', error,
                        float(meta.get('time_namelookup', 0) or 0) * 1000, elapsed,
                        meta.get('local_ip', ''), meta.get('remote_ip', ''),
                        received=received, complete=not error)


def last_status(header_path):
    """Status of the final response (a proxy CONNECT reply comes first)."""
    status = 0
    try:
        with open(header_path, 'r', encoding='latin1') as headers:
            for line in headers:
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith('HTTP/') and parts[1].isdigit():
                    status = int(parts[1])
    except OSError:
        pass
    return status
