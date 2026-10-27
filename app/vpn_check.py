"""On-demand VPN check: tampering, DNS filtering, entry/exit and MTU.

Each finding is an observation with its reason, never a verdict about the provider.
Runs in a worker thread; uses its own IPChecker so it shares no state with the app.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time

from local_network import command
from network_monitor import brand
from ping_monitor import path_mtu, resolve_target
from probes import IPChecker, route_for
from transport import PLAIN_HTTP, fetch

OK, WARN, BAD, INFO = 'Норма', 'Внимание', 'Проблема', 'Нет данных'
LEVEL_ORDER = {BAD: 0, WARN: 1, INFO: 2, OK: 3}

DNS_DOMAINS = ('example.com', 'google.com', 'youtube.com', 'instagram.com', 'x.com', 'linkedin.com')
TLS_HOSTS = ('www.google.com', 'www.cloudflare.com', 'github.com', 'www.wikipedia.org', 'yandex.ru')
# Public certificate authorities seen on large sites. An issuer outside this list is not
# proof of interception, only a reason to look closer.
KNOWN_CAS = ('google trust services', "let's encrypt", 'digicert', 'sectigo', 'globalsign', 'amazon',
             'microsoft', 'godaddy', 'entrust', 'certum', 'buypass', 'actalis', 'harica', 'ssl.com',
             'zerossl', 'yandex', 'apple', 'cloudflare', 'russian trusted', 'geant', 'trustasia',
             'comodo', 'usertrust', 'baltimore', 'identrust', 'starfield', 'quovadis', 'swisssign',
             'telia', 'thawte', 'rapidssl', 'geotrust', 'ssl corp')


@dataclass(frozen=True)
class Finding:
    level: str
    title: str
    detail: str


# ----- DNS ---------------------------------------------------------------------------------

def system_addresses(host):
    result = subprocess.run(['/usr/bin/dscacheutil', '-q', 'host', '-a', 'name', host],
                            capture_output=True, text=True, timeout=3,
                            env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
    return tuple(sorted(set(re.findall(r'^ip_address:\s*(\S+)', result.stdout, re.M))))


def parse_doh(body):
    data = json.loads(body)
    found = []
    for answer in data.get('Answer', []) or []:
        if answer.get('type') == 1:
            found.append(str(ipaddress.ip_address(answer.get('data', ''))))
    return tuple(sorted(set(found)))


def doh_addresses(host, config):
    for url, headers in ((f'https://dns.google/resolve?name={host}&type=A', ()),
                         (f'https://cloudflare-dns.com/dns-query?name={host}&type=A',
                          ('accept: application/dns-json',))):
        response = fetch(url, route_for(config, url), headers=headers)
        if response.ok and response.status == 200:
            try:
                return parse_doh(response.body)
            except (ValueError, TypeError, AttributeError):
                continue
    return None


FAKE_IP = ipaddress.ip_network('198.18.0.0/15')


def usable(addresses):
    return [a for a in addresses if ipaddress.ip_address(a).is_global]


def judge_dns(rows):
    """rows: (host, system addresses or None when the lookup itself failed, DoH addresses or None)."""
    if all(doh is None for _, _, doh in rows):
        return Finding(INFO, 'Фильтрация DNS', 'DoH недоступен')
    answered = [a for _, system, _ in rows for a in (system or ())]
    if answered and all(ipaddress.ip_address(a) in FAKE_IP for a in answered):
        return Finding(INFO, 'Фильтрация DNS',
                       'Режим fake-IP (198.18.x.x) · сравнение с DoH не выполняется')
    blocked, differs = [], []
    for host, system, doh in rows:
        if system is None or not doh or not usable(doh):
            continue
        if not system or not usable(system):
            blocked.append(f'{host} ({", ".join(system) or "нет ответа"})')
        elif not set(system) & set(doh):
            differs.append(host)
    note = (f' · другие адреса CDN: {", ".join(differs)}' if differs else '')
    if blocked:
        return Finding(BAD, 'Фильтрация DNS',
                       'Системный DNS расходится с DoH: ' + '; '.join(blocked) + note)
    return Finding(OK, 'Фильтрация DNS', f'Совпадает с DoH: {len(rows)} из {len(rows)}' + note)


def check_dns(config):
    rows = []
    for host in DNS_DOMAINS:
        try:
            system = system_addresses(host)
        except (OSError, subprocess.TimeoutExpired):
            system = None   # no data is not the same as 'blocked'
        rows.append((host, system, doh_addresses(host, config)))
    return judge_dns(rows)


# ----- Certificates and plain HTTP -----------------------------------------------------------

def leaf_issuer(host, timeout=4):
    """Issuer of the certificate the path actually presents (verification off on purpose:
    we want to see a substitute certificate, not fail on it)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Bounded resolution first: getaddrinfo inside create_connection has no time limit.
    address = resolve_target(host)
    with socket.create_connection((address, 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as handle:
        handle.write(ssl.DER_cert_to_PEM_cert(der))
        path = handle.name
    try:
        info = ssl._ssl._test_decode_cert(path)
    finally:
        os.unlink(path)
    issuer = dict(item[0] for item in info.get('issuer', ()) if item)
    return issuer.get('organizationName') or issuer.get('commonName') or ''


def known_ca(issuer):
    text = issuer.lower()
    return any(name in text for name in KNOWN_CAS)


def judge_tls(rows):
    """rows: (host, issuer or '', macOS verification error or '')."""
    rejected = [f'{h}: {e}' for h, _, e in rows if 'сертификат' in e.lower()]
    if rejected:
        return Finding(BAD, 'Подмена сертификатов',
                       'Не проходят проверку macOS: ' + '; '.join(rejected))
    unknown = [f'{h}: {i}' for h, i, _ in rows if i and not known_ca(i)]
    seen = [r for r in rows if r[1]]
    if not seen:
        return Finding(INFO, 'Подмена сертификатов', 'Сертификаты не получены')
    if unknown:
        return Finding(WARN, 'Подмена сертификатов',
                       'Нестандартный издатель: ' + '; '.join(unknown))
    return Finding(OK, 'Подмена сертификатов',
                   f'Издатели известны: {len(seen)} из {len(rows)}')


def check_tls(config):
    rows = []
    for host in TLS_HOSTS:
        try:
            issuer = leaf_issuer(host)
        except Exception:   # unreachable host or an unexpected certificate format
            issuer = ''
        url = f'https://{host}/'
        response = fetch(url, route_for(config, url), head=True)
        rows.append((host, issuer, response.error))
    finding = judge_tls(rows)
    if config.kind not in ('none', 'pac', 'unknown'):
        finding = Finding(finding.level, finding.title,
                          finding.detail + ' · без прокси')
    return finding


def judge_http(rows):
    """rows: (url, expected status, expected body, actual status, actual body, error)."""
    changed, redirected, failed = [], [], []
    for url, status, body, actual_status, actual_body, error in rows:
        host = url.split('/')[2]
        if error:
            failed.append(host)
        elif actual_status in (301, 302, 303, 307, 308):
            redirected.append(host)
        elif actual_status != status or actual_body != body:
            if body and body in actual_body:
                # The real answer is there with something added around it: injection.
                changed.append(f'{host} (HTTP {actual_status}, {len(actual_body)} байт)')
            else:
                # A whole different page: usually a Wi-Fi login portal, sometimes a substitute.
                redirected.append(host)
    if changed:
        return Finding(BAD, 'Подмена HTTP',
                       'HTTP-ответ изменен: ' + '; '.join(changed))
    if redirected:
        return Finding(WARN, 'Подмена HTTP', 'Другая страница или перенаправление: ' + ', '.join(redirected))
    if len(failed) == len(rows):
        return Finding(INFO, 'Подмена HTTP', 'Проверочные адреса недоступны')
    return Finding(OK, 'Подмена HTTP', 'HTTP-ответы без изменений')


def check_http(config):
    rows = []
    for url, (status, body) in PLAIN_HTTP.items():
        response = fetch(url, route_for(config, url))
        rows.append((url, status, body, response.status, response.body, response.error))
    return judge_http(rows)


# ----- Entry and exit ------------------------------------------------------------------------

def endpoint_candidates(netstat_text):
    """Host routes to public addresses via a physical interface: VPN clients add one for
    their server so the tunnel's own packets do not loop into the tunnel."""
    lines = netstat_text.splitlines()
    header = next((l.split() for l in lines if l.split()[:1] == ['Destination']), None)
    if not header or 'Flags' not in header or 'Netif' not in header:
        return []
    flags_at, netif_at = header.index('Flags'), header.index('Netif')
    found = []
    for line in lines:
        fields = line.split()
        match = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)(/32)?', fields[0]) if fields else None
        if len(fields) <= netif_at or not match:
            continue
        flags, netif = fields[flags_at], fields[netif_at]
        # Static ('S') gateway routes to one host; 'W' marks routes macOS clones on its own
        # for recently contacted hosts, which are not VPN servers.
        single_host = 'H' in flags or match.group(2)
        if not single_host or 'G' not in flags or 'S' not in flags or 'W' in flags:
            continue
        if not re.fullmatch(r'(?:en|bridge)\d+', netif):
            continue
        ip = match.group(1)
        if ipaddress.ip_address(ip).is_global and ip not in found:
            found.append(ip)
    return found


def describe(checker, config, ip):
    found = checker.lookup(ip, config, 0, spaced=False) if ip else None
    if not found:
        return ip
    country, _, org, asn = found
    return ' · '.join(part for part in (ip, country, brand(org, asn)) if part)


def judge_route(state, entries, exit_text, entry_countries, exit_country=''):
    if state == 'outside':
        return Finding(INFO, 'Вход и выход', f'Вход: не виден, VPN вне Mac\n  Выход: {exit_text}')
    if state not in ('mac', 'partial', 'leak'):
        return Finding(INFO, 'Вход и выход', 'VPN не обнаружен')
    if not entries:
        return Finding(INFO, 'Вход и выход', f'Вход: не найден\n  Выход: {exit_text}')
    entry_text = '; '.join(entries)
    if any(code == 'RU' for code in entry_countries) and exit_country != 'RU':
        return Finding(WARN, 'Вход и выход',
                       f'Вход: {entry_text}\n  Выход: {exit_text}\n  Входной сервер в РФ')
    return Finding(OK, 'Вход и выход', f'Вход: {entry_text}\n  Выход: {exit_text}')


def check_route(config, state, exit_ip):
    checker = IPChecker()
    entries, codes = [], []
    if state in ('mac', 'partial', 'leak'):
        try:
            candidates = endpoint_candidates(command(['/usr/sbin/netstat', '-rn', '-f', 'inet']))
        except (OSError, subprocess.TimeoutExpired):
            candidates = []
        for ip in candidates[:3]:
            if ip == exit_ip:
                continue
            found = checker.lookup(ip, config, 0, spaced=False)
            codes.append(found[1] if found else '')
            entries.append(describe(checker, config, ip))
    exit_found = checker.lookup(exit_ip, config, 0, spaced=False) if exit_ip else None
    exit_text = describe(checker, config, exit_ip) if exit_ip else 'не определен'
    return judge_route(state, entries, exit_text, codes, exit_found[1] if exit_found else '')


# ----- MTU -----------------------------------------------------------------------------------

def judge_mtu(mtu, note):
    if mtu is None:
        return Finding(INFO, 'MTU пути', note)
    if mtu >= 1400:
        return Finding(OK, 'MTU пути', f'{mtu} байт')
    if mtu >= 1280:
        return Finding(WARN, 'MTU пути',
                       f'{mtu} байт · ниже 1400')
    return Finding(BAD, 'MTU пути', f'{mtu} байт · ниже 1280')


def check_mtu(ping_host):
    try:
        address = resolve_target(ping_host)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return Finding(INFO, 'MTU пути', 'Адрес пинга не найден')
    if ':' in address:
        return Finding(INFO, 'MTU пути', 'Только IPv4 · адрес пинга IPv6')
    return judge_mtu(*path_mtu(address))


# ----- Report --------------------------------------------------------------------------------

def report(findings, extra=()):
    findings = sorted(list(findings) + list(extra), key=lambda f: LEVEL_ORDER.get(f.level, 9))
    bad = sum(f.level == BAD for f in findings)
    warn = sum(f.level == WARN for f in findings)
    lines = [f'ПРОВЕРКА VPN · {datetime.now():%d.%m %H:%M}',
             f'Итог: проблемы {bad} · внимание {warn}' if bad or warn else 'Итог: норма']
    for f in findings:
        lines.append(f'• {f.level} · {f.title}\n  {f.detail}')
    return '\n'.join(lines)


def run(config, ping_host, state, exit_ip, extra=()):
    jobs = {'tls': lambda: check_tls(config), 'http': lambda: check_http(config),
            'dns': lambda: check_dns(config), 'route': lambda: check_route(config, state, exit_ip),
            'mtu': lambda: check_mtu(ping_host)}
    titles = {'tls': 'Подмена сертификатов', 'http': 'Подмена HTTP', 'dns': 'Фильтрация DNS',
              'route': 'Вход и выход', 'mtu': 'MTU пути'}
    findings = []
    deadline = time.monotonic() + 75
    pool = ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix='vpn-check')
    try:
        futures = {name: pool.submit(job) for name, job in jobs.items()}
        for name, future in futures.items():
            try:
                findings.append(future.result(timeout=max(.1, deadline - time.monotonic())))
            except Exception as error:   # one failed or slow check must not hide the others
                reason = 'превышено время' if isinstance(error, TimeoutError) else type(error).__name__
                findings.append(Finding(INFO, titles[name], f'Проверка не выполнена: {reason}'))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)   # never keep the lane busy past the deadline
    return report(findings, extra)
