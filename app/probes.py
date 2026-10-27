"""The same Russian + foreign pair participates in every cycle."""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
import json
import time
from dataclasses import dataclass
from connectivity import Cycle, Probe
from network_monitor import (valid_ip, safe_country, safe_text, country_code_to_flag,
                             country_name, looks_like_hosting)
from transport import fetch, fetch_sample, site_url

# HEAD avoids downloading the home page. No redirects are followed.
TARGETS = (('ru', 'https://yandex.ru/robots.txt', True, 200),
           ('global', 'https://www.gstatic.com/generate_204', False, 204))

# With PAC/WPAD or unreadable proxy settings the proxy for a URL is unknown. Checks
# then use the system route and say so explicitly instead of stopping entirely.
SYSTEM_FALLBACK = ('pac', 'unknown')


def route_for(config, url):
    return '' if config.kind in SYSTEM_FALLBACK else config.for_url(url)


def path_label(config):
    if config.kind == 'pac':
        return 'pac-system'
    if config.kind == 'unknown':
        return 'unknown-system'
    return config.url or 'system'


def probe(target, config):
    group, url, head, expected = target
    response = fetch(url, route_for(config, url), head=head)
    ok = response.ok and response.status == expected
    detail = 'Отвечает' if ok else response.error or f'HTTP {response.status}'
    if response.status in (301, 302, 303, 307, 308):
        detail = 'Перенаправление'
    return Probe(group, ok, detail, time.monotonic(), response.total_ms,
                 response.dns_ms, url, response.local_ip, response.ok and response.status > 0, response.retry_after)


def check_cycle(generation, config):
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix='https-target') as pool:
        results = tuple(pool.map(lambda target: probe(target, config), TARGETS))
    return Cycle(results, generation, started, time.monotonic(), path_label(config))


@dataclass(frozen=True)
class IPResult:
    ip: str = ''
    country: str = ''
    code: str = ''
    detail: str = ''
    source: str = 'https://api64.ipify.org?format=json'
    at: float = 0
    retry_after: int = 0
    org: str = ''
    asn: str = ''
    direct_ip: str = ''
    geo_retry: float = 0
    v6_checked: bool = False   # whether the IPv6-only check ran in this result
    v6_ip: str = ''            # empty when the Mac has no IPv6 route to the internet
    v6_org: str = ''
    v6_asn: str = ''

    @property
    def hosting(self):
        return looks_like_hosting(self.org, self.asn)


class IPChecker:
    """IP on every check; geolocation and network owner only for an IP not yet cached."""
    GEO_SPACING = 15      # seconds between lookups of different new IPs
    GEO_RETRY = 120       # seconds before retrying a failed lookup of the same IP

    def __init__(self):
        self.cache = OrderedDict()
        self.failed = {}
        self.next_geo = 0

    def lookup(self, ip, config, now, spaced=True):
        if ip in self.cache:
            self.cache.move_to_end(ip)
            return self.cache[ip]
        if (spaced and now < self.next_geo) or now < self.failed.get(ip, 0):
            return None
        self.next_geo = now + self.GEO_SPACING
        geo_url = f'https://ipwho.is/{ip}?fields=success,ip,country,country_code,connection'
        geo = fetch(geo_url, route_for(config, geo_url))
        try:
            data = json.loads(geo.body)
            if not geo.ok or data.get('success') is not True or valid_ip(data['ip']) != ip:
                raise ValueError()
            code = data['country_code']
            if country_code_to_flag(code) == '🏳️':
                raise ValueError()
            country = country_name(code, safe_country(data['country']))
            connection = data.get('connection') or {}
            org = safe_text(connection.get('org') or connection.get('isp') or '')
            asn = connection.get('asn')
            asn = f'AS{asn}' if isinstance(asn, int) and asn > 0 else ''
        except (ValueError, KeyError, TypeError, AttributeError):
            self.failed[ip] = now + self.GEO_RETRY
            return None
        self.cache[ip] = (country, code, org, asn)
        while len(self.cache) > 16:
            self.cache.popitem(last=False)
        return self.cache[ip]

    @staticmethod
    def read_ip(url, proxy):
        response = fetch(url, proxy)
        if not response.ok or response.status != 200:
            return '', response
        try:
            return valid_ip(json.loads(response.body)['ip']), response
        except (ValueError, KeyError, TypeError):
            return '', response

    def check_v6(self, config):
        """IPv6-only service: answers only if IPv6 traffic leaves the Mac, and shows by
        which network. A VPN that carries only IPv4 leaks exactly here."""
        url = 'https://api6.ipify.org?format=json'
        ip, _ = self.read_ip(url, route_for(config, url))
        if not ip or ':' not in ip:
            return '', '', ''
        found = self.lookup(ip, config, time.monotonic(), spaced=False)
        _, _, org, asn = found or ('', '', '', '')
        return ip, org, asn

    def check(self, config, with_v6=False):
        url = 'https://api64.ipify.org?format=json'
        proxy = route_for(config, url)
        response = fetch(url, proxy)
        if not response.ok or response.status != 200:
            return IPResult(detail=response.error or f'HTTP {response.status}', retry_after=response.retry_after)
        try:
            ip = valid_ip(json.loads(response.body)['ip'])
        except (ValueError, KeyError, TypeError):
            return IPResult(detail='IP-сервис: ошибка ответа')
        now = time.monotonic()
        found = self.lookup(ip, config, now)
        country, code, org, asn = found or ('', '', '', '')
        retry = 0 if found else max(1.0, max(self.next_geo, self.failed.get(ip, 0)) - now)
        detail = ('Системный маршрут · PAC не применяется' if config.kind == 'pac' else
                  'Системный маршрут · прокси не прочитан' if config.kind == 'unknown' else
                  'Системный маршрут')
        # With a configured proxy the system route may exit elsewhere; show both, never mix them.
        direct = self.read_ip(url, '')[0] if proxy else ''
        if proxy:
            detail = 'Через прокси'
        v6 = self.check_v6(config) if with_v6 else ('', '', '')
        return IPResult(ip, country, code, detail, at=time.monotonic(), org=org, asn=asn, direct_ip=direct,
                        geo_retry=retry, v6_checked=with_v6, v6_ip=v6[0], v6_org=v6[1], v6_asn=v6[2])


def check_site(value, config, extended=False):
    url = site_url(value)
    proxy = route_for(config, url)
    note = ''
    if extended:
        response = fetch_sample(url, proxy, limit=102400, deadline=8)
    else:
        response = fetch(url, proxy, head=True, limit=16384, deadline=4)
        if not response.error and response.status in (403, 405, 501):
            # Many servers refuse HEAD; repeat with a short GET before concluding anything.
            response = fetch_sample(url, proxy, limit=16384, deadline=4)
            note = 'HEAD отклонен · повтор GET\n'
    if response.error:
        detail = response.error
    elif response.status in (403, 451):
        detail = f'Доступ ограничен: HTTP {response.status}'
    elif 200 <= response.status < 400:
        detail = f'Сайт отвечает: HTTP {response.status}'
    elif response.status:
        detail = f'Ответ: HTTP {response.status}'
    else:
        detail = 'Ответ без кода HTTP'
    if extended:
        kb = response.received / 1000
        speed = f' за {response.total_ms / 1000:.1f} с'.replace('.', ',') if response.total_ms else ''
        if response.complete and response.received >= 102400:
            sample = f'Загрузка: 100 КБ{speed}'
        elif response.complete:
            sample = f'Загрузка: {kb:.0f} КБ{speed}, полностью'
        else:
            sample = f'Загрузка: {kb:.0f} КБ, прервана'
    else:
        sample = ''
    route = ('системный маршрут · PAC не применяется' if config.kind == 'pac' else
             'системный маршрут · прокси не прочитан' if config.kind == 'unknown' else
             'через прокси' if proxy else 'системный маршрут')
    return (f'{url}\n{note}{detail}\n'
            + (sample + '\n' if sample else '')
            + f'Путь: {route}\n'
            f'DNS: {response.dns_ms:.0f} мс · HTTPS: {response.total_ms:.0f} мс\n'
            f'Локальный адрес: {response.local_ip or "—"}')
