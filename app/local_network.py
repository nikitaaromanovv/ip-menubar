"""Read-only macOS inspection. A tunnel is evidence, not a safety verdict."""
from dataclasses import dataclass
import os
import re
import subprocess
import time


def command(args, input_text=None):
    p = subprocess.run(args, input=input_text, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=2,
                       env={**os.environ, 'LC_ALL': 'C'})
    if p.returncode:
        raise OSError('System inspection unavailable')
    return p.stdout


def route_interface(text):
    match = re.search(r'^\s*interface:\s*([a-zA-Z][a-zA-Z0-9]*)\s*$', text, re.M)
    return match[1] if match else ''


def tunnel_interface(name):
    return bool(re.fullmatch(r'(?:utun|tun|tap|ppp|ipsec)\d+', name))


@dataclass(frozen=True)
class VPNSnapshot:
    kind: str = 'unknown'  # tunnel, not_detected, unknown
    routes: tuple = ()  # interface toward two fixed IPv4 destinations
    proxy: bool = False
    at: float = 0.0

    @property
    def signature(self):
        return self.kind, self.routes, self.proxy

    @property
    def active(self):
        return self.kind == 'tunnel'

    @property
    def label(self):
        return {'tunnel': 'Туннель на Mac',
                'partial': 'Туннель частично',
                'not_detected': 'Туннеля нет',
                'unknown': 'Маршруты: нет данных'}[self.kind]

    @property
    def summary(self):
        known = [i for i in self.routes if i]
        through = [i for i in known if tunnel_interface(i)]
        return f'Через туннель: {len(through)} из {len(known)} маршрутов'


def classify_routes(routes):
    known = [i for i in routes if i]
    through = [i for i in known if tunnel_interface(i)]
    if through and len(through) == len(known):
        return 'tunnel'
    if through:
        return 'partial'
    if all(routes[:2]) or all(routes[2:]):
        return 'not_detected'
    return 'unknown'


def inspect_vpn():
    routes = []
    for target in ('1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '2001:4860:4860::8888'):
        try:
            routes.append(route_interface(command(['/sbin/route', '-n', 'get', target])))
        except (OSError, subprocess.TimeoutExpired):
            routes.append('')
    # Proxy settings are read once per context in proxy_monitor; no duplicate scutil call.
    return VPNSnapshot(classify_routes(routes), tuple(routes), False, time.monotonic())


def parse_counters(text):
    rows = text.splitlines()
    if not rows:
        raise ValueError('No network counters')
    header = rows[0].split()
    required = ('Name', 'Network', 'Ibytes', 'Obytes')
    if not all(name in header for name in required):
        raise ValueError('Missing counter columns')
    output = {}
    for row in rows[1:]:
        fields = row.split()
        if not fields or not re.fullmatch(r'(?:en|bridge)\d+', fields[0]):
            continue
        link = next((i for i, f in enumerate(fields) if re.fullmatch(r'<Link#\d+>', f)), None)
        if link is None:
            continue
        # Only optional Address may be absent; other shape changes are rejected.
        missing = len(header) - len(fields)
        if missing not in (0, 1):
            continue
        def cell(name):
            index = header.index(name)
            if missing and 'Address' in header and index > header.index('Address'):
                index -= 1
            return fields[index]
        try:
            incoming, outgoing = int(cell('Ibytes')), int(cell('Obytes'))
            if min(incoming, outgoing) < 0:
                continue
            output[fields[0]] = (incoming, outgoing)
        except (ValueError, IndexError):
            continue
    return output


_primary_cache = ('', 0.0)


def read_traffic():
    global _primary_cache
    counters = parse_counters(command(['/usr/sbin/netstat', '-ibn']))
    preferred, checked_at = _primary_cache
    if preferred in counters and time.monotonic() - checked_at < 15:
        return counters, preferred, time.monotonic()
    preferred = ''
    try:
        text = command(['/usr/sbin/scutil'], 'show State:/Network/Global/IPv4\nquit\n')
        match = re.search(r'PrimaryInterface\s*:\s*(\w+)', text)
        if match and match[1] in counters:
            preferred = match[1]
        if not preferred:
            text = command(['/usr/sbin/scutil', '--nwi'])
            for name in re.findall(r'^\s*(en\d+|bridge\d+)\s*:\s*flags', text, re.M):
                if name in counters:
                    preferred = name
                    break
    except (OSError, subprocess.TimeoutExpired):
        pass
    _primary_cache = (preferred, time.monotonic())
    # Don't silently guess among interfaces when the active one isn't known.
    return counters, preferred, time.monotonic()


@dataclass(frozen=True)
class TrafficRate:
    interface: str = ''
    down: float | None = None
    up: float | None = None
    detail: str = ''


class TrafficSampler:
    def __init__(self):
        self.previous = None

    def sample(self, counters, preferred, at, selected='auto'):
        interface = preferred if selected == 'auto' else selected
        if not interface or interface not in counters:
            self.previous = None
            return TrafficRate(detail='Интерфейс не определен')
        current = (interface, at, counters[interface])
        previous, self.previous = self.previous, current
        if not previous or previous[0] != interface:
            return TrafficRate(interface, detail='Замер…')
        elapsed = at - previous[1]
        incoming = current[2][0] - previous[2][0]
        outgoing = current[2][1] - previous[2][1]
        if elapsed <= 0 or elapsed > 30 or min(incoming, outgoing) < 0:
            return TrafficRate(interface, detail='Счетчики сброшены')
        return TrafficRate(interface, incoming / elapsed, outgoing / elapsed)


def format_rate(value):
    if value is None:
        return '—'
    if value >= 1_000_000:
        return f'{value / 1_000_000:.1f} МБ/с'.replace('.', ',')
    return f'{value / 1000:.1f} КБ/с'.replace('.', ',')
