"""One bounded ICMP attempt. No shell, root privileges or user-controlled options."""
from collections import deque
from statistics import median
from dataclasses import dataclass
import ipaddress
import os
import re
import subprocess
import time
import socket
import struct
import secrets


def validate_host(value):
    value = value.strip()
    if not value or len(value) > 253 or '%' in value:
        raise ValueError('Нужен домен или IP без URL и порта')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # This version intentionally uses IPv4 ICMP. IPv6 is a separate test.
        host = value.rstrip('.').encode('idna').decode('ascii')
        labels = host.split('.')
        if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
               for p in labels):
            raise ValueError('Некорректное имя сервера')
        return host.lower()
    return str(address)


@dataclass(frozen=True)
class PingResult:
    host: str
    kind: str  # reply, loss, error
    latency_ms: float | None = None
    detail: str = ''
    at: float = 0.0
    ttl: int | None = None


_resolved = {}
_resolution_epoch = 0


def reset_resolution():
    global _resolution_epoch
    _resolution_epoch += 1
    _resolved.clear()


def resolve_target(host):
    epoch = _resolution_epoch
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    cached = _resolved.get(host)
    if cached and time.monotonic() - cached[1] < 120:
        return cached[0]
    # Bound system resolution independently; never pin a worker indefinitely in getaddrinfo.
    result = subprocess.run(['/usr/bin/dscacheutil', '-q', 'host', '-a', 'name', host],
                            capture_output=True, text=True, timeout=2,
                            env={**os.environ, 'LC_ALL': 'C'})
    match = re.search(r'^ip_address:\s*(\S+)', result.stdout, re.M)
    if not match:
        match = re.search(r'^ipv6_address:\s*(\S+)', result.stdout, re.M)
    if not match:
        raise ValueError('DNS')
    address = str(ipaddress.ip_address(match[1]))
    if epoch == _resolution_epoch:
        _resolved[host] = (address, time.monotonic())
    return address


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ping_once(host):
    host = validate_host(host)
    try:
        address = resolve_target(host)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return PingResult(host, 'error', detail='DNS: имя не найдено', at=time.monotonic())
    token = secrets.token_bytes(16)
    seq = secrets.randbelow(65536)
    ipv6 = ':' in address
    request_type, reply_type = (128, 129) if ipv6 else (8, 0)
    header = struct.pack('!BBHHH', request_type, 0, 0, 0, seq)
    packet = struct.pack('!BBHHH', request_type, 0, 0 if ipv6 else checksum(header + token), 0, seq) + token
    try:
        with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM,
                           socket.IPPROTO_ICMPV6 if ipv6 else socket.IPPROTO_ICMP) as sock:
            started = time.monotonic()
            sock.sendto(packet, (address, 0))
            while time.monotonic() - started < 1:
                sock.settimeout(max(.001, 1 - (time.monotonic() - started)))
                try:
                    raw, peer = sock.recvfrom(4096)
                except socket.timeout:
                    break
                has_header = bool(raw) and raw[0] >> 4 == 4
                offset = (raw[0] & 15) * 4 if has_header else 0
                payload = raw[offset:]
                if (peer[0] == address and len(payload) >= 24 and payload[0] == reply_type
                        and payload[6:8] == struct.pack('!H', seq) and payload[8:24] == token):
                    # TTL of the reply changes when the path length changes, e.g. a VPN
                    # switched on the router. It is only a trigger for a re-check.
                    ttl = raw[8] if has_header and len(raw) > 8 else None
                    return PingResult(host, 'reply', (time.monotonic() - started) * 1000,
                                      detail=address, at=time.monotonic(), ttl=ttl)
        return PingResult(host, 'loss', detail='Нет ответа', at=time.monotonic())
    except OSError:
        return PingResult(host, 'error', detail='ICMP недоступен', at=time.monotonic())


def ping_df(address, payload, timeout_ms=1000):
    """MTU probe with the system ping: '-D' sets Don't Fragment, '-s' is the ICMP data size.
    ICMP datagram sockets may not accept IP_DONTFRAG, so the dedicated tool is used."""
    address = str(ipaddress.ip_address(address))   # never pass anything else to a command
    try:
        result = subprocess.run(['/sbin/ping', '-D', '-n', '-q', '-c', '1', '-W', str(timeout_ms),
                                 '-s', str(int(payload)), address],
                                capture_output=True, text=True, timeout=timeout_ms / 1000 + 2,
                                env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin:/sbin:/usr/sbin'})
    except FileNotFoundError:
        return 'unsupported'
    except (OSError, subprocess.TimeoutExpired):
        return 'loss'
    text = result.stdout + result.stderr
    if 'Message too long' in text or 'message too long' in text:
        return 'too_big'
    if 'illegal option' in text or 'invalid option' in text:
        return 'unsupported'
    return 'reply' if result.returncode == 0 else 'loss'


def path_mtu(address, probe=ping_df, low=1172, high=1472):
    """Largest packet (bytes, including headers) that reaches `address` unfragmented,
    by binary search over ICMP data size. Returns (mtu or None, note)."""
    first = probe(address, 64)
    if first == 'unsupported':
        return None, 'Проверка MTU недоступна'
    if first != 'reply' and probe(address, 64) != 'reply':
        return None, 'Нет ответа на пинг'

    def passes(size):
        return any(probe(address, size) == 'reply' for _ in range(2))
    if passes(high):
        return high + 28, ''
    if not passes(low):
        return None, f'Меньше {low + 28} байт'
    while high - low > 4:
        middle = (low + high) // 2
        if passes(middle):
            low = middle
        else:
            high = middle
    return low + 28, ''


class PingWindow:
    """Rolling 60-attempt window. Thresholds favour few false warnings: ICMP is
    often rate-limited, so a handful of lost probes is not a connection problem."""
    MIN_ATTEMPTS = 30
    LOSS_THRESHOLD = .15
    LATENCY_LIMIT_MS = 200

    def __init__(self):
        self.attempts = deque(maxlen=60)
        self.last = None
        self.failures = 0
        self.last_ttl = None
        self.signals = []

    def add(self, result):
        if self.last and result.at - self.last.at > 10:
            self.attempts.clear()  # Don't join samples across sleep/long pauses.
            self.failures = 0
            self.last_ttl = None
        previous_failures = self.failures
        self.last = result
        self.failures = 0 if result.kind == 'reply' else self.failures + 1
        if result.kind != 'error':
            self.attempts.append(result)
        if result.kind == 'reply':
            if previous_failures >= 2:
                self.signals.append('ping_resumed')
            if result.ttl is not None:
                if self.last_ttl is not None and result.ttl != self.last_ttl:
                    self.signals.append('ttl_changed')
                self.last_ttl = result.ttl
            if self.rtt_shift():
                self.signals.append('rtt_shift')

    def take_signals(self):
        signals, self.signals = self.signals, []
        return signals

    def rebase(self):
        """The path changed (TTL or a latency step): the new path's latency is the new
        normal, so older samples must not make it look 'grown'."""
        recent = list(self.attempts)[-5:]
        self.attempts.clear()
        self.attempts.extend(recent)

    def forget_losses(self):
        """After a confirmed outage the lost probes describe the outage, not quality."""
        replies = [r for r in self.attempts if r.kind == 'reply']
        self.attempts.clear()
        self.attempts.extend(replies[-5:])

    def replies(self):
        return [r.latency_ms for r in self.attempts if r.kind == 'reply']

    def rtt_shift(self):
        values = self.replies()
        if len(values) < 25:
            return False
        recent, baseline = median(values[-5:]), median(values[-25:-5])
        # Exactly at the step: the previous five did not show the shift yet.
        before = median(values[-6:-1])
        step = max(20, .4 * baseline)
        return abs(recent - baseline) > step and abs(before - baseline) <= step

    def loss_ratio(self):
        total = len(self.attempts)
        return sum(r.kind == 'loss' for r in self.attempts) / total if total else None

    def loss_text(self):
        total = len(self.attempts)
        if not total:
            return 'Потери: нет данных'
        lost = sum(r.kind == 'loss' for r in self.attempts)
        return f'Потери: {lost}/{total} · {100 * lost / total:.1f}%'.replace('.', ',')

    def jitter(self):
        items = list(self.attempts)
        pairs = [abs(b.latency_ms - a.latency_ms) for a, b in zip(items, items[1:])
                 if a.kind == b.kind == 'reply']
        return median(pairs) if len(pairs) >= 10 else None

    def degraded(self):
        completed = list(self.attempts)
        if len(completed) >= self.MIN_ATTEMPTS and self.loss_ratio() >= self.LOSS_THRESHOLD:
            return 'Потери пинга'
        values = self.replies()
        # About 20 s of samples: a single burst of slow replies is not a warning.
        latest = [p.latency_ms for p in completed[-10:] if p.kind == 'reply']
        if len(latest) >= 7:
            current = median(latest)
            if current > self.LATENCY_LIMIT_MS:
                return 'Высокая задержка'
            if len(values) >= 30:
                baseline = median(values[:-10])
                if current > 3 * baseline and current - baseline >= 50:
                    return 'Задержка выросла'
        return ''
