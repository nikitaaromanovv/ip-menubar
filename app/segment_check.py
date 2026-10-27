"""On-demand observations along the current route; never bypasses a VPN."""
import ipaddress
import re
import subprocess
from local_network import command
from ping_monitor import ping_once
from probes import check_cycle


def check_segments(generation, proxy):
    lines = []
    gateway = ''
    try:
        route = command(['/sbin/route', '-n', 'get', 'default'])
        match = re.search(r'^\s*gateway:\s*(\S+)', route, re.M)
        if match:
            gateway = str(ipaddress.ip_address(match[1]))
    except (ValueError, OSError, subprocess.TimeoutExpired):
        pass
    if gateway:
        result = ping_once(gateway)
        lines.append(f'Шлюз {gateway}: ' + (
            f'{result.latency_ms:.0f} мс' if result.kind == 'reply' else 'нет ответа на ICMP'))
    else:
        lines.append('Шлюз: не определен')
    cycle = check_cycle(generation, proxy)
    if proxy.kind in ('pac', 'unknown'):
        lines.append('Путь: системный маршрут')
    if cycle.limited:
        lines.append(cycle.limited)
    for probe in cycle.probes:
        lines.append(('Российский ресурс: ' if probe.group == 'ru' else 'Зарубежный ресурс: ') + probe.detail)
    if cycle.probes and all(p.ok for p in cycle.probes):
        lines.append('Итог: внешние ресурсы доступны')
    elif any(p.ok for p in cycle.probes):
        lines.append('Итог: часть ресурсов недоступна')
    else:
        lines.append('Итог: внешние ресурсы недоступны')
    return generation, '\n'.join(lines)
