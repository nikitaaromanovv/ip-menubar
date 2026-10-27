"""Read system proxy configuration without reading passwords or client configs."""
from dataclasses import dataclass
import re
from urllib.parse import urlsplit
import fnmatch
from local_network import command
import subprocess


@dataclass(frozen=True)
class ProxyConfig:
    url: str = ''
    kind: str = 'none'
    exceptions: tuple = ()
    exclude_simple: bool = False
    detail: str = ''

    @property
    def signature(self):
        return self.url, self.kind, self.exceptions, self.exclude_simple

    def for_url(self, url):
        host = urlsplit(url).hostname or ''
        if self.exclude_simple and '.' not in host:
            return ''
        for pattern in self.exceptions:
            if fnmatch.fnmatchcase(host.lower(), pattern.lower()):
                return ''
        return self.url

    @property
    def label(self):
        return {'none': 'Прокси нет', 'unknown': 'Прокси: нет данных',
                'pac': 'Прокси: PAC/WPAD'}.get(self.kind, 'Прокси настроен')


def parse_proxy(text):
    def value(key):
        m = re.search(r'^\s*' + key + r'\s*:\s*(.*?)\s*$', text, re.M)
        return m[1] if m else ''
    if value('ProxyAutoConfigEnable') == '1' or value('ProxyAutoDiscoveryEnable') == '1':
        return ProxyConfig(kind='pac', detail='PAC/WPAD не вычисляется')
    exceptions = ()
    m = re.search(r'ExceptionsList\s*:\s*<array>\s*\{(.*?)\}', text, re.S)
    if m:
        exceptions = tuple(re.findall(r'\d+\s*:\s*(\S+)', m[1]))
    for prefix, scheme in (('HTTPS', 'http'), ('SOCKS', 'socks5h')):
        if value(prefix + 'Enable') == '1':
            host, port = value(prefix + 'Proxy'), value(prefix + 'Port')
            if not host or not re.fullmatch(r'[A-Za-z0-9.:-]+', host) or not port.isdigit() or not 0 < int(port) < 65536:
                return ProxyConfig(kind='unknown', detail='Некорректные параметры прокси')
            if ':' in host:
                host = '[' + host + ']'
            return ProxyConfig(f'{scheme}://{host}:{port}', prefix, exceptions,
                               value('ExcludeSimpleHostnames') == '1')
    # HTTP-only proxy does not apply to the HTTPS probes.
    return ProxyConfig(detail='HTTP-прокси не применяется к HTTPS' if value('HTTPEnable') == '1' else '')


def inspect_proxy():
    try:
        return parse_proxy(command(['/usr/sbin/scutil', '--proxy']))
    except (OSError, subprocess.TimeoutExpired):
        return ProxyConfig(kind='unknown', detail='Параметры не прочитаны')
