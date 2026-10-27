"""Private local preferences and bounded event history. No browsing records."""
from dataclasses import asdict, dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time

from ping_monitor import validate_host
from traffic_store import acquire_lock, PERIOD_KEYS

MENUBAR_STYLES = ('full', 'ip', 'flag', 'icon')   # icon+flag+IP, icon+IP, icon+flag, icon only
HISTORY_DAYS = (30, 90, 365)


@dataclass
class Settings:
    ping_host: str = 'google.com'
    traffic_interface: str = 'auto'
    history_enabled: bool = True
    history_days: int = 365
    notifications: bool = False
    menubar_style: str = 'full'
    hover_open: bool = True
    economical: bool = False
    exclude_export_ip: bool = True
    traffic_period: str = 'today'
    warn_no_vpn: bool = False

    # Compatibility helpers for the older two-flag model.
    @property
    def compact_mode(self):
        return self.menubar_style == 'icon'

    @property
    def show_flag(self):
        return self.menubar_style in ('full', 'flag')

    def validate(self):
        self.ping_host = validate_host(self.ping_host)
        if self.traffic_interface != 'auto' and not re.fullmatch(r'(?:en|bridge)\d+', self.traffic_interface):
            raise ValueError('Некорректный интерфейс')
        for field in ('history_enabled', 'notifications', 'hover_open', 'economical', 'exclude_export_ip',
                      'warn_no_vpn'):
            if type(getattr(self, field)) is not bool:
                raise ValueError('Invalid preference')
        if self.menubar_style not in MENUBAR_STYLES:
            raise ValueError('Invalid menu bar style')
        if type(self.history_days) is not int or self.history_days not in HISTORY_DAYS:
            raise ValueError('Invalid retention')
        if self.traffic_period not in PERIOD_KEYS:
            raise ValueError('Invalid period')
        return self


def migrate(data):
    """Older settings used compact_mode/show_flag; unknown keys are ignored."""
    data = dict(data)
    if 'menubar_style' not in data and ('compact_mode' in data or 'show_flag' in data):
        if data.get('compact_mode') is True:
            data['menubar_style'] = 'icon'
        elif data.get('show_flag') is False:
            data['menubar_style'] = 'ip'
        else:
            data['menubar_style'] = 'full'
    return data


class Store:
    def __init__(self, root=None):
        self.root = Path(root) if root else Path.home() / 'Library/Application Support/IP Menubar'
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Single-instance lock before any file is read or modified.
        self.lock = acquire_lock(self.root)
        self.config_path = self.root / 'settings.json'
        self.settings_error = ''
        self.settings = Settings()
        try:
            if self.config_path.exists():
                if self.config_path.stat().st_size > 16384:
                    raise ValueError('Oversized settings')
                data = json.loads(self.config_path.read_text())
                if not isinstance(data, dict):
                    raise ValueError('Invalid settings')
                data = migrate(data)
                allowed = {f for f in Settings.__dataclass_fields__}
                self.settings = Settings(**{k: v for k, v in data.items() if k in allowed}).validate()
        except (OSError, ValueError, TypeError, AttributeError):
            self.settings = Settings()
            self.settings_error = self.preserve_damaged_settings()
        database_path = self.root / 'history.sqlite3'
        self.db = sqlite3.connect(database_path)
        os.chmod(database_path, 0o600)
        self.db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at REAL NOT NULL, '
                        'kind TEXT NOT NULL, message TEXT NOT NULL, evidence TEXT NOT NULL, confidence TEXT NOT NULL)')
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(events)')}
        if 'duration' not in columns:
            self.db.execute('ALTER TABLE events ADD COLUMN duration REAL NOT NULL DEFAULT 0')
        self.prune()
        if not self.settings.history_enabled:
            self.clear()

    def preserve_damaged_settings(self):
        """Keep the unreadable file for inspection; it is never silently overwritten."""
        name = f'settings.damaged-{time.strftime("%Y%m%d-%H%M%S")}.json'
        try:
            os.replace(self.config_path, self.root / name)
            return f'Настройки сброшены · копия: {name}'
        except OSError:
            return 'Настройки сброшены'

    def save(self, settings):
        settings.validate()
        fd, path = tempfile.mkstemp(prefix='settings-', dir=self.root)
        try:
            with os.fdopen(fd, 'w') as out:
                json.dump(asdict(settings), out, ensure_ascii=False, indent=2)
                out.flush()
                os.fsync(out.fileno())
            os.replace(path, self.config_path)
        finally:
            if os.path.exists(path):
                os.unlink(path)
        self.settings = settings
        if not settings.history_enabled:
            self.clear()
        else:
            self.prune()

    def add(self, kind, message, evidence='', confidence='', at=None, duration=0):
        if not self.settings.history_enabled:
            return
        self.db.execute('INSERT INTO events(at,kind,message,evidence,confidence,duration) VALUES(?,?,?,?,?,?)',
                        (time.time() if at is None else at, kind, message[:400], evidence[:600], confidence[:100], max(0, duration)))
        self.prune()

    def prune(self):
        self.db.execute('DELETE FROM events WHERE at < ?', (time.time() - self.settings.history_days * 86400,))
        self.db.commit()

    def recent(self, limit=20):
        self.prune()
        return self.db.execute('SELECT at,kind,message,evidence,confidence FROM events ORDER BY id DESC LIMIT ?',
                               (max(1, min(int(limit), 500)),)).fetchall()

    def count(self):
        return self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]

    def size(self):
        try:
            return (self.root / 'history.sqlite3').stat().st_size
        except OSError:
            return 0

    def clear(self):
        self.db.execute('DELETE FROM events')
        self.db.commit()
        # Logical deletion; not a guarantee of forensic erasure on an SSD/backups.
        self.db.execute('VACUUM')

    def close(self):
        self.db.close()
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    def vpn_drops(self, hours=24):
        """Times traffic went around the VPN, and for how long, in the last `hours`."""
        count, seconds = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(duration), 0) FROM events WHERE kind='vpn_drop' AND at >= ?",
            (time.time() - hours * 3600,)).fetchone()
        return count, seconds

    def summary(self, days=7):
        rows = self.db.execute('SELECT kind,duration FROM events WHERE at >= ?',
                               (time.time() - days * 86400,)).fetchall()
        return {'outages': sum(k == 'offline' for k, _ in rows),
                'duration': sum(d for k, d in rows if k == 'recovered'),
                'degraded': sum(k in ('degraded', 'quality') for k, _ in rows),
                'gaps': sum(k == 'gap' for k, _ in rows)}

    def export_csv(self, path, exclude_ip=True):
        import csv
        from datetime import datetime

        def hide_ip(text):
            text = re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)(?!\w)', '[IP]', text)

            def v6(match):
                token = match.group(0)
                try:
                    if ipaddress.ip_address(token).version == 6:
                        return '[IP]'
                except ValueError:
                    pass
                return token
            return re.sub(r'[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+', v6, text)

        def clean(value):
            text = str(value)
            if exclude_ip:
                text = hide_ip(text)
            # Spreadsheet formula and control prefixes.
            if text and (text[0] in '=+-@\t\r' or text.lstrip().startswith(('=', '+', '-', '@'))):
                text = "'" + text
            return text
        paths = {'system': 'системный маршрут', 'pac-system': 'системный маршрут · PAC не применяется',
                 'unknown-system': 'системный маршрут · прокси не прочитан'}
        with open(path, 'w', newline='', encoding='utf-8-sig') as output:
            writer = csv.writer(output)
            writer.writerow(['Время', 'Событие', 'Описание', 'Причина', 'Длительность, с',
                             'Путь проверки', 'Неполные данные'])
            for at, kind, message, evidence, elapsed, route in self.db.execute(
                    'SELECT at,kind,message,evidence,duration,confidence FROM events ORDER BY at'):
                route = paths.get(route, 'через прокси' if route else '')
                writer.writerow([datetime.fromtimestamp(at).astimezone().isoformat(),
                                 clean(kind), clean(message), clean(evidence), elapsed,
                                 clean(route), 'да' if kind == 'gap' else ''])
