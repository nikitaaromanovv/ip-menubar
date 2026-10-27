"""Persistent measured bytes, independent of history retention. Main-thread only."""
from datetime import date, datetime, timedelta
import fcntl
import os
import sqlite3
import time

PERIODS = (('today', 'Сегодня'), ('7d', '7 дней'), ('30d', '30 дней'),
           ('month', 'Этот месяц'), ('year', 'Этот год'), ('all', 'Все время'))
PERIOD_KEYS = tuple(key for key, _ in PERIODS)


def acquire_lock(root):
    lock = open(root / 'monitor.lock', 'a')
    os.chmod(root / 'monitor.lock', 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise RuntimeError('IP Menubar уже запущен')
    return lock


def period_start(key, today):
    return {'today': today, '7d': today - timedelta(days=6), '30d': today - timedelta(days=29),
            'week': today - timedelta(days=today.weekday()), 'month': today.replace(day=1),
            'year': today.replace(month=1, day=1), 'all': date.min}[key]


class TrafficStore:
    def __init__(self, root, lock=True):
        # The app takes the single-instance lock in Store before opening any database.
        self.lock = acquire_lock(root) if lock else None
        self.db = sqlite3.connect(root / 'traffic.sqlite3')
        os.chmod(root / 'traffic.sqlite3', 0o600)
        self.db.execute('CREATE TABLE IF NOT EXISTS daily(day TEXT PRIMARY KEY, rx INTEGER, tx INTEGER)')
        self.db.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT)')
        self.db.execute('INSERT OR IGNORE INTO meta VALUES(?,?)', ('started', date.today().isoformat()))
        self.db.commit()
        self.previous = None
        self.pending = {}
        self.last_flush = time.monotonic()
        self.closed = False
        self._rows = None  # cached committed rows; invalidated by flush/reset

    def sample(self, counters, interface, at, wall=None):
        wall = wall or datetime.now().astimezone()
        if not interface or interface not in counters:
            self.previous = None
            return
        current = (interface, at, counters[interface])
        old, self.previous = self.previous, current
        if old and old[0] == interface and 0 < at - old[1] <= 30:
            rx, tx = (current[2][i] - old[2][i] for i in (0, 1))
            if min(rx, tx) >= 0:
                key = wall.date().isoformat()
                values = self.pending.setdefault(key, [0, 0])
                values[0] += rx
                values[1] += tx
        if at - self.last_flush >= 5:
            self.flush(at)

    def flush(self, at=None):
        if self.pending:
            with self.db:
                for day, (rx, tx) in self.pending.items():
                    self.db.execute('INSERT INTO daily VALUES(?,?,?) ON CONFLICT(day) DO UPDATE '
                                    'SET rx=rx+excluded.rx,tx=tx+excluded.tx', (day, rx, tx))
            self.pending.clear()
            self._rows = None
        self.last_flush = time.monotonic() if at is None else at

    def rows(self):
        if self._rows is None:
            self._rows = {day: (rx, tx) for day, rx, tx in self.db.execute('SELECT day,rx,tx FROM daily')}
        rows = {day: list(values) for day, values in self._rows.items()}
        for day, values in self.pending.items():
            row = rows.setdefault(day, [0, 0])
            row[0] += values[0]; row[1] += values[1]
        return rows

    def range_totals(self, start, end, rows=None):
        rows = self.rows() if rows is None else rows
        first, last = start.isoformat(), end.isoformat()
        return tuple(sum(v[i] for d, v in rows.items() if first <= d <= last) for i in (0, 1))

    def period(self, key, today=None):
        today = today or date.today()
        return self.range_totals(period_start(key, today), today)

    def totals(self, today=None):
        today = today or date.today()
        rows = self.rows()
        names = (('Сегодня', 'today'), ('7 дней', '7d'), ('Эта неделя', 'week'), ('30 дней', '30d'),
                 ('Этот месяц', 'month'), ('Этот год', 'year'), ('Все время', 'all'))
        return {name: self.range_totals(period_start(key, today), today, rows) for name, key in names}

    def daily(self, days=14, today=None):
        today = today or date.today()
        rows = self.rows()
        result = []
        for offset in range(days):
            day = today - timedelta(days=offset)
            rx, tx = rows.get(day.isoformat(), (0, 0))
            result.append((day, rx, tx))
        return result

    def reset(self):
        with self.db:
            self.db.execute('DELETE FROM daily')
            self.db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', ('started', date.today().isoformat()))
        self.pending.clear()
        self.previous = None
        self._rows = None

    @property
    def started(self):
        return self.db.execute('SELECT value FROM meta WHERE key="started"').fetchone()[0]

    def close(self):
        if self.closed:
            return
        try:
            self.flush()
        finally:
            self.closed = True
            self.db.close()
            if self.lock is not None:
                self.lock.close()


def format_bytes(value):
    for unit in ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ'):
        if value < 1000 or unit == 'ТБ':
            return f'{value:.1f} {unit}'.replace('.', ',') if unit != 'Б' else f'{value} Б'
        value /= 1000


def parse_range(text, today=None):
    """'01.10.2026 - 24.10.2026' or a single date. Returns (start, end)."""
    today = today or date.today()
    cleaned = text.replace('—', '-').replace('–', '-').replace('…', '-')
    parts = [p.strip() for p in cleaned.split('-') if p.strip()]
    if not 1 <= len(parts) <= 2:
        raise ValueError('Формат: ДД.ММ.ГГГГ - ДД.ММ.ГГГГ')
    try:
        dates = [datetime.strptime(p, '%d.%m.%Y').date() for p in parts]
    except ValueError:
        raise ValueError('Формат: ДД.ММ.ГГГГ - ДД.ММ.ГГГГ')
    start, end = dates[0], dates[-1]
    if start > end:
        start, end = end, start
    if end > today:
        end = today
    return start, end
