"""Pure state machine: failures of selected probes are observations, not attribution."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Probe:
    group: str
    ok: bool
    detail: str
    at: float
    latency_ms: float = 0
    dns_ms: float = 0
    source: str = ''
    local_ip: str = ''
    reachable: bool = False
    retry_after: int = 0


@dataclass(frozen=True)
class Cycle:
    probes: tuple
    generation: int
    started: float
    finished: float
    path: str = 'system'
    limited: str = ''


class Connectivity:
    """HTTPS reachability state plus a separate, slower 'quality' layer.

    Reachability (online/degraded/offline/recovering) comes from HTTPS cycles and
    fresh successes. Quality warnings (ping loss/latency) never clear or create
    outages; they only colour an otherwise online state and have their own
    start/stop events, so they cannot flap the reachability state.
    """

    def __init__(self):
        self.generation = 0
        self.status = 'pending'
        self.reason = 'Проверка связи…'
        self.last_success = float('-inf')
        self.last_success_kind = ''
        self.last_cycle = None
        self.fail_cycles = 0
        self.good_cycles = 0
        self.problem_since = None
        self.offline_since = None
        self.fail_series_start = None
        self.was_offline = False
        self.quality_reason = ''
        self.quality_since = None
        self.events = []

    def reset(self, now):
        if self.problem_since is not None or self.quality_since is not None:
            self.events.append(('gap', 'Перерыв в измерениях', 0))
        self.generation += 1
        self.status, self.reason = 'pending', 'Проверка связи…'
        self.last_success = float('-inf')
        self.last_success_kind = ''
        self.last_cycle = None
        self.fail_cycles = self.good_cycles = 0
        self.problem_since = self.offline_since = self.fail_series_start = None
        self.was_offline = False
        self.quality_reason, self.quality_since = '', None

    def success(self, at, kind='icmp'):
        """Returns True when this success ended a confirmed outage."""
        if at >= self.last_success:
            self.last_success = at
            self.last_success_kind = kind
        if self.status == 'offline':
            elapsed = max(0, at - self.offline_since)
            self.events.append(('recovered', 'Связь восстановлена', elapsed))
            self.offline_since = None
            self.status, self.reason = 'recovering', 'Восстановление связи'
            # A later outage must start its own series, not inherit this one's start.
            self.good_cycles = self.fail_cycles = 0
            self.fail_series_start = None
            return True
        return False

    def warning(self, now, reason):
        if self.problem_since is None:
            self.problem_since = now
            self.events.append(('degraded', reason, 0))
        if self.status != 'offline':
            self.status, self.reason = 'degraded', reason

    def set_quality(self, now, reason):
        if not reason:
            return
        if self.quality_since is None:
            self.quality_since = now
            self.events.append(('quality', reason, 0))
        self.quality_reason = reason

    def clear_quality(self, now):
        if self.quality_since is not None:
            self.events.append(('quality_ok', 'Пинг в норме', now - self.quality_since))
        self.quality_reason, self.quality_since = '', None

    def _clear_problem(self, now):
        if self.problem_since is not None:
            self.events.append(('stable', 'Связь стабильна', now - self.problem_since))
        self.problem_since = None
        self.was_offline = False
        self.status, self.reason = 'online', 'Связь стабильна'

    def apply(self, cycle):
        if cycle.generation != self.generation:
            return False
        self.last_cycle = cycle
        now = cycle.finished
        if cycle.limited:
            self.warning(now, cycle.limited)
            self.fail_cycles = 0
            self.fail_series_start = None
            return True
        successes = [p for p in cycle.probes if p.ok]
        for p in successes:
            self.success(p.at, 'https')
        groups = {p.group for p in cycle.probes}
        complete = groups >= {'ru', 'global'}
        if successes and complete and all(p.ok for p in cycle.probes):
            self.fail_cycles = 0
            self.fail_series_start = None
            self.good_cycles += 1
            # Two good cycles are required only after a confirmed outage.
            if self.was_offline and self.good_cycles < 2:
                self.status, self.reason = 'recovering', 'Восстановление связи'
            else:
                self._clear_problem(now)
        elif successes:
            self.fail_cycles = self.good_cycles = 0
            self.fail_series_start = None
            ru = any(p.ok and p.group == 'ru' for p in cycle.probes)
            foreign = any(p.ok and p.group == 'global' for p in cycle.probes)
            reason = ('Доступны только российские ресурсы'
                      if ru and not foreign else 'Часть проверок не проходит')
            self.warning(cycle.started, reason)
        elif any(p.reachable for p in cycle.probes):
            self.success(now, 'http_response')
            self.fail_cycles = self.good_cycles = 0
            self.fail_series_start = None
            self.warning(now, 'Неожиданный ответ проверок')
        elif not complete:
            self.fail_cycles = self.good_cycles = 0
            self.fail_series_start = None
            self.warning(now, 'Проверка неполная')
        else:
            self.fail_cycles += 1
            self.good_cycles = 0
            if self.fail_series_start is None:
                self.fail_series_start = cycle.started
            fresh = now - self.last_success <= 6
            self.warning(cycle.started, ('Пинг есть · HTTPS нет'
                         if self.last_success_kind == 'icmp' else 'Проверки не проходят · другой HTTPS есть')
                         if fresh else 'Проверки не проходят')
            if self.fail_cycles >= 2 and not fresh:
                if self.offline_since is None:
                    # Duration starts at the first failed cycle of this series, not at an
                    # earlier unrelated degradation.
                    self.offline_since = self.fail_series_start
                    self.was_offline = True
                    self.events.append(('offline', 'Нет связи', 0))
                self.status, self.reason = 'offline', 'Нет связи'
        return True

    def display(self, now, interval=30):
        if self.last_cycle and now - self.last_cycle.finished > interval + 5:
            return 'pending', 'Нет свежих данных'
        if self.status == 'online' and self.quality_reason:
            return 'degraded', self.quality_reason
        return self.status, self.reason
