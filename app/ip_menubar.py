"""IP Menubar: main-thread UI, bounded independent worker lanes."""
from dataclasses import replace
from datetime import datetime
import ipaddress
import logging
import time
import subprocess

import rumps
from Foundation import NSRunLoop, NSRunLoopCommonModes

from connectivity import Connectivity
from event_history import Store
from local_network import TrafficSampler, TrafficRate, format_rate, inspect_vpn, read_traffic, command
from network_monitor import country_code_to_flag, duration, age, number
from ping_monitor import PingWindow, ping_once, validate_host, reset_resolution
from workers import Lane
from presentation import status_title
from probes import check_cycle, IPChecker, check_site
from proxy_monitor import ProxyConfig, inspect_proxy
from segment_check import check_segments
from traffic_store import TrafficStore, format_bytes, PERIODS, PERIOD_KEYS, parse_range
from vpn_state import Exit, VPNTracker, badge, classify, short

log = logging.getLogger('ip_menubar')

IP_TRIGGERS = {'ping_resumed': 'пинг возобновился', 'ttl_changed': 'изменился TTL',
               'rtt_shift': 'скачок задержки', 'recovered': 'связь восстановлена',
               'network': 'сеть изменилась', 'manual': 'вручную', 'periodic': 'по расписанию'}
PATH_LABELS = {'system': 'системный маршрут', 'pac-system': 'системный маршрут · PAC не применяется',
               'unknown-system': 'системный маршрут · прокси не прочитан'}


def ipv4_addresses(text):
    found = []
    for line in text.splitlines():
        if 'address' not in line:
            continue
        value = line.split(':', 1)[-1].strip()
        try:
            if ipaddress.ip_address(value).version == 4:
                found.append(value)
        except ValueError:
            continue
    return tuple(found)


def inspect_context():
    snapshot, proxy = inspect_vpn(), inspect_proxy()
    try:
        # IPv4 only: rotating temporary IPv6 addresses must not look like a network change.
        addresses = ipv4_addresses(command(['/usr/sbin/scutil', '--nwi']))
    except (OSError, subprocess.TimeoutExpired):
        addresses = ()
    return snapshot, proxy, addresses


def cycle_is_healthy(cycle, now, freshness=35):
    return bool(cycle and cycle.probes and now - cycle.finished <= freshness and all(p.ok for p in cycle.probes))


class IPMenuBarApp(rumps.App):
    QUALITY_ENTER_AFTER = 20   # a ping problem must last this long before the icon turns yellow
    QUALITY_CLEAR_AFTER = 30   # seconds of clean ping before the quality warning ends
    STABLE_AFTER = 4           # healthy HTTPS cycles in a row before checks slow down

    def __init__(self, store=None):
        super().__init__('IP Menubar', title='', quit_button=None)
        self.dashboard = None
        self.settings_window = None
        self.store = store or Store()
        self.settings = self.store.settings
        self.traffic_store = TrafficStore(self.store.root, lock=False)
        self.storage_error = self.store.settings_error
        self.health = Connectivity()
        self.proxy = ProxyConfig(kind='unknown', detail='Проверка настроек сети')
        self.snapshot = None
        self.context_signature = self.context_candidate = None
        self.context_count = 0
        self.ip_checker = IPChecker()
        self.ip = self.country = self.country_code = self.previous_ip = ''
        self.ip_org = self.ip_asn = ''
        self.ip_detail = self.direct_ip = ''
        self.ip_at = 0
        self.ip_generation = -1
        self.ip_reason = 'periodic'
        self.last_ip_reason = ''
        self.last_ip_request = float('-inf')
        self.pings = PingWindow()
        self.traffic_sampler = TrafficSampler()
        self.traffic_rate = TrafficRate()
        self.traffic_at = 0
        self.peak_rate = 0.0
        self.quality_ok_since = self.quality_bad_since = None
        self.last_tick = time.monotonic()
        self.fast_cycles = 0
        self.healthy_streak = 0
        self.cycle_period = 30          # interval the last HTTPS cycle was scheduled with
        self.was_visible = False
        self.https_not_before = self.ip_not_before = 0.0
        self.last_cycle_start = float('-inf')
        self.last_fallback = float('-inf')
        self.dialog_open = False
        self.closed = False
        self.sleeping = False
        self.site_result = ''
        self.site_title = 'ПРОВЕРКА САЙТА'
        self.traffic_query = ''
        self.activity = None
        self.last_title = None
        self.last_data = None
        self.vpn_tracker = VPNTracker()
        self.vpn_state, self.vpn_text = 'unknown', ''
        self.v6 = None                       # Exit of IPv6 traffic, None when there is none
        self.v6_known = False                # whether an IPv6 check has run at all
        self.last_v6_check = float('-inf')
        self.vpn_report = ''
        self.drop_cache = (float('-inf'), (0, 0))
        self.lanes = {key: Lane(key) for key in ('https', 'ping', 'context', 'traffic', 'ip', 'site', 'segments', 'vpn')}
        self.due = {key: 0.0 for key in self.lanes}
        self.menu = [rumps.MenuItem('Обновить', callback=self.manual_refresh),
                     rumps.MenuItem('Открыть окно', callback=self.open_dashboard_window),
                     rumps.MenuItem('Проверить сайт…', callback=self.test_site),
                     rumps.MenuItem('Проверить загрузку сайта…', callback=self.test_download),
                     rumps.MenuItem('Проверить маршрут', callback=self.test_segments),
                     rumps.MenuItem('Проверить VPN', callback=self.run_vpn_check),
                     rumps.MenuItem('Трафик за даты…', callback=self.ask_traffic_range),
                     None,
                     rumps.MenuItem('Настройки…', callback=self.open_settings),
                     None, rumps.MenuItem('Завершить', callback=self.quit)]
        self.timer = rumps.Timer(self.tick, 1)
        self.timer.start()
        NSRunLoop.mainRunLoop().addTimer_forMode_(self.timer._nstimer, NSRunLoopCommonModes)
        self.record('gap', 'Запуск мониторинга')
        self.tick(None)

    # ----- scheduling -------------------------------------------------------------------

    @property
    def interval(self):
        """Base HTTPS interval; used while anything is unsettled."""
        return 60 if self.settings.economical else 30

    def next_interval(self):
        """A stable link is watched by ping every 2 s; a failed ping asks HTTPS at once,
        so the HTTPS cycle itself can be rare while everything is fine."""
        stable = (self.healthy_streak >= self.STABLE_AFTER and self.health.status == 'online'
                  and not self.health.quality_reason and self.pings.failures == 0 and self.pings.replies())
        return (300 if self.settings.economical else 120) if stable else self.interval

    @property
    def freshness(self):
        return max(self.interval, self.cycle_period) + 5

    @property
    def ip_interval(self):
        # The IP is also re-read at once on path signals; this is only the safety net.
        return 300 if self.settings.economical else 120

    @property
    def context_interval(self):
        # Ping signals and failures request the context at once; this is the safety net.
        return 30 if self.settings.economical else 15

    def panel_visible(self):
        return bool(self.dashboard and self.dashboard.is_visible())

    def record(self, kind, message, evidence='', elapsed=0):
        cycle = self.health.last_cycle
        try:
            self.store.add(kind, message, evidence, cycle.path if cycle else '', duration=elapsed)
        except Exception:
            log.exception('History write failed')
            self.storage_error = 'История не сохраняется'

    def drain_events(self):
        for kind, message, elapsed in self.health.events:
            self.record(kind, message, elapsed=elapsed)
            if self.settings.notifications and kind in ('offline', 'recovered'):
                try:
                    rumps.notification('IP Menubar', message, duration(elapsed) if elapsed else '')
                except Exception:
                    log.exception('Notification failed')
        self.health.events.clear()

    def reset_network(self, now):
        self.health.reset(now)
        self.fast_cycles = 0
        self.healthy_streak = 0
        self.pings = PingWindow()
        self.quality_ok_since = self.quality_bad_since = None
        reset_resolution()
        self.traffic_sampler = TrafficSampler()
        self.traffic_store.previous = None
        self.ip_generation = -1
        self.ip_reason = 'network'
        self.v6, self.v6_known = None, False
        for key in ('https', 'ping', 'ip', 'context'):
            self.due[key] = 0

    def request_ip(self, now, reason):
        """Re-read the external IP soon: a router VPN switch is invisible in Mac routes.
        Signals closer than 10 s apart are delayed, not dropped; a manual refresh is
        immediate. A server-requested cooldown (ip_not_before) is still respected."""
        at = now if reason == 'manual' else max(now, self.last_ip_request + 10)
        self.last_ip_request = at
        self.ip_reason = reason
        self.due['ip'] = min(self.due['ip'], at)

    def tick(self, _):
        if self.sleeping or self.closed:
            return
        now = time.monotonic()
        # Real sleep arrives as on_sleep/on_wake. A long gap here means a stalled timer;
        # only a very long one is treated as lost continuity.
        if now - self.last_tick > 60:
            self.reset_network(now)
        self.last_tick = now
        for name, lane in self.lanes.items():
            job = lane.poll()
            if job is not None:
                self.consume(name, job)
        generation = self.health.generation
        visible = self.panel_visible()
        if visible and not self.was_visible:
            self.due['traffic'] = now  # live rate right away when the panel opens
        self.was_visible = visible
        if now >= self.due['context'] and self.lanes['context'].launch(inspect_context):
            self.due['context'] = now + self.context_interval
        if self.context_signature is not None and now >= max(self.due['https'], self.https_not_before) and now - self.last_cycle_start >= 2:
            if self.lanes['https'].launch(check_cycle, generation, self.proxy):
                self.last_cycle_start = now
                self.cycle_period = max(self.cycle_period, self.interval)
                self.due['https'] = now + self.interval
        if now >= self.due['ping']:
            host = self.settings.ping_host
            if self.lanes['ping'].launch(lambda g=generation, h=host: (g, ping_once(h))):
                self.due['ping'] = now + (5 if self.settings.economical else 2)
        if now >= self.due['traffic']:
            if self.lanes['traffic'].launch(lambda g=generation: (g, read_traffic())):
                # Live rate only matters while it is on screen; totals stay exact either way.
                self.due['traffic'] = now + (1 if visible else 15 if self.settings.economical else 10)
        if self.context_signature is not None and now >= max(self.due['ip'], self.ip_not_before):
            config, reason = self.proxy, self.ip_reason
            # IPv6 leak check every 5 minutes and whenever the path may have changed.
            with_v6 = reason != 'periodic' or now - self.last_v6_check >= 300
            if self.lanes['ip'].launch(lambda g=generation, c=config, r=reason, v=with_v6:
                                       (g, r, self.ip_checker.check(c, v))):
                self.due['ip'] = now + self.ip_interval
                self.ip_reason = 'periodic'
                if with_v6:
                    self.last_v6_check = now
        self.drain_events()
        self.update_activity(now, visible)
        self.render()

    def update_activity(self, now, visible):
        """Ask macOS not to throttle timers only while the panel is open or a fault is
        being confirmed (bounded to two minutes), never permanently."""
        status = self.health.status
        confirming = status in ('degraded', 'offline', 'recovering') and (
            self.health.problem_since is not None and now - self.health.problem_since < 120)
        need = visible or confirming
        if need == (self.activity is not None):
            return
        try:
            import Foundation
            info = Foundation.NSProcessInfo.processInfo()
            if need:
                options = getattr(Foundation, 'NSActivityUserInitiatedAllowingIdleSystemSleep', 0x00EFFFFF)
                self.activity = info.beginActivityWithOptions_reason_(options, 'IP Menubar: проверка связи')
            else:
                info.endActivity_(self.activity)
                self.activity = None
        except Exception:
            self.activity = None

    # ----- results ----------------------------------------------------------------------

    def high_load(self):
        t = self.traffic_rate
        rate = max(t.down or 0, t.up or 0)
        return rate >= max(500_000, .5 * self.peak_rate)

    def update_quality(self, now):
        # No replies at all means ICMP is filtered, not that the link is poor; the panel
        # says 'пинг недоступен' and HTTPS decides reachability.
        reason = self.pings.degraded() if self.pings.replies() else ''
        if reason and self.health.problem_since is not None:
            return  # a reachability problem is already shown; losses are part of it
        if reason:
            self.quality_ok_since = None
            if self.health.quality_since is None:
                # Entering needs persistence too: short bursts never colour the icon.
                if self.quality_bad_since is None:
                    self.quality_bad_since = now
                if now - self.quality_bad_since < self.QUALITY_ENTER_AFTER:
                    return
            if self.high_load():
                reason += ' · канал загружен'
            self.health.set_quality(now, reason)
        else:
            self.quality_bad_since = None
            if self.health.quality_since is not None:
                if self.quality_ok_since is None:
                    self.quality_ok_since = now
                    # Say plainly that this is the tail of a past problem, not a current one.
                    base = self.health.quality_reason.removeprefix('Недавно: ')
                    self.health.quality_reason = 'Недавно: ' + base[:1].lower() + base[1:]
                elif now - self.quality_ok_since >= self.QUALITY_CLEAR_AFTER:
                    self.health.clear_quality(now)
                    self.quality_ok_since = None

    def end_outage(self, now):
        """Lost probes of a confirmed outage describe the outage, not the quality after it."""
        self.pings.forget_losses()
        self.health.clear_quality(now)
        self.quality_ok_since = self.quality_bad_since = None
        self.fast_cycles = 0  # confirm recovery with fast cycles, not the normal interval
        self.request_ip(now, 'recovered')
        self.due['https'] = min(self.due['https'], now)  # confirm recovery without waiting

    def consume(self, name, job):
        now = time.monotonic()
        if job.error:
            if name == 'https':
                self.health.warning(now, 'Ошибка проверки')
            elif name == 'traffic':
                self.traffic_rate = TrafficRate(detail='Счетчики недоступны')
                self.traffic_sampler.previous = self.traffic_store.previous = None
            elif name in ('site', 'segments'):
                self.site_result = 'Ошибка проверки · см. журнал'
            elif name == 'vpn':
                self.vpn_report = 'Ошибка проверки VPN · см. журнал'
            return
        if name == 'https':
            before = self.health.status
            if self.health.apply(job.value):
                if before == 'offline' and self.health.status != 'offline':
                    self.end_outage(now)
                elif before in ('degraded', 'recovering') and self.health.status == 'online':
                    self.request_ip(now, 'recovered')
                if self.health.status in ('degraded', 'recovering', 'offline'):
                    self.fast_cycles = self.fast_cycles + 1
                    self.healthy_streak = 0
                    self.cycle_period = self.interval
                    self.due['https'] = now + (2 if self.fast_cycles <= 2 else self.interval)
                else:
                    self.fast_cycles = 0
                    healthy = bool(job.value.probes) and all(p.ok for p in job.value.probes)
                    self.healthy_streak = self.healthy_streak + 1 if healthy else 0
                    self.cycle_period = self.next_interval()
                    self.due['https'] = now + self.cycle_period
                cooldown = max((p.retry_after for p in job.value.probes), default=0)
                if cooldown:
                    self.https_not_before = max(self.https_not_before, now + cooldown)
                    self.due['https'] = max(self.due['https'], now + cooldown)
                    self.last_fallback = now + cooldown
                if self.ip_generation != self.health.generation and any(p.ok for p in job.value.probes):
                    self.due['ip'] = min(self.due['ip'], now)
        elif name == 'ping':
            generation, result = job.value
            if generation != self.health.generation:
                return
            self.pings.add(result)
            if result.kind == 'reply':
                if self.health.success(result.at):
                    self.end_outage(now)
                else:
                    cycle = self.health.last_cycle
                    if cycle and cycle.probes and not any(p.ok for p in cycle.probes):
                        self.health.warning(now, 'Пинг есть · HTTPS нет')
            for signal in self.pings.take_signals():
                self.request_ip(now, signal)
                self.due['context'] = min(self.due['context'], now)  # routes may have changed too
                if signal in ('ttl_changed', 'rtt_shift'):
                    # A different path (e.g. VPN on the router toggled) has its own normal
                    # latency; comparing it with the old path would be a false warning.
                    self.pings.rebase()
            self.update_quality(now)
            # A new failure after a reply asks HTTPS at once; persistent ICMP filtering
            # does not raise the HTTPS rate above the normal interval.
            if result.kind != 'reply':
                self.healthy_streak = 0
            if result.kind != 'reply' and now >= self.last_fallback and (
                    self.pings.failures == 1 or now - self.last_fallback >= self.interval):
                self.due['https'] = min(self.due['https'], now)
                if self.pings.failures == 1:
                    self.due['context'] = min(self.due['context'], now)
                self.last_fallback = now
            if self.pings.failures >= 3:
                cycle = self.health.last_cycle
                if not cycle or not any(p.ok for p in cycle.probes) or now - cycle.finished > self.freshness:
                    self.health.warning(now, 'Нет ответа пинга')
        elif name == 'context':
            snapshot, config, addresses = job.value
            signature = (snapshot.routes, config.signature, addresses)
            self.snapshot = snapshot
            if signature == self.context_candidate:
                self.context_count += 1
            else:
                self.context_candidate, self.context_count = signature, 1
                if self.context_signature is not None and signature != self.context_signature:
                    self.due['context'] = min(self.due['context'], now + 2)  # confirm quickly
            if self.context_signature is None or self.context_count >= 2:
                if signature != self.context_signature:
                    previous = self.context_signature
                    self.context_signature = signature
                    self.proxy = config
                    self.reset_network(now)
                    if previous is not None:
                        self.record('route', 'Сеть изменилась', snapshot.label)
                    self.update_vpn(now)
        elif name == 'traffic':
            generation, values = job.value
            if generation != self.health.generation:
                return
            counters, preferred, at = values
            self.traffic_at = at
            self.traffic_rate = self.traffic_sampler.sample(counters, preferred, at)
            rate = max(self.traffic_rate.down or 0, self.traffic_rate.up or 0)
            self.peak_rate = max(rate, self.peak_rate * .995)
            try:
                self.traffic_store.sample(counters, preferred, at)
            except Exception:
                log.exception('Traffic write failed')
                self.storage_error = 'Трафик не сохраняется'
        elif name == 'ip':
            generation, reason, result = job.value
            if generation != self.health.generation:
                return
            if result.retry_after:
                self.ip_not_before = max(self.ip_not_before, now + result.retry_after)
                self.due['ip'] = max(self.due['ip'], now + result.retry_after)
            if not result.ip:
                return
            changed = self.ip != result.ip
            if self.ip and changed:
                self.previous_ip = self.ip
                self.record('ip', 'Смена IP',
                            f'{self.ip} → {result.ip} · {IP_TRIGGERS.get(reason, reason)}')
            if changed or result.code:
                # A failed geolocation of a new IP clears the old country instead of keeping it.
                self.country, self.country_code = result.country, result.code
                self.ip_org, self.ip_asn = result.org, result.asn
            self.ip, self.ip_detail = result.ip, result.detail
            self.direct_ip = result.direct_ip
            self.ip_at, self.ip_generation = result.at, generation
            self.last_ip_reason = reason
            if result.geo_retry:
                # Country lookup was throttled for a new IP; ask again shortly.
                self.due['ip'] = min(self.due['ip'], now + result.geo_retry)
            if result.v6_checked:
                self.v6_known = True
                self.v6 = Exit(result.v6_ip, result.v6_org, result.v6_asn) if result.v6_ip else None
            self.update_vpn(now)
            if self.health.success(result.at, 'https'):
                self.end_outage(now)
        elif name == 'vpn':
            self.vpn_report = job.value
            if self.dashboard:
                self.dashboard.show_details()
        elif name in ('site', 'segments'):
            generation, result = job.value
            self.site_result = result if generation == self.health.generation else 'Сеть изменилась · повторите проверку'
            if self.dashboard:
                self.dashboard.show_details()

    # ----- presentation -----------------------------------------------------------------

    def current_exit(self):
        return Exit(self.ip, self.ip_org, self.ip_asn)

    def update_vpn(self, now):
        """Combine the Mac's routes with the exit network; record drops around the VPN."""
        kind = self.snapshot.kind if self.snapshot else ''
        # Right after a network change the old exit IP is not evidence about the new path.
        exit = self.current_exit() if self.ip_generation == self.health.generation else Exit()
        state, text = classify(kind, exit, self.v6)
        if state == 'unknown':
            return
        self.vpn_state, self.vpn_text = state, text
        for event in self.vpn_tracker.observe(state, now, exit):
            kind_, message, evidence = event[:3]
            self.record(kind_, message, evidence, elapsed=event[3] if len(event) > 3 else 0)
            self.drop_cache = (float('-inf'), (0, 0))
            if (self.settings.warn_no_vpn and self.settings.notifications
                    and kind_ in ('vpn_off', 'vpn_drop', 'ipv6_leak')):
                try:
                    rumps.notification('IP Menubar', message, evidence)
                except Exception:
                    log.exception('Notification failed')

    def drops_today(self, fresh=False):
        now = time.monotonic()
        at, value = self.drop_cache
        if fresh or now - at > 60:
            try:
                value = self.store.vpn_drops(hours=24)
            except Exception:
                value = (0, 0)
            self.drop_cache = (now, value)
        return value

    def tunnel_text(self):
        if not self.snapshot:
            return 'VPN: проверка…'
        label = self.vpn_text or self.snapshot.label
        count, _ = self.drops_today()
        if count:
            label += f' · обрывы за 24 ч: {count}'
        return label

    def proxy_badge(self, label):
        if self.proxy.kind == 'none':
            return 'gray'
        if 'работает' in label:
            return 'green'
        if 'не отвечает' in label or 'не проходит' in label:
            return 'red'
        return 'amber'

    def traffic_line(self):
        key = self.settings.traffic_period if self.settings.traffic_period in PERIOD_KEYS else 'today'
        rx, tx = self.traffic_store.period(key)
        return f'{dict(PERIODS)[key]}: ↓ {format_bytes(rx)} · ↑ {format_bytes(tx)}  ›'

    def view_data(self):
        now = time.monotonic()
        status, reason = self.health.display(now, self.freshness - 5)
        if status == 'offline' and self.health.offline_since is not None:
            reason += ' · ' + duration(now - self.health.offline_since)
        p = self.pings.last
        fresh_ping = p is not None and now - p.at <= 10
        ping_value = (f'{p.latency_ms:.0f} мс' if fresh_ping and p.kind == 'reply' else
                      'Нет ответа' if fresh_ping and p.kind == 'loss' else '—')
        loss = self.pings.loss_ratio()
        t = self.traffic_rate if now - self.traffic_at <= 20 else TrafficRate(detail='Нет замера')
        if self.pings.failures >= 3 and cycle_is_healthy(self.health.last_cycle, now, self.freshness):
            if status == 'online':
                reason = 'Связь есть · пинг недоступен'
        # One late periodic check is normal (timers can be deferred); two missed ones are not.
        stale = (self.ip_generation != self.health.generation or now - self.ip_at > 2 * self.ip_interval + 15
                 or status == 'offline')
        subtitle = (f'{"Последний IP · " if stale else ""}{self.country or "Страна не определена"}'
                    + (f' · {age(now - self.ip_at)}' if self.ip_at else ''))
        cycle = self.health.last_cycle
        proxy = self.proxy.label
        if self.proxy.url and cycle and not cycle.limited and self.proxy.kind not in ('pac', 'unknown'):
            through_proxy = [p for p in cycle.probes if self.proxy.for_url(p.source)]
            if through_proxy:
                proxy = 'Прокси работает' if any(p.ok for p in through_proxy) else 'Прокси: HTTPS не проходит'
                if any('авторизацию' in p.detail for p in through_proxy):
                    proxy = 'Прокси требует авторизацию'
                elif all('Соединение не установлено' in p.detail or 'DNS прокси' in p.detail for p in through_proxy):
                    proxy = 'Прокси не отвечает'
        flag = (country_code_to_flag(self.country_code) + ' ') if self.country_code else ''
        return dict(ip=flag + (self.ip or 'IP не определен'),
                    country=subtitle, connection=reason, status=status, ping_value=ping_value,
                    loss_value=f'{100 * loss:.0f}%' if loss is not None else '—',
                    down=format_rate(t.down), up=format_rate(t.up), vpn=self.tunnel_text(), proxy=proxy,
                    vpn_badge=badge(self.vpn_state, self.settings.warn_no_vpn), proxy_badge=self.proxy_badge(proxy),
                    today=self.traffic_line(),
                    compact=self.settings.menubar_style == 'icon',
                    details=self.details_text() if self.panel_visible() else '',
                    storage=self.storage_error, stale=stale)

    def render(self):
        data = self.view_data()
        title = status_title(self.ip, self.country_code, self.settings.menubar_style)
        if title != self.last_title:
            self.title = title
            self.last_title = title
        # Only changed data reaches AppKit; an idle panel causes no redraws.
        if self.dashboard and data != self.last_data:
            self.dashboard.update(data)
        self.last_data = data

    def details_text(self):
        totals = self.traffic_store.totals()
        lines = ['ПРОВЕРКИ СВЯЗИ']
        cycle = self.health.last_cycle
        if cycle:
            lines.append('Путь: ' + PATH_LABELS.get(cycle.path, 'прокси'))
            if cycle.limited:
                lines.append(cycle.limited)
            for p in cycle.probes:
                lines.append(f'{p.source}\n{p.detail} · HTTPS {p.latency_ms:.0f} мс · DNS {p.dns_ms:.0f} мс\n'
                             f'Локальный адрес: {p.local_ip or "—"}')
        lines += ['', 'ПИНГ', f'{self.settings.ping_host} · {self.pings.loss_text()}']
        jitter = self.pings.jitter()
        lines.append(f'Разброс RTT: {number(jitter)} мс' if jitter is not None else 'Разброс RTT: нет данных')
        if self.pings.last_ttl is not None:
            lines.append(f'TTL: {self.pings.last_ttl}')
        if self.health.quality_reason:
            lines.append(f'Качество: {self.health.quality_reason}')
        lines.append(f'Порог: потери от 15% · задержка выше 200 мс или в 3 раза выше обычной · '
                     f'дольше {self.QUALITY_ENTER_AFTER} с')
        lines += ['', 'VPN', self.vpn_text or 'Проверка…']
        if self.v6_known:
            lines.append(f'IPv6: {self.v6.ip} · {short(self.v6.org, self.v6.asn)}' if self.v6 else 'IPv6: нет')
        count, seconds = self.drops_today()
        lines.append(f'Обрывы за 24 ч: {count} · {int(seconds)} с без VPN' if count else 'Обрывы за 24 ч: нет')
        if self.vpn_report:
            lines += ['', self.vpn_report]
        if self.snapshot:
            lines += ['', 'МАРШРУТЫ', self.snapshot.label, self.snapshot.summary,
                      'IPv4: ' + ', '.join(i or 'нет данных' for i in self.snapshot.routes[:2]),
                      'IPv6: ' + ', '.join(i or 'нет данных' for i in self.snapshot.routes[2:])]
        lines += ['', 'ПРОКСИ', self.proxy.label, self.proxy.url or self.proxy.detail,
                  '', 'IP', self.ip or 'Не определен']
        if self.ip_org or self.ip_asn:
            lines.append(f'Сеть: {short(self.ip_org, self.ip_asn, 40)}{" · " + self.ip_asn if self.ip_asn else ""}'
                         + (' · хостинг' if self.current_exit().hosting else ''))
        if self.ip_detail:
            lines.append(self.ip_detail)
        if self.direct_ip:
            lines.append(f'Без прокси: {self.direct_ip}')
        if self.last_ip_reason:
            lines.append(f'Последняя проверка: {IP_TRIGGERS.get(self.last_ip_reason, self.last_ip_reason)}')
        lines += [f'Проверка: раз в {self.ip_interval // 60} мин и при смене пути',
                  '', 'ТРАФИК']
        lines += [f'{period}: ↓ {format_bytes(rx)} · ↑ {format_bytes(tx)}' for period, (rx, tx) in totals.items()]
        if self.traffic_query:
            lines += ['', self.traffic_query]
        lines += ['', 'По дням:']
        days = self.traffic_store.daily(14)
        peak = max((rx + tx for _, rx, tx in days), default=0) or 1
        for day, rx, tx in days:
            bar = '▇' * max(1, round(10 * (rx + tx) / peak)) if rx + tx else '·'
            lines.append(f'{day:%d.%m}  ↓ {format_bytes(rx)} · ↑ {format_bytes(tx)}  {bar}')
        lines += [f'Учет с {self.traffic_store.started}',
                  f'Интерфейс: {self.traffic_rate.interface or "не определен"}']
        if self.storage_error:
            lines.append(self.storage_error)
        if self.site_result:
            lines += ['', self.site_title, self.site_result]
        return '\n'.join(lines)

    # ----- settings and actions ---------------------------------------------------------

    def save(self, **changes):
        try:
            settings = replace(self.settings, **changes)
            self.store.save(settings)
            self.settings = settings
            return True
        except Exception:
            log.exception('Settings save failed')
            self.alert('Настройки', 'Настройки не сохранены')
            return False

    def apply_settings(self, **changes):
        """Single entry point for the settings window and menu actions."""
        old = self.settings
        if not self.save(**changes):
            return False
        now = time.monotonic()
        if 'ping_host' in changes and changes['ping_host'] != old.ping_host:
            self.reset_network(now)
        if 'economical' in changes and changes['economical'] != old.economical:
            for key in ('https', 'ping', 'traffic', 'ip'):
                self.due[key] = min(self.due[key], now + 1)
        self.last_data = None
        self.render()
        return True

    def alert(self, title, message, **kwargs):
        self.dialog_open = True
        try:
            return rumps.alert(title, message, **kwargs)
        finally:
            self.dialog_open = False

    def ask(self, title, message, default='', ok='Проверить'):
        self.dialog_open = True
        try:
            response = rumps.Window(message, title, default_text=default, ok=ok, cancel='Отмена',
                                    dimensions=(360, 24)).run()
            return response.text.strip() if response.clicked else None
        finally:
            self.dialog_open = False

    def toggle_setting(self, key):
        if key == 'history_enabled' and self.settings.history_enabled:
            if not self.confirm_history_off():
                return
        self.apply_settings(**{key: not getattr(self.settings, key)})

    def confirm_history_off(self):
        return self.alert('Выключить историю?',
                          f'Событий будет удалено: {self.store.count()}. Трафик сохранится.',
                          ok='Удалить и выключить', cancel='Отмена') == 1

    def toggle_compact(self, _):
        self.apply_settings(menubar_style='full' if self.settings.menubar_style == 'icon' else 'icon')

    def cycle_traffic_period(self):
        keys = list(PERIOD_KEYS)
        current = self.settings.traffic_period if self.settings.traffic_period in keys else 'today'
        self.apply_settings(traffic_period=keys[(keys.index(current) + 1) % len(keys)])

    def ask_traffic_range(self, _=None):
        today = datetime.now().date()
        value = self.ask('Трафик за период', 'ДД.ММ.ГГГГ - ДД.ММ.ГГГГ или одна дата',
                         f'{today.replace(day=1):%d.%m.%Y} - {today:%d.%m.%Y}', ok='Показать')
        if not value:
            return
        try:
            start, end = parse_range(value, today)
        except ValueError as error:
            self.alert('Трафик за период', str(error)); return
        rx, tx = self.traffic_store.range_totals(start, end)
        self.traffic_query = (f'{start:%d.%m.%Y} - {end:%d.%m.%Y}: ↓ {format_bytes(rx)} · ↑ {format_bytes(tx)}'
                              + (f'\nУчет с {self.traffic_store.started}'
                                 if start.isoformat() < self.traffic_store.started else ''))
        self.last_data = None
        self.explain(None)

    def login_status(self):
        import autostart
        return autostart.status()

    def set_login(self, value):
        import autostart
        try:
            return autostart.set_enabled(value)
        except Exception as error:
            log.exception('Autostart change failed')
            self.alert('Автозапуск', str(error))
            return None

    def change_ping(self, _):
        value = self.ask('Адрес пинга', 'Домен или IP без URL и порта', self.settings.ping_host)
        if value is None:
            return
        try:
            value = validate_host(value)
        except ValueError as error:
            self.alert('Адрес пинга', str(error)); return
        self.apply_settings(ping_host=value)

    def manual_refresh(self, _):
        self.due['https'] = 0
        self.request_ip(time.monotonic(), 'manual')
        self.tick(None)

    def open_dashboard_window(self, _):
        if self.dashboard:
            self.dashboard.open_window()

    def open_settings(self, _=None):
        if self.settings_window is None:
            from settings_window import SettingsController
            self.settings_window = SettingsController(self)
        self.settings_window.show()

    def explain(self, _):
        if self.dashboard:
            self.dashboard.show_details()

    def services_text(self):
        econ = self.settings.economical
        return ('Связь: yandex.ru/robots.txt, www.gstatic.com/generate_204\n'
                f'Раз в {self.interval} с, при стабильной связи раз в {5 if econ else 2} мин, при сбое чаще\n'
                f'IP: api64.ipify.org · раз в {self.ip_interval // 60} мин и при смене пути\n'
                'IPv6: api6.ipify.org · раз в 5 мин\n'
                'Страна и сеть: ipwho.is · для нового IP\n'
                'История и трафик хранятся только на этом Mac')

    def show_services(self, _):
        self.alert('Проверочные сервисы', self.services_text())

    def show_history(self, _):
        rows = self.store.recent(200)
        summary = self.store.summary()
        text = '\n\n'.join(f'{datetime.fromtimestamp(at).astimezone():%d.%m %H:%M:%S} · {message}\n{evidence}'.rstrip()
                             for at, kind, message, evidence, _ in rows)
        heading = (f'7 дней: обрывы {summary["outages"]} ({duration(summary["duration"])}) · '
                   f'ухудшения {summary["degraded"]} · хранение {self.settings.history_days} дн.'
                   if self.settings.history_enabled else 'История выключена')
        self.dialog_open = True
        try:
            rumps.Window(heading, 'История', default_text=text or 'Событий нет', ok='Закрыть',
                         cancel=False, dimensions=(560, 340)).run()
        finally:
            self.dialog_open = False

    def export_history(self, _=None):
        from AppKit import NSSavePanel, NSModalResponseOK
        self.dialog_open = True
        try:
            panel = NSSavePanel.savePanel()
            panel.setNameFieldStringValue_('IP-Menubar-history.csv')
            panel.setMessage_('IP-адреса будут заменены на [IP]' if self.settings.exclude_export_ip
                              else 'Файл будет содержать IP-адреса')
            if panel.runModal() == NSModalResponseOK:
                self.store.export_csv(panel.URL().path(), self.settings.exclude_export_ip)
        except Exception:
            log.exception('CSV export failed')
            self.alert('Экспорт', 'CSV не сохранен')
        finally:
            self.dialog_open = False

    def clear_history(self, _=None):
        if self.alert('Очистить историю?', f'Событий будет удалено: {self.store.count()}. Трафик сохранится.',
                      ok='Очистить', cancel='Отмена') == 1:
            self.store.clear()
            return True
        return False

    def reset_traffic(self, _=None):
        if self.alert('Сбросить трафик?', 'Суммы за все периоды будут удалены. История сохранится.',
                      ok='Сбросить', cancel='Отмена') == 1:
            self.traffic_store.reset()
            self.last_data = None
            self.render()
            return True
        return False

    def test_notification(self):
        try:
            rumps.notification('IP Menubar', 'Тестовое уведомление', 'Обрыв и восстановление связи')
        except Exception:
            log.exception('Test notification failed')
            self.alert('Уведомления', 'macOS отклонила уведомление · Системные настройки → Уведомления')

    def start_site(self, extended):
        if self.lanes['site'].busy:
            self.alert('Проверка сайта', 'Проверка уже выполняется'); return
        value = self.ask('Проверка сайта', 'HTTPS-домен' + (' · загрузка до 100 КБ' if extended else ''))
        if not value:
            return
        from transport import site_url
        try:
            value = site_url(value)
        except ValueError as error:
            self.alert('Адрес сайта', str(error)); return
        g, config = self.health.generation, self.proxy
        self.site_title, self.site_result = 'ПРОВЕРКА САЙТА', 'Проверка…'
        self.lanes['site'].launch(lambda: (g, check_site(value, config, extended)))
        self.explain(None)

    def test_segments(self, _):
        if self.lanes['segments'].busy:
            return
        self.site_title, self.site_result = 'ПРОВЕРКА МАРШРУТА', 'Проверка…'
        self.lanes['segments'].launch(check_segments, self.health.generation, self.proxy)
        self.explain(None)

    def test_site(self, _): self.start_site(False)
    def test_download(self, _): self.start_site(True)

    def install_dashboard(self):
        from dashboard import DashboardController
        try:
            from settings_window import ensure_edit_menu
            ensure_edit_menu()  # copy/paste in dialogs and the settings window
        except Exception:
            log.exception('Edit menu setup failed')
        self.dashboard = DashboardController(self, self._nsapp.nsstatusitem)
        self.last_data = None
        self.render()

    def run_vpn_check(self, _=None):
        if self.lanes['vpn'].busy:
            self.alert('Проверка VPN', 'Проверка уже выполняется')
            return
        import vpn_check
        from vpn_check import Finding, OK, WARN, BAD, INFO
        extra = []
        if self.vpn_state == 'leak':
            extra.append(Finding(BAD, 'Утечка IPv6', self.vpn_text))
        elif self.v6_known and self.v6 is None:
            extra.append(Finding(OK, 'Утечка IPv6', 'IPv6 нет'))
        elif self.v6_known and not self.v6.known:
            extra.append(Finding(INFO, 'Утечка IPv6', f'IPv6 {self.v6.ip} · сеть не определена'))
        elif self.v6_known:
            extra.append(Finding(OK, 'Утечка IPv6', f'IPv6 через ту же сеть · {short(self.v6.org, self.v6.asn)}'))
        else:
            extra.append(Finding(INFO, 'Утечка IPv6', 'IPv6 не проверен'))
        count, seconds = self.drops_today(fresh=True)
        if not self.settings.history_enabled:
            extra.append(Finding(INFO, 'Обрывы VPN', 'История выключена'))
        elif count:
            extra.append(Finding(WARN, 'Обрывы VPN',
                                 f'За 24 ч: {count} · всего {int(seconds)} с без VPN'))
        elif self.vpn_tracker.vpn_seen:
            extra.append(Finding(OK, 'Обрывы VPN', 'За 24 ч: нет'))
        else:
            extra.append(Finding(INFO, 'Обрывы VPN', 'VPN не обнаружен'))
        config, host, state, ip = self.proxy, self.settings.ping_host, self.vpn_state, self.ip
        self.vpn_report = 'Проверка VPN… до 1 мин'
        self.lanes['vpn'].launch(lambda: vpn_check.run(config, host, state, ip, extra))
        self.last_v6_check = float('-inf')
        self.request_ip(time.monotonic(), 'manual')
        self.explain(None)

    def on_sleep(self):
        self.sleeping = True
        self.vpn_tracker.reset()
        self.health.reset(time.monotonic())
        self.drain_events()
        try:
            self.traffic_store.flush()
        except Exception:
            log.exception('Flush before sleep failed')
            self.storage_error = 'Трафик не сохранен'

    def on_wake(self):
        self.sleeping = False
        self.vpn_tracker.reset(time.monotonic())
        self.reset_network(time.monotonic())
        self.tick(None)

    def run(self, **options):
        rumps.events.before_quit.register(self.close)
        rumps.events.on_sleep.register(self.on_sleep)
        rumps.events.on_wake.register(self.on_wake)
        rumps.events.before_start.register(self.install_dashboard)
        try:
            super().run(**options)
        finally:
            rumps.events.before_start.unregister(self.install_dashboard)
            rumps.events.before_quit.unregister(self.close)
            rumps.events.on_sleep.unregister(self.on_sleep)
            rumps.events.on_wake.unregister(self.on_wake)
            self.close()

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.traffic_store.close()
            finally:
                self.store.close()

    def quit(self, _):
        try:
            self.close()
        finally:
            rumps.quit_application()


def setup_logging():
    from logging.handlers import RotatingFileHandler
    from pathlib import Path
    folder = Path.home() / 'Library/Logs/IP Menubar'
    folder.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(folder / 'app.log', maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(threadName)s %(message)s'))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    return folder / 'app.log'


if __name__ == '__main__':
    import sys
    try:
        log_path = setup_logging()
    except OSError:
        log_path = None
    try:
        if '--smoke-test' in sys.argv:
            import tempfile
            from app_smoke import install
            folder = tempfile.TemporaryDirectory(prefix='ip-menubar-packaged-test-')
            app = IPMenuBarApp(Store(folder.name))
            app.settings.hover_open = False
            install(app, folder)
        else:
            app = IPMenuBarApp()
    except Exception as error:
        log.exception('Startup failed')
        if isinstance(error, RuntimeError):
            message = str(error)
        else:
            message = f'Не удалось запустить IP Menubar: {type(error).__name__}.'
            if log_path:
                message += f' Журнал: {log_path}'
        rumps.alert('IP Menubar', message)
        raise SystemExit(1)
    app.run()
