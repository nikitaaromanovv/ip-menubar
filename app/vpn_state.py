"""What the exit looks like over time: VPN on this Mac, VPN outside it, or direct.

Pure logic, no I/O. 'Outside' means the exit belongs to a hosting network while no
tunnel is visible on the Mac; that is how a VPN on the router looks from here. It is
weak evidence and is always labelled as such.
"""
from dataclasses import dataclass

from network_monitor import brand, looks_like_hosting

VPN_STATES = ('mac', 'partial', 'outside')
DROP_WINDOW = 90       # a direct spell shorter than this between VPN spells looks like a drop
WAKE_QUIET = 60        # after wake the VPN client reconnects; transitions then are not drops


@dataclass(frozen=True)
class Exit:
    ip: str = ''
    org: str = ''
    asn: str = ''

    @property
    def hosting(self):
        return looks_like_hosting(self.org, self.asn)

    @property
    def known(self):
        return bool(self.ip and (self.org or self.asn))


def classify(tunnel_kind, exit, v6=None):
    """Returns (state, short text). v6 is the IPv6 exit, if the Mac has one."""
    if tunnel_kind == 'tunnel':
        state = 'mac'
    elif tunnel_kind == 'partial':
        state = 'partial'
    elif tunnel_kind == 'not_detected' and exit.known:
        state = 'outside' if exit.hosting else 'direct'
    else:
        return 'unknown', ''
    if state in VPN_STATES and v6 is not None and v6.known and not v6.hosting and v6.asn != exit.asn:
        return 'leak', f'IPv6 мимо VPN{" · " + short(v6.org, v6.asn) if v6.org or v6.asn else ""}'
    text = {'mac': 'VPN на этом Mac',
            'partial': 'VPN частично · часть маршрутов мимо',
            'outside': f'VPN вне Mac · {short(exit.org, exit.asn)}',
            'direct': f'Без VPN{" · " + short(exit.org, exit.asn) if exit.org or exit.asn else ""}'}[state]
    return state, text


def short(org, asn='', limit=24):
    org = brand(org, asn)
    return org if len(org) <= limit else org[:limit - 1] + '…'


def badge(state, warn_without_vpn=False):
    if state in ('mac', 'outside'):
        return 'green'
    if state in ('partial', 'leak'):
        return 'amber'
    if state == 'direct' and warn_without_vpn:
        return 'red'
    return 'gray'


class VPNTracker:
    """Turns successive classifications into events. A short direct spell between two
    VPN spells is reported as a drop: traffic went around the VPN (no kill switch)."""

    def __init__(self):
        self.state = 'unknown'
        self.direct_since = None
        self.direct_exit = None
        self.vpn_seen = False
        self.quiet_until = float('-inf')

    def observe(self, state, now, exit=None):
        events = []
        vpn_like = state in VPN_STATES or state == 'leak'
        if state == 'unknown' or state == self.state:
            return events
        previous, self.state = self.state, state
        if now < self.quiet_until:
            self.direct_since = self.direct_exit = None
            self.vpn_seen = self.vpn_seen or vpn_like
            return events
        if state == 'direct':
            if self.vpn_seen:
                self.direct_since, self.direct_exit = now, exit
                events.append(('vpn_off', 'Выход без VPN',
                               short(exit.org, exit.asn) or exit.ip if exit else ''))
        elif vpn_like:
            if self.direct_since is not None:
                spell = now - self.direct_since
                if spell <= DROP_WINDOW:
                    d = self.direct_exit
                    org = short(d.org, d.asn) if d else ''
                    events.append(('vpn_drop', 'Обрыв VPN',
                                    f'{int(spell)} с без VPN{" · " + org if org else ""}', spell))
                else:
                    events.append(('vpn_on', 'VPN включен', ''))
            if state == 'leak' and previous != 'leak':
                events.append(('ipv6_leak', 'IPv6 мимо VPN', ''))
            self.direct_since = self.direct_exit = None
            self.vpn_seen = True
        return events

    def reset(self, now=None):
        """Sleep: earlier spells cannot be joined to later ones, and the reconnect after
        wake is not a drop."""
        self.state = 'unknown'
        self.direct_since = self.direct_exit = None
        if now is not None:
            self.quiet_until = now + WAKE_QUIET
