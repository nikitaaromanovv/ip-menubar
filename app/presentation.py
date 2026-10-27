"""Text beside the separately drawn native status icon."""
from network_monitor import country_code_to_flag


def status_title(ip, country_code, style='full'):
    """style: full (flag + IP), ip (IP only), flag (flag only), icon (nothing)."""
    if style == 'icon':
        return ''
    flag = country_code_to_flag(country_code) if style in ('full', 'flag') and country_code else ''
    # IPv6 stays fully readable in the panel without exhausting menu bar space.
    address = ip if ip and ':' not in ip and style in ('full', 'ip') else ''
    return ' '.join(part for part in (flag, address) if part)
