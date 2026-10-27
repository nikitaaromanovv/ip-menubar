"""Shared validation and formatting; no network or UI side effects."""
import ipaddress
import re
import unicodedata


def country_code_to_flag(code: str) -> str:
    if not isinstance(code, str) or len(code) != 2 or not code.isascii() or not code.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())


def country_name(code, fallback=''):
    """Russian country name from the system locale; the service text is only a fallback."""
    if isinstance(code, str) and len(code) == 2 and code.isascii() and code.isalpha():
        try:
            from Foundation import NSLocale
            name = NSLocale.localeWithLocaleIdentifier_('ru_RU').localizedStringForCountryCode_(code.upper())
            if name:
                return str(name)
        except Exception:
            pass
    return fallback


def duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02}:{seconds:02}" if hours else f"{minutes:02}:{seconds:02}"


def age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f'{seconds} с назад'
    if seconds < 3600:
        return f'{seconds // 60} мин назад'
    return f'{seconds // 3600} ч назад'


def number(value, digits=1):
    """Russian decimal comma."""
    return f'{value:.{digits}f}'.replace('.', ',')


def valid_ip(value):
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise ValueError("Invalid IP")
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError("Non-public IP")
    return str(address)


def safe_country(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 80:
        raise ValueError("Invalid country")
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise ValueError("Control character")
    return value


def safe_text(value, limit=80):
    if not isinstance(value, str):
        return ''
    value = ''.join(c for c in value if not unicodedata.category(c).startswith('C')).strip()
    return value[:limit]


# Weak evidence only: a hosting/datacenter network is typical for VPN and proxy exits,
# but also for corporate networks and cloud desktops.
HOSTING_HINTS = re.compile(
    r'\b(?:vultr|choopa|digitalocean|hetzner|ovh|linode|akamai|amazon|aws|google cloud|'
    r'microsoft|azure|oracle cloud|alibaba|tencent|contabo|leaseweb|m247|datacamp|cdn77|'
    r'aeza|timeweb|selectel|hostinger|hosting|datacenter|data center|vps|servers?|'
    r'colocation|cloud|constant company)\b', re.I)

# Networks of large hosting providers by AS number, with the brand people know.
# Legal names often hide it (Vultr is 'The Constant Company, LLC').
HOSTING_BRANDS = {
    20473: 'Vultr', 14061: 'DigitalOcean', 24940: 'Hetzner', 16276: 'OVH',
    63949: 'Linode', 16509: 'Amazon', 14618: 'Amazon', 8075: 'Microsoft',
    396982: 'Google Cloud', 31898: 'Oracle Cloud', 45102: 'Alibaba Cloud', 51167: 'Contabo',
    60781: 'Leaseweb', 28753: 'Leaseweb', 9009: 'M247', 212238: 'Datacamp', 60068: 'CDN77',
    49505: 'Selectel', 9123: 'Timeweb', 210644: 'Aeza', 13335: 'Cloudflare', 47583: 'Hostinger',
    197540: 'netcup', 36352: 'ColoCrossing', 53667: 'BuyVM', 44477: 'Stark Industries',
    199524: 'G-Core', 57043: 'HOSTKEY', 8849: 'Melbicom', 8560: 'IONOS', 12876: 'Scaleway',
    36007: 'Kamatera', 40676: 'Psychz', 21859: 'Zenlayer',
}
HOSTING_ASNS = set(HOSTING_BRANDS)
LEGAL_SUFFIX = re.compile(r',?\s+(?:LLC|L\.L\.C\.|Ltd\.?|Limited|Inc\.?|GmbH|B\.V\.|S\.A\.S?|SAS|AG|OOO|LLP)$', re.I)


def brand(org, asn=None):
    """Short provider name for the UI: the known brand, else the name without legal form."""
    known = HOSTING_BRANDS.get(asn_number(asn))
    if known:
        return known
    org = (org or '').strip()
    for _ in range(2):
        org = LEGAL_SUFFIX.sub('', org).strip()
    return org or str(asn or '')


def asn_number(asn):
    text = str(asn or '').upper().removeprefix('AS')
    return int(text) if text.isdigit() else None


def looks_like_hosting(org, asn=None):
    return asn_number(asn) in HOSTING_ASNS or bool(org and HOSTING_HINTS.search(org))
