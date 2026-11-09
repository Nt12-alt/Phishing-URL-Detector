import re
import math
from urllib.parse import urlparse
import tldextract

# Suspicious keywords commonly used in phishing
SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure',
    'banking', 'confirm', 'password', 'credential', 'wallet',
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'free', 'gift', 'prize', 'bonus', 'winner', 'urgent'
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'cutt.ly'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.zip', '.review', '.country', '.work', '.click'
]

def entropy(s):
    """Shannon entropy — high entropy = random-looking = suspicious."""
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log2(p) for p in prob)


def extract_features(url: str) -> dict:
    """Extract detection features from a URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    full = url

    # --- Basic structural features ---
    features = {
        'url_length': len(full),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'num_dots': full.count('.'),
        'num_hyphens': full.count('-'),
        'num_underscores': full.count('_'),
        'num_slashes': full.count('/'),
        'num_digits': sum(c.isdigit() for c in full),
        'num_special': sum(not c.isalnum() for c in full),
        'num_query_params': len(query.split('&')) if query else 0,
        'has_at_symbol': int('@' in full),
        'has_double_slash_redirect': int('//' in path),
        'has_port': int(parsed.port is not None),
        'is_https': int(parsed.scheme == 'https'),
        'has_ip_host': int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname))),
        'uses_shortener': int(any(s in hostname for s in SHORTENERS)),
    }

    # --- Lexical features ---
    features['digit_ratio'] = features['num_digits'] / max(len(full), 1)
    features['entropy'] = entropy(hostname)

    # --- Subdomain depth (e.g., paypal.com.secure-login.xyz) ---
    features['num_subdomains'] = max(ext.subdomain.count('.') + 1, 0) if ext.subdomain else 0

    # --- Suspicious keyword hits ---
    lower = full.lower()
    features['suspicious_word_count'] = sum(w in lower for w in SUSPICIOUS_WORDS)

    # --- Suspicious TLD ---
    features['suspicious_tld'] = int(any(ext.suffix.endswith(t) for t in SUSPICIOUS_TLDS))

    # --- Brand impersonation: brand in subdomain/path but not in registered domain ---
    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix']
    domain_name = (ext.domain or '').lower()
    features['brand_in_subdomain'] = int(
        any(b in (ext.subdomain or '').lower() or b in path.lower() for b in brands)
        and not any(b in domain_name for b in brands)
    )

    # --- Phishing-like path keywords ---
    features['path_has_phish_word'] = int(
        any(k in path.lower() for k in ['login', 'signin', 'verify', 'account', 'update'])
    )

    # --- TLD length ---
    features['tld_length'] = len(ext.suffix or '')

    return features


FEATURE_ORDER = [
    'url_length', 'hostname_length', 'path_length', 'num_dots', 'num_hyphens',
    'num_underscores', 'num_slashes', 'num_digits', 'num_special',
    'num_query_params', 'has_at_symbol', 'has_double_slash_redirect',
    'has_port', 'is_https', 'has_ip_host', 'uses_shortener',
    'digit_ratio', 'entropy', 'num_subdomains', 'suspicious_word_count',
    'suspicious_tld', 'brand_in_subdomain', 'path_has_phish_word', 'tld_length'
]


def features_to_vector(features: dict) -> list:
    return [features[k] for k in FEATURE_ORDER]