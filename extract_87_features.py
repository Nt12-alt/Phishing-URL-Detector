import re
from urllib.parse import urlparse
import tldextract

def get_features(url):
    """Extracts features and maps them perfectly to the model's expected columns."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    # 1. Calculate the core URL features we know how to extract live
    f = {
        'length_url': len(url),
        'length_hostname': len(parsed.hostname or ''),
        'ip': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname or '') else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'), # Matched CSV spelling
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        'nb_www': url.count('www'),
        'nb_com': url.count('.com'),
        'nb_dslash': url.count('//'),
        'http_in_path': 1 if 'http' in parsed.path else 0,
        'https_token': 1 if 'https' in (parsed.hostname or '') else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / max(len(url), 1),
        'ratio_digits_host': sum(c.isdigit() for c in (parsed.hostname or '')) / max(len(parsed.hostname or ''), 1),
        'punycode': 1 if 'xn--' in url else 0,
        'port': 1 if parsed.port else 0,
        'tld_in_path': 1 if ext.suffix in parsed.path else 0,
        'tld_in_subdomain': 1 if ext.suffix in (ext.subdomain or '') else 0,
        'abnormal_subdomain': 1 if len(ext.subdomain) > 3 else 0,
        'nb_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
        'prefix_suffix': 1 if '-' in ext.domain else 0,
        'shortening_service': 1 if ext.domain in ['bit', 'goo', 'tinyurl', 't', 'ow'] else 0,
        'path_extension': 1 if '.' in parsed.path else 0,
        'nb_redirection': url.count('//') - 1,
        'length_words_raw': len(url.split('/')), # Matched CSV spelling
        'shortest_words_raw': min([len(w) for w in url.split('/')] + [10]),
        'shortest_word_host': min([len(w) for w in (parsed.hostname or '').split('.')] + [10]),
        'longest_words_raw': max([len(w) for w in url.split('/')] + [0]),
        'longest_word_host': max([len(w) for w in (parsed.hostname or '').split('.')] + [0]),
        'longest_word_path': max([len(w) for w in parsed.path.split('/')] + [0]),
        'avg_words_raw': len(url) / max(len(url.split('/')), 1),
        'avg_word_host': len(parsed.hostname or '') / max(len((parsed.hostname or '').split('.')), 1),
        'avg_word_path': len(parsed.path) / max(len(parsed.path.split('/')), 1),
        'phish_hints': 1 if any(w in url.lower() for w in ['login', 'verify', 'update', 'secure']) else 0,
        'suspecious_tld': 1 if ext.suffix in ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz'] else 0,
        
        # Defaults for heavy HTML/Network features
        'domain_age': 3650, 'web_traffic': 1000, 'dns_record': 1, 
        'google_index': 1, 'page_rank': 5, 'safe_anchor': 1, 
        'domain_registration_length': 365, 'whois_registered_domain': 1
    }

    # 2. Read the exact column names the model expects from the CSV
    import pandas as pd
    import os
    
    expected_columns = []
    if os.path.exists('dataset_phishing.csv'):
        # We only read the first row to get the column names quickly
        expected_columns = pd.read_csv('dataset_phishing.csv', nrows=0).columns.tolist()
        # Remove 'url' and 'status' because the model doesn't use them
        expected_columns = [c for c in expected_columns if c not in ['url', 'status']]
    
    # 3. Build the final dictionary matching the CSV perfectly
    final_features = {}
    for col in expected_columns:
        if col in f:
            final_features[col] = f[col]
        else:
            # If it's an HTML feature we didn't calculate (like onmouseover), default to 0 (safe)
            # If it's a count feature we missed, default to 0
            final_features[col] = 0
            
    # Override a few specific defaults to make sure they are safe
    if 'safe_anchors' in final_features: final_features['safe_anchors'] = 1
    if 'dns_record' in final_features: final_features['dns_record'] = 1

    return final_features