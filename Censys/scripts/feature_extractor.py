import json
import os
from datetime import datetime, timezone
import pandas as pd
from pathlib import Path

def extract_bgp_prefix_len(bgp_prefix):
    """Estrae la lunghezza del prefisso BGP (es. '5.61.16.0/21' → 21)"""
    if not bgp_prefix:
        return 0
    try:
        return int(bgp_prefix.split('/')[-1])
    except:
        return 0

def calculate_network_age_days(created_str):
    """Calcola età della network allocation in giorni"""
    if not created_str:
        return 0
    try:
        created = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return (now - created).days
    except:
        return 0

def is_hosting_provider(asn_description):
    """Controlla se è un hosting provider"""
    if not asn_description:
        return 0
    
    hosting_keywords = ['hosting', 'datacenter', 'data center', 'vps', 
                        'cloud', 'server', 'dedicated']
    asn_lower = asn_description.lower()
    return int(any(kw in asn_lower for kw in hosting_keywords))

def get_http_endpoint(services, port, path="/"):
    """Trova endpoint HTTP per porta e path specifici"""
    for service in services:
        if service.get('port') == port:
            for endpoint in service.get('endpoints', []):
                if endpoint.get('path') == path:
                    return endpoint.get('http', {})
    return {}

def has_meta_refresh(http_data):
    """Controlla presenza di meta refresh"""
    html_tags = http_data.get('html_tags', [])
    return int(any('meta' in tag.lower() and 'refresh' in tag.lower() 
                   for tag in html_tags))

def get_cert_from_services(services):
    """Trova il primo certificato nei servizi"""
    for service in services:
        if 'cert' in service:
            return service['cert']
    return None

def calculate_cert_age_days(not_before_str):
    """Calcola età del certificato in giorni"""
    if not not_before_str:
        return 0
    try:
        not_before = datetime.fromisoformat(not_before_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return (now - not_before).days
    except:
        return 0

def is_letsencrypt(issuer_dn):
    """Controlla se il certificato è Let's Encrypt"""
    if not issuer_dn:
        return 0
    return int("let's encrypt" in issuer_dn.lower())

def has_wildcard_cert(cert_names):
    """Controlla se il certificato ha wildcard"""
    if not cert_names:
        return 0
    return int(any(name.startswith('*') for name in cert_names))

def has_suspicious_dns_tokens(dns_names):
    """Controlla presenza di token sospetti nei nomi DNS"""
    if not dns_names:
        return 0
    
    # Token generici di phishing
    generic_tokens = ['login', 'verify', 'secure', 'account', 'update',
                      'confirm', 'banking', 'signin', 'password',
                      'credential', 'wallet', 'support', 'authentication']
    
    # Brand impersonation (brand noti)
    brand_tokens = ['paypal', 'amazon', 'microsoft', 'apple', 'google',
                   'facebook', 'instagram', 'netflix', 'spotify',
                   't-mobile', 'verizon', 'att', 'chase', 'wellsfargo',
                   'bankofamerica', 'citibank', 'usbank', 'capitalone']
    
    # TLD sospetti (usati spesso per phishing)
    suspicious_tlds = ['.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top']
    
    dns_lower = ' '.join(dns_names).lower()
    
    # Check 1: Generic suspicious tokens
    has_generic = any(token in dns_lower for token in generic_tokens)
    
    # Check 2: Brand impersonation
    has_brand = any(brand in dns_lower for brand in brand_tokens)
    
    # Check 3: Suspicious TLDs
    has_suspicious_tld = any(tld in dns_lower for tld in suspicious_tlds)
    
    # Check 4: Molti domini con stesso prefisso (brand repetition)
    # Conta quanti domini hanno lo stesso prefisso
    prefixes = [name.split('.')[0] for name in dns_names]
    from collections import Counter
    prefix_counts = Counter(prefixes)
    has_repetition = any(count > 5 for count in prefix_counts.values())
    
    # Sospetto se almeno 2 condizioni sono vere
    suspicious_count = sum([has_generic, has_brand, has_suspicious_tld, has_repetition])
    
    return int(suspicious_count >= 2)

def extract_features(json_file, label):
    """
    Estrae le 20 feature da un singolo JSON Censys
    
    Args:
        json_file: path al file JSON
        label: 0 (legit) o 1 (phishing)
    
    Returns:
        dict con 20 feature + ip + label
    """
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    resource = data.get('result', {}).get('resource', {})
    
    # IP
    ip = resource.get('ip', 'unknown')
    
    # === Network/Hosting (4 features) ===
    asn_data = resource.get('autonomous_system', {})
    whois_data = resource.get('whois', {}).get('network', {})
    
    asn = asn_data.get('asn', 0)
    bgp_prefix_len = extract_bgp_prefix_len(asn_data.get('bgp_prefix'))
    whois_network_age_days = calculate_network_age_days(whois_data.get('created'))
    is_hosting = is_hosting_provider(asn_data.get('description', ''))
    
    # === Services (4 features) ===
    services = resource.get('services', [])
    service_count = len(services)
    
    ports = [s.get('port') for s in services]
    has_80 = int(80 in ports)
    has_443 = int(443 in ports)
    https_only = int(443 in ports and 80 not in ports)
    
    # === HTTP (4 features) ===
    # Prova prima 443, poi 80
    http_data = get_http_endpoint(services, 443, "/")
    if not http_data:
        http_data = get_http_endpoint(services, 80, "/")
    
    http_status_root = http_data.get('status_code', 0)
    has_redirect_like = int(http_status_root in [301, 302, 303, 307, 308])
    has_meta_refresh_flag = has_meta_refresh(http_data)
    body_size_root = http_data.get('body_size', 0)
    
    # === Certificate (6 features) ===
    cert = get_cert_from_services(services)
    
    if cert:
        parsed = cert.get('parsed', {})
        validity = parsed.get('validity_period', {})
        
        not_before = validity.get('not_before')
        cert_age_days = calculate_cert_age_days(not_before)
        
        # Lifetime in giorni
        length_seconds = validity.get('length_seconds', 0)
        cert_lifetime_days = length_seconds // 86400
        
        cert_validation_level = cert.get('validation_level', 'unknown')
        
        issuer_dn = parsed.get('issuer_dn', '')
        cert_is_letsencrypt_flag = is_letsencrypt(issuer_dn)
        
        cert_names = cert.get('names', [])
        cert_san_count = len(cert_names)
        cert_is_wildcard_flag = has_wildcard_cert(cert_names)
    else:
        cert_age_days = 0
        cert_lifetime_days = 0
        cert_validation_level = 'none'
        cert_is_letsencrypt_flag = 0
        cert_san_count = 0
        cert_is_wildcard_flag = 0
    
    # === DNS (2 features) ===
    dns = resource.get('dns', {})
    dns_names = dns.get('names', [])
    num_dns_names = len(dns_names)
    dns_has_suspicious_tokens_flag = has_suspicious_dns_tokens(dns_names)
    
    # Costruisci feature dict
    features = {
        'ip': ip,
        'label': label,
        
        # Network/Hosting
        'asn': asn,
        'bgp_prefix_len': bgp_prefix_len,
        'whois_network_age_days': whois_network_age_days,
        'is_hosting_provider': is_hosting,
        
        # Services
        'service_count': service_count,
        'has_80': has_80,
        'has_443': has_443,
        'https_only': https_only,
        
        # HTTP
        'http_status_root': http_status_root,
        'has_redirect_like': has_redirect_like,
        'has_meta_refresh': has_meta_refresh_flag,
        'body_size_root': body_size_root,
        
        # Certificate
        'cert_age_days': cert_age_days,
        'cert_lifetime_days': cert_lifetime_days,
        'cert_validation_level': cert_validation_level,
        'cert_is_letsencrypt': cert_is_letsencrypt_flag,
        'cert_san_count': cert_san_count,
        'cert_is_wildcard': cert_is_wildcard_flag,
        
        # DNS
        'num_dns_names': num_dns_names,
        'dns_has_suspicious_tokens': dns_has_suspicious_tokens_flag,
    }
    
    return features

def create_dataset(phishing_dir, legit_dir, output_csv):
    """
    Crea dataset completo da tutti i JSON
    
    Args:
        phishing_dir: directory con JSON phishing
        legit_dir: directory con JSON legit
        output_csv: path output CSV
    """
    all_features = []
    
    # Process phishing IPs (label=1)
    print(f"Processing phishing IPs from {phishing_dir}...")
    phishing_count = 0
    for filename in os.listdir(phishing_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(phishing_dir, filename)
            try:
                features = extract_features(filepath, label=1)
                all_features.append(features)
                phishing_count += 1
            except Exception as e:
                print(f"  Error processing {filename}: {e}")
    
    print(f"  Processed {phishing_count} phishing IPs")
    
    # Process legitimate IPs (label=0)
    print(f"\nProcessing legitimate IPs from {legit_dir}...")
    legit_count = 0
    for filename in os.listdir(legit_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(legit_dir, filename)
            try:
                features = extract_features(filepath, label=0)
                all_features.append(features)
                legit_count += 1
            except Exception as e:
                print(f"  Error processing {filename}: {e}")
    
    print(f"  Processed {legit_count} legitimate IPs")
    
    # Create DataFrame
    df = pd.DataFrame(all_features)
    
    # Reorder columns (label last)
    cols = ['ip'] + [col for col in df.columns if col not in ['ip', 'label']] + ['label']
    df = df[cols]
    
    # Save
    df.to_csv(output_csv, index=False)
    
    print(f"\n{'='*60}")
    print(f"DATASET CREATED")
    print(f"{'='*60}")
    print(f"Output file: {output_csv}")
    print(f"Total samples: {len(df)}")
    print(f"Shape: {df.shape}")
    print(f"\nLabel distribution:")
    print(df['label'].value_counts())
    print(f"\nFirst 5 rows:")
    print(df.head())
    print(f"\nFeature types:")
    print(df.dtypes)
    print(f"\nMissing values:")
    print(df.isnull().sum())
    
    return df


# Test con i due JSON che hai fornito
def test_examples():
    # NOT phishing (5.61.23.39 - VK)
    features_legit = extract_features(
        "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/Censys/raw/hosts/legit/5.61.23.39.json",
        label=0
    )
    print("NOT PHISHING (VK):")
    for k, v in features_legit.items():
        print(f"  {k}: {v}")
    
    print("\n" + "="*60 + "\n")
    
    # Phishing (8.219.239.111 - t-mobile)
    features_phish = extract_features(
        "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/Censys/raw/hosts/phishing/8.219.239.111.json",
        label=1
    )
    print("PHISHING (t-mobile):")
    for k, v in features_phish.items():
        print(f"  {k}: {v}")



if __name__ == "__main__":
    # Paths
    BASE_DIR = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/Censys"
    PHISHING_DIR = os.path.join(BASE_DIR, "raw", "hosts", "phishing")
    LEGIT_DIR = os.path.join(BASE_DIR, "raw", "hosts", "legit")
    OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed")
    OUTPUT_CSV = os.path.join(OUTPUT_DIR, "dataset_features.csv")
    
    # Crea directory output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Estrai dataset
    df = create_dataset(PHISHING_DIR, LEGIT_DIR, OUTPUT_CSV)