import os
import json
import glob
import pandas as pd
from datetime import datetime, timezone
from math import log1p
from collections import Counter

# ==========================================
# COSTANTI
# ==========================================
AUTH_TOKENS = [
    'login', 'verify', 'secure', 'account', 'update', 'confirm',
    'signin', 'password', 'credential', 'authentication'
]

BRAND_TOKENS = [
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
    'instagram', 'netflix', 'spotify', 't-mobile', 'verizon', 'att',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'capitalone'
]

SUSPICIOUS_TLDS = ['.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top']
WEB_PORTS = {80, 443, 8080, 8443}

# ==========================================
# HELPER TEMPORALI
# ==========================================
def parse_datetime(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        try:
            dt = datetime.strptime(dt_str[:19], "%Y-%m-%dT%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

def days_since(dt_str, ref_date=datetime(2024, 1, 1, tzinfo=timezone.utc)):
    dt = parse_datetime(dt_str)
    if not dt:
        return 0
    diff = (ref_date - dt).days
    return diff if diff > 0 else 0

def days_until(dt_str, ref_date=datetime(2024, 1, 1, tzinfo=timezone.utc)):
    dt = parse_datetime(dt_str)
    if not dt:
        return 0
    diff = (dt - ref_date).days
    return diff if diff > 0 else 0

# ==========================================
# HELPER RETE E PORTE
# ==========================================
def provider_is_hosting(asn_desc):
    if not asn_desc:
        return 0
    desc = asn_desc.lower()
    hosting_keywords = [
        'hosting', 'cloud', 'aws', 'amazon', 'google', 'azure',
        'digitalocean', 'linode', 'hetzner', 'ovh', 'choopa', 'vultr'
    ]
    return int(any(k in desc for k in hosting_keywords))

def port_count_bucket(distinct_ports: int) -> str:
    if distinct_ports <= 1:
        return "1"
    if distinct_ports <= 3:
        return "2_3"
    return "4_plus"

def has_non_web_ports(ports) -> int:
    return int(any(p not in WEB_PORTS for p in ports if isinstance(p, int) and p > 0))

# ==========================================
# HELPER HTTP E WEB SERVER
# ==========================================
def get_http_endpoint_http_obj(services, port, path="/"):
    for s in services or []:
        if s.get("port") == port:
            for ep in s.get("endpoints", []) or []:
                if ep.get("path") == path:
                    return ep.get("http") or {}
    return {}

def status_class(code):
    try:
        code = int(code)
    except Exception:
        return "0"

    if code <= 0:
        return "0"
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return "other"

def content_type_is_html(http_endpoint):
    if not http_endpoint:
        return 0
    headers = http_endpoint.get("headers") or {}

    ct = headers.get("Content-Type") or headers.get("content-type")
    if isinstance(ct, dict):
        vals = ct.get("headers") or []
        joined = " ".join(map(str, vals)).lower()
        return int("text/html" in joined)

    if isinstance(ct, list):
        joined = " ".join(map(str, ct)).lower()
        return int("text/html" in joined)

    if ct:
        return int("text/html" in str(ct).lower())

    for k, v in headers.items():
        if str(k).lower() == "content-type":
            if isinstance(v, dict):
                vals = v.get("headers") or []
                return int("text/html" in " ".join(map(str, vals)).lower())
            return int("text/html" in str(v).lower())

    return 0

def supports_http2(http_endpoint):
    if not http_endpoint:
        return 0
    versions = http_endpoint.get("supported_versions") or []
    versions = [str(v).upper() for v in versions]
    return int("HTTP/2" in versions or "H2" in versions)

def extract_web_server(services):
    for s in services or []:
        if s.get("protocol") == "HTTP":
            sw_list = s.get("software") or []
            for sw in sw_list:
                vendor = (sw.get("vendor") or "").strip().lower()
                product = (sw.get("product") or "").strip().lower()
                if product:
                    return f"{vendor}:{product}".strip(":") if vendor else product
    return "unknown"

def simplify_webserver_family(web_server: str) -> str:
    if not web_server:
        return "unknown"
    ws = web_server.lower()

    if any(x in ws for x in ['cloudflare', 'akamai', 'fastly', 'cdn']):
        return 'edge_or_cdn'
    if any(x in ws for x in ['nginx', 'apache', 'iis', 'microsoft', 'litespeed']):
        return 'common_self_managed'
    if ws == 'unknown':
        return 'unknown'
    return 'other'

# ==========================================
# HELPER TLS E CERTIFICATI
# ==========================================
def get_first_cert(services, prefer_ports=[443, 8443, 9443]):
    for p in prefer_ports:
        for s in services or []:
            if s.get("port") == p:
                cert = s.get("cert")
                if cert:
                    return cert

    for s in services or []:
        cert = s.get("cert")
        if cert:
            return cert

    return None

def cert_chain_len(services, prefer_ports=[443, 8443, 9443]):
    for p in prefer_ports:
        for s in services or []:
            if s.get("port") == p:
                tls = s.get("tls")
                if isinstance(tls, dict):
                    chain = tls.get("presented_chain")
                    if isinstance(chain, list):
                        return len(chain)

    for s in services or []:
        tls = s.get("tls")
        if isinstance(tls, dict):
            chain = tls.get("presented_chain")
            if isinstance(chain, list):
                return len(chain)

    return 0

def cert_validation_group(cert: dict) -> str:
    if not cert:
        return "none_or_unknown"

    level = (cert.get("validation_level") or "").lower()
    if level in ["ov", "ev"]:
        return "ov_ev"
    if level == "dv":
        return "dv"
    return "none_or_unknown"

def cert_recently_issued(cert: dict) -> int:
    if not cert:
        return 0
    validity = ((cert.get("parsed") or {}).get("validity_period")) or {}
    age_days = days_since(validity.get("not_before"))
    return int(age_days <= 30)

def cert_short_lived(cert: dict) -> int:
    if not cert:
        return 0
    validity = ((cert.get("parsed") or {}).get("validity_period")) or {}
    lifetime_days = int((validity.get("length_seconds") or 0) // 86400)
    return int(0 < lifetime_days <= 120)

def cert_age_ratio(cert: dict) -> float:
    if not cert:
        return 0.0
    validity = ((cert.get("parsed") or {}).get("validity_period")) or {}
    age_days = days_since(validity.get("not_before"))
    lifetime_days = int((validity.get("length_seconds") or 0) // 86400)
    if lifetime_days <= 0:
        return 0.0
    return min(age_days / lifetime_days, 1.0)

# ==========================================
# HELPER DNS
# ==========================================
def dns_suspicious_token_count(dns_names) -> int:
    if not dns_names:
        return 0

    dns_lower = " ".join(map(str, dns_names)).lower()
    count = 0

    if any(t in dns_lower for t in AUTH_TOKENS):
        count += 1
    if any(t in dns_lower for t in BRAND_TOKENS):
        count += 1
    if any(tld in dns_lower for tld in SUSPICIOUS_TLDS):
        count += 1

    prefixes = [str(n).split(".")[0] for n in dns_names if "." in str(n)]
    prefix_counts = Counter(prefixes)
    if any(c > 5 for c in prefix_counts.values()):
        count += 1

    return count

def dns_has_auth_token(dns_names) -> int:
    if not dns_names:
        return 0
    dns_lower = " ".join(map(str, dns_names)).lower()
    return int(any(t in dns_lower for t in AUTH_TOKENS))

def dns_has_brand_token(dns_names) -> int:
    if not dns_names:
        return 0
    dns_lower = " ".join(map(str, dns_names)).lower()
    return int(any(t in dns_lower for t in BRAND_TOKENS))

def dns_name_depth(dns_names) -> float:
    if not dns_names:
        return 0.0

    depths = [max(len(str(n).split(".")) - 2, 0) for n in dns_names if "." in str(n)]
    if not depths:
        return 0.0
    return sum(depths) / len(depths)

def dns_has_punycode(dns_names) -> int:
    if not dns_names:
        return 0
    return int(any("xn--" in str(n).lower() for n in dns_names))

def dns_has_digit_hyphen_pattern(dns_names) -> int:
    if not dns_names:
        return 0
    for n in dns_names:
        s = str(n).lower()
        if any(ch.isdigit() for ch in s) and "-" in s:
            return 1
    return 0

# ==========================================
# ESTRATTORE PRINCIPALE
# ==========================================
def extract_features_from_censys_json(json_file: str, label: int) -> dict:
    with open(json_file, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return None

    resource = (data.get("result") or {}).get("resource") or {}
    if not resource:
        resource = data.get("result", data) if isinstance(data, dict) else {}

    ip = resource.get("ip", "unknown")

    # Network
    asn_data = resource.get("autonomous_system") or {}
    asn_desc = asn_data.get("description", "")
    is_hosting = provider_is_hosting(asn_desc)

    whois_net = ((resource.get("whois") or {}).get("network")) or {}
    whois_network_age_days = days_since(whois_net.get("created"))

    # Services
    services = resource.get("services") or []
    ports = [s.get("port") for s in services if isinstance(s.get("port"), int) and s.get("port") > 0]
    distinct_ports_raw = len(set(ports))

    # HTTP
    http80_root = get_http_endpoint_http_obj(services, 80, "/")
    http443_root = get_http_endpoint_http_obj(services, 443, "/")

    http80_present = int(bool(http80_root))
    http443_present = int(bool(http443_root))
    http_observed = int(http80_present or http443_present)

    http80_status_class = status_class(http80_root.get("status_code", 0)) if http80_root else "0"
    http443_status_class = status_class(http443_root.get("status_code", 0)) if http443_root else "0"

    http80_is_html = content_type_is_html(http80_root) if http80_root else 0
    http443_is_html = content_type_is_html(http443_root) if http443_root else 0

    root_2xx_html = int(
        (http443_status_class == "2xx" and http443_is_html == 1) or
        (not http443_present and http80_status_class == "2xx" and http80_is_html == 1)
    )

    root_redirect_like = int(
        (http443_status_class == "3xx") or
        (not http443_present and http80_status_class == "3xx")
    )

    http_any_is_html = http443_is_html if http443_present else http80_is_html
    http_any_supports_http2 = supports_http2(http443_root) if http443_root else 0

    web_server_raw = extract_web_server(services)
    server_family = simplify_webserver_family(web_server_raw)

    # TLS
    cert = get_first_cert(services, prefer_ports=[443, 8443, 9443])
    cert_present = int(cert is not None)

    if cert:
        validity = ((cert.get("parsed") or {}).get("validity_period")) or {}
        cert_remaining_days = days_until(validity.get("not_after"))
    else:
        cert_remaining_days = 0

    cert_chain = cert_chain_len(services, prefer_ports=[443, 8443, 9443])
    cert_val_group = cert_validation_group(cert)
    cert_recent = cert_recently_issued(cert)
    cert_short = cert_short_lived(cert)
    cert_ratio = cert_age_ratio(cert)

    # DNS
    dns = resource.get("dns") or {}
    dns_names = dns.get("names") or []

    features = {
        "ip": ip,
        "label": label,

        # Network / Hosting
        "whois_network_age_days": log1p(whois_network_age_days),
        "provider_is_hosting": is_hosting,
        "num_distinct_ports": log1p(distinct_ports_raw),
        "port_count_bucket": port_count_bucket(distinct_ports_raw),
        "has_non_web_ports": has_non_web_ports(ports),

        # HTTP
        "http_observed": http_observed,
        "root_2xx_html": root_2xx_html,
        "root_redirect_like": root_redirect_like,
        "http_any_is_html": http_any_is_html,
        "http_any_supports_http2": http_any_supports_http2,

        # Web Server
        "server_family": server_family,

        # TLS
        "cert_present": cert_present,
        "cert_validation_group": cert_val_group,
        "cert_remaining_days": log1p(cert_remaining_days),
        "cert_chain_len": log1p(cert_chain),
        "cert_recently_issued": cert_recent,
        "cert_short_lived": cert_short,
        "cert_age_ratio": cert_ratio,

        # DNS
        "has_dns_names_data": int(len(dns_names) > 0),
        "dns_suspicious_token_count": dns_suspicious_token_count(dns_names),
        "dns_has_auth_token": dns_has_auth_token(dns_names),
        "dns_has_brand_token": dns_has_brand_token(dns_names),
        "dns_name_depth": dns_name_depth(dns_names),
        "dns_has_punycode": dns_has_punycode(dns_names),
        "dns_has_digit_hyphen_pattern": dns_has_digit_hyphen_pattern(dns_names),
    }

    return features

# ==========================================
# DATASET CREATION
# ==========================================
def process_directory(directory_path: str, label: int):
    records = []
    json_files = glob.glob(os.path.join(directory_path, "*.json"))
    for f in json_files:
        feats = extract_features_from_censys_json(f, label)
        if feats:
            records.append(feats)
    return records

def create_dataset(phishing_dir: str, legit_dir: str, output_csv: str):
    print(f"Processing phishing JSONs from: {phishing_dir}")
    phishing_records = process_directory(phishing_dir, label=1)
    print(f"  Processed phishing: {len(phishing_records)}")

    print(f"\nProcessing legit JSONs from: {legit_dir}")
    legit_records = process_directory(legit_dir, label=0)
    print(f"  Processed legit: {len(legit_records)}")

    all_records = phishing_records + legit_records
    df = pd.DataFrame(all_records)

    if not df.empty:
        cols = ["ip"] + [c for c in df.columns if c not in ["ip", "label"]] + ["label"]
        df = df[cols]

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)

    print("\n" + "=" * 60)
    print("DATASET CREATED")
    print("=" * 60)
    print(f"Output: {output_csv}")
    print(f"Samples: {len(df)} | Shape: {df.shape}")

    if not df.empty:
        print("\nLabel distribution:")
        print(df["label"].value_counts())

        numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
        cat_cols = df.select_dtypes(include=['object']).columns

        print(f"\nFeature breakdown:")
        print(f"  Numeric features: {len([c for c in numeric_cols if c != 'label'])}")
        print(f"  Categorical features: {len([c for c in cat_cols if c not in ['ip']])}")

        print("\nCategorical cardinality:")
        for col in cat_cols:
            if col != "ip":
                print(f"  {col}: {df[col].nunique()} unique values")

    return df

# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    BASE_DIR = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/Censys"
    PHISHING_DIR = os.path.join(BASE_DIR, "raw", "hosts", "phishing")
    LEGIT_DIR = os.path.join(BASE_DIR, "raw", "hosts", "legit")
    OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed")
    OUTPUT_CSV = os.path.join(OUTPUT_DIR, "dataset_features_final_v3.csv")

    df = create_dataset(PHISHING_DIR, LEGIT_DIR, OUTPUT_CSV)