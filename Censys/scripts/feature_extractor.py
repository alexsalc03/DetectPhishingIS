import json
import os
import math
from datetime import datetime, timezone
from collections import Counter
import pandas as pd

# =========================
# Config
# =========================
DNS_NAME_CAP = 50

GENERIC_TOKENS = [
    'login', 'verify', 'secure', 'account', 'update', 'confirm', 'banking',
    'signin', 'password', 'credential', 'wallet', 'support', 'authentication'
]

BRAND_TOKENS = [
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'instagram',
    'netflix', 'spotify', 't-mobile', 'verizon', 'att', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'usbank', 'capitalone'
]

SUSPICIOUS_TLDS = ['.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top']

HOSTING_KEYWORDS = ['hosting', 'datacenter', 'data center', 'vps', 'cloud', 'server', 'dedicated']


# =========================
# Math helpers
# =========================
def log1p(x):
    """log(1+x) safe for non-negative values"""
    try:
        return math.log1p(max(float(x), 0))
    except:
        return 0.0


# =========================
# Time helpers
# =========================
def parse_iso_z(dt_str: str):
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None

def days_since(dt_str: str) -> int:
    dt = parse_iso_z(dt_str)
    if not dt:
        return 0
    now = datetime.now(timezone.utc)
    return max((now - dt).days, 0)

def days_until(dt_str: str) -> int:
    dt = parse_iso_z(dt_str)
    if not dt:
        return 0
    now = datetime.now(timezone.utc)
    return max((dt - now).days, 0)


# =========================
# Feature helpers
# =========================
def extract_bgp_prefix_len(bgp_prefix: str) -> int:
    if not bgp_prefix:
        return 0
    try:
        return int(bgp_prefix.split("/")[-1])
    except Exception:
        return 0

def provider_is_hosting(asn_description: str) -> int:
    if not asn_description:
        return 0
    s = asn_description.lower()
    return int(any(k in s for k in HOSTING_KEYWORDS))

def simplify_continent(continent: str) -> str:
    """Reduce to valid continents + Other"""
    valid = ['Europe', 'Asia', 'North America', 'South America', 'Africa', 'Oceania']
    if not continent or continent == "unknown":
        return "Other"
    return continent if continent in valid else "Other"

def simplify_webserver(web_server: str) -> str:
    """Reduce webserver cardinality: top vendors + other"""
    if not web_server:
        return "unknown"
    ws_lower = web_server.lower()
    
    if 'nginx' in ws_lower:
        return 'nginx'
    if 'apache' in ws_lower:
        return 'apache'
    if 'cloudflare' in ws_lower:
        return 'cloudflare'
    if 'iis' in ws_lower or 'microsoft' in ws_lower:
        return 'iis'
    if web_server == 'unknown':
        return 'unknown'
    
    return 'other'

def status_class(code) -> str:
    try:
        c = int(code)
    except Exception:
        return "0"
    if c <= 0:
        return "0"
    if 100 <= c < 200:
        return "1xx"
    if 200 <= c < 300:
        return "2xx"
    if 300 <= c < 400:
        return "3xx"
    if 400 <= c < 500:
        return "4xx"
    if 500 <= c < 600:
        return "5xx"
    return "other"

def extract_web_server(services) -> str:
    """
    Extract web server from software, prioritizing product field.
    Search all software entries for first non-empty product.
    """
    for s in services or []:
        if s.get("protocol") == "HTTP":
            sw_list = s.get("software") or []
            for sw in sw_list:
                vendor = (sw.get("vendor") or "").strip().lower()
                product = (sw.get("product") or "").strip().lower()
                if product:  # Prioritize product
                    return f"{vendor}:{product}".strip(":") if vendor else product
    return "unknown"

def get_http_endpoint_http_obj(services, port: int, path: str = "/") -> dict:
    """Find endpoint {path} on port {port} and return 'http' dict"""
    for s in services or []:
        if s.get("port") == port:
            for ep in s.get("endpoints", []) or []:
                if ep.get("path") == path:
                    return ep.get("http") or {}
    return {}

def has_meta_refresh(http_obj: dict) -> int:
    """Check for meta refresh tag in HTML"""
    if not http_obj:
        return 0
    html_tags = http_obj.get("html_tags") or []
    for t in html_tags:
        tl = str(t).lower()
        if "meta" in tl and "refresh" in tl:
            return 1
    return 0

def supports_http2(http_obj: dict) -> int:
    versions = http_obj.get("supported_versions") or []
    versions = [str(v).upper() for v in versions]
    return int("HTTP/2" in versions or "H2" in versions)

def content_type_is_html(http_obj: dict) -> int:
    headers = http_obj.get("headers") or {}
    ct = headers.get("Content-Type") or headers.get("content-type")
    if isinstance(ct, dict):
        vals = ct.get("headers") or []
        joined = " ".join(map(str, vals)).lower()
        return int("text/html" in joined)
    return 0

def has_reverse_dns(resource_dns: dict) -> int:
    rdns = (resource_dns or {}).get("reverse_dns") or {}
    names = rdns.get("names")
    return int(bool(names))

def has_suspicious_dns_tokens(dns_names) -> int:
    if not dns_names:
        return 0

    dns_lower = " ".join(dns_names).lower()
    has_generic = any(t in dns_lower for t in GENERIC_TOKENS)
    has_brand = any(t in dns_lower for t in BRAND_TOKENS)
    has_suspicious_tld = any(tld in dns_lower for tld in SUSPICIOUS_TLDS)

    prefixes = [n.split(".")[0] for n in dns_names if "." in n]
    prefix_counts = Counter(prefixes)
    has_repetition = any(c > 5 for c in prefix_counts.values())

    suspicious_count = sum([has_generic, has_brand, has_suspicious_tld, has_repetition])
    return int(suspicious_count >= 2)

def get_first_cert(services, prefer_ports=[443, 8443, 9443]) -> dict | None:
    """
    Get certificate, preferring web ports (443, 8443, 9443) first.
    This avoids getting certs from mail/other services.
    """
    # First pass: look for preferred ports
    for port in prefer_ports:
        for s in services or []:
            if s.get("port") == port:
                cert = s.get("cert")
                if cert:
                    return cert
    
    # Fallback: any cert
    for s in services or []:
        cert = s.get("cert")
        if cert:
            return cert
    
    return None

def cert_chain_len(services, prefer_ports=[443, 8443, 9443]) -> int:
    """
    Get TLS certificate chain length, preferring web ports.
    Aligned with get_first_cert() logic.
    """
    # First pass: preferred ports
    for port in prefer_ports:
        for s in services or []:
            if s.get("port") == port:
                tls = s.get("tls")
                if tls and isinstance(tls, dict):
                    chain = tls.get("presented_chain")
                    if isinstance(chain, list):
                        return len(chain)
    
    # Fallback: any TLS
    for s in services or []:
        tls = s.get("tls")
        if tls and isinstance(tls, dict):
            chain = tls.get("presented_chain")
            if isinstance(chain, list):
                return len(chain)
    
    return 0

def cert_is_letsencrypt(cert: dict) -> int:
    if not cert:
        return 0
    issuer_dn = (((cert.get("parsed") or {}).get("issuer_dn")) or "")
    return int("let's encrypt" in issuer_dn.lower())

def cert_is_wildcard(cert: dict) -> int:
    if not cert:
        return 0
    names = cert.get("names") or []
    return int(any(str(n).startswith("*") for n in names))

def cert_san_count(cert: dict) -> int:
    if not cert:
        return 0
    return len(cert.get("names") or [])

def cert_validation_level(cert: dict) -> str:
    if not cert:
        return "none"
    return cert.get("validation_level") or "unknown"


# =========================
# Main extractor
# =========================
def extract_features_from_censys_json(json_file: str, label: int) -> dict:
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    resource = (data.get("result") or {}).get("resource") or {}

    # ---- Basic ----
    ip = resource.get("ip", "unknown")

    # ---- Location ----
    loc = resource.get("location") or {}
    continent = simplify_continent(loc.get("continent", "unknown"))

    # ---- Autonomous system ----
    asn_data = resource.get("autonomous_system") or {}
    bgp_prefix_len = extract_bgp_prefix_len(asn_data.get("bgp_prefix"))
    asn_desc = asn_data.get("description", "")
    is_hosting = provider_is_hosting(asn_desc)

    # ---- WHOIS network ----
    whois_net = ((resource.get("whois") or {}).get("network")) or {}
    whois_network_age_days = days_since(whois_net.get("created"))

    # ---- Services ----
    services = resource.get("services") or []
    ports = [s.get("port") for s in services if isinstance(s.get("port"), int)]
    distinct_ports = len(set([p for p in ports if p > 0]))
    
    has_80 = int(80 in ports)
    has_443 = int(443 in ports)
    https_only = int(has_443 == 1 and has_80 == 0)

    # ---- HTTP Root (80 and 443) - AGGREGATED ----
    http80_root = get_http_endpoint_http_obj(services, 80, "/")
    http443_root = get_http_endpoint_http_obj(services, 443, "/")
    
    # Presence
    http80_present = int(bool(http80_root))
    http443_present = int(bool(http443_root))
    http_root_any_present = int(http80_present or http443_present)

    # Status (prefer 443, fallback 80)
    http80_status_class = status_class(http80_root.get("status_code", 0)) if http80_root else "0"
    http443_status_class = status_class(http443_root.get("status_code", 0)) if http443_root else "0"
    http_any_status_class = http443_status_class if http443_status_class != "0" else http80_status_class

    # Body size (prefer 443, fallback 80)
    http80_body_size = int(http80_root.get("body_size", 0) or 0) if http80_root else 0
    http443_body_size = int(http443_root.get("body_size", 0) or 0) if http443_root else 0
    http_any_body_size = http443_body_size if http443_body_size > 0 else http80_body_size

    # HTTP/2 support (prefer 443, it's where HTTP/2 matters)
    http443_supports_http2 = supports_http2(http443_root) if http443_root else 0
    http_any_supports_http2 = http443_supports_http2  # HTTP/2 primarily on 443

    # Content type HTML (prefer 443, fallback 80)
    http80_is_html = content_type_is_html(http80_root) if http80_root else 0
    http443_is_html = content_type_is_html(http443_root) if http443_root else 0
    http_any_is_html = http443_is_html if http443_present else http80_is_html

    # Redirect (prefer 443, fallback 80)
    http80_redirect_like = int(http80_status_class == "3xx")
    http443_redirect_like = int(http443_status_class == "3xx")
    http_any_redirect_like = http443_redirect_like if http443_present else http80_redirect_like
    
    # Meta refresh (any port)
    http80_meta = has_meta_refresh(http80_root)
    http443_meta = has_meta_refresh(http443_root)
    http_any_meta_refresh = int(http80_meta or http443_meta)

    web_server = simplify_webserver(extract_web_server(services))

    # ---- Certificate (prefer web ports, aligned with chain_len) ----
    cert = get_first_cert(services, prefer_ports=[443, 8443, 9443])
    if cert:
        validity = ((cert.get("parsed") or {}).get("validity_period")) or {}
        cert_age_days = days_since(validity.get("not_before"))
        cert_lifetime_days = int((validity.get("length_seconds") or 0) // 86400)
        cert_remaining_days = days_until(validity.get("not_after"))
        cert_val_level = cert_validation_level(cert)
        cert_is_le = cert_is_letsencrypt(cert)
        cert_sans = cert_san_count(cert)
        cert_wild = cert_is_wildcard(cert)
    else:
        cert_age_days = 0
        cert_lifetime_days = 0
        cert_remaining_days = 0
        cert_val_level = "none"
        cert_is_le = 0
        cert_sans = 0
        cert_wild = 0
    
    # Chain length (aligned with cert selection)
    cert_chain = cert_chain_len(services, prefer_ports=[443, 8443, 9443])

    # ---- DNS ----
    dns = resource.get("dns") or {}
    dns_names = dns.get("names") or []
    num_dns_names_capped = min(len(dns_names), DNS_NAME_CAP)
    dns_has_susp_tokens = has_suspicious_dns_tokens(dns_names)
    rdns_present = has_reverse_dns(dns)

    features = {
        "ip": ip,
        "label": label,

        # Geo
        "continent": continent,

        # Network/hosting
        "bgp_prefix_len": bgp_prefix_len,
        "whois_network_age_days": log1p(whois_network_age_days),
        "provider_is_hosting": is_hosting,

        # Services
        "num_distinct_ports": log1p(distinct_ports),
        "has_80": has_80,
        "has_443": has_443,
        "https_only": https_only,
        "web_server": web_server,

        # HTTP - AGGREGATED (prefer 443, fallback 80)
        "http_root_any_present": http_root_any_present,
        "http_any_status_class": http_any_status_class,
        "http_any_redirect_like": http_any_redirect_like,
        "http_any_body_size": log1p(http_any_body_size),
        "http_any_supports_http2": http_any_supports_http2,
        "http_any_is_html": http_any_is_html,
        "http_any_meta_refresh": http_any_meta_refresh,

        # Certificate
        "cert_age_days": log1p(cert_age_days),
        "cert_lifetime_days": log1p(cert_lifetime_days),
        "cert_remaining_days": log1p(cert_remaining_days),
        "cert_validation_level": cert_val_level,
        "cert_is_letsencrypt": cert_is_le,
        "cert_san_count": log1p(cert_sans),
        "cert_is_wildcard": cert_wild,
        "cert_chain_len": log1p(cert_chain),

        # DNS
        "has_reverse_dns": rdns_present,
        "num_dns_names_capped": log1p(num_dns_names_capped),
        "dns_has_suspicious_tokens": dns_has_susp_tokens,
    }

    return features


def create_dataset(phishing_dir: str, legit_dir: str, output_csv: str):
    rows = []

    print(f"Processing phishing JSONs from: {phishing_dir}")
    phish = 0
    for fn in os.listdir(phishing_dir):
        if fn.endswith(".json"):
            try:
                rows.append(extract_features_from_censys_json(os.path.join(phishing_dir, fn), label=1))
                phish += 1
            except Exception as e:
                print(f"  [phish] error {fn}: {e}")
    print(f"  Processed phishing: {phish}")

    print(f"\nProcessing legit JSONs from: {legit_dir}")
    legit = 0
    for fn in os.listdir(legit_dir):
        if fn.endswith(".json"):
            try:
                rows.append(extract_features_from_censys_json(os.path.join(legit_dir, fn), label=0))
                legit += 1
            except Exception as e:
                print(f"  [legit] error {fn}: {e}")
    print(f"  Processed legit: {legit}")

    df = pd.DataFrame(rows)

    # Reorder columns
    cols = ["ip"] + [c for c in df.columns if c not in ["ip", "label"]] + ["label"]
    df = df[cols]

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)

    print("\n" + "=" * 60)
    print("DATASET CREATED - PRODUCTION READY")
    print("=" * 60)
    print(f"Output: {output_csv}")
    print(f"Samples: {len(df)} | Shape: {df.shape}")
    print("\nLabel distribution:")
    print(df["label"].value_counts())
    
    # Feature summary
    numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
    cat_cols = df.select_dtypes(include=['object']).columns
    
    print(f"\nFeature breakdown:")
    print(f"  Numeric features: {len(numeric_cols) - 1}")  # -1 for label
    print(f"  Categorical features: {len(cat_cols) - 1}")  # -1 for ip
    
    print("\nCategorical cardinality:")
    for col in cat_cols:
        if col not in ['ip', 'label']:
            nunique = df[col].nunique()
            print(f"  {col}: {nunique} unique values")
    
    print("\nMissing values:")
    missing = df.isnull().sum()
    if missing.sum() > 0:
        print(missing[missing > 0])
    else:
        print("  No missing values!")
    
    print("\nEstimated feature count after one-hot encoding:")
    estimated = len(numeric_cols) - 1
    for col in cat_cols:
        if col not in ['ip', 'label']:
            estimated += df[col].nunique()
    print(f"  ~{estimated} columns")
    print(f"  Ratio: {len(df)}/{estimated} = {len(df)/estimated:.1f}:1")
    
    if len(df)/estimated >= 4.5:
        print("  ✓ Ratio acceptable for Logistic Regression with regularization")
    else:
        print("  ⚠ Ratio low - recommend L1/elastic-net regularization")

    return df


if __name__ == "__main__":
    BASE_DIR = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/Censys"
    PHISHING_DIR = os.path.join(BASE_DIR, "raw", "hosts", "phishing")
    LEGIT_DIR = os.path.join(BASE_DIR, "raw", "hosts", "legit")
    OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed")
    OUTPUT_CSV = os.path.join(OUTPUT_DIR, "dataset_features_production.csv")

    df = create_dataset(PHISHING_DIR, LEGIT_DIR, OUTPUT_CSV)