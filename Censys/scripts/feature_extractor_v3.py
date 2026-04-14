import os
import json
import glob
import math
import pandas as pd

from datetime import datetime, timezone
from math import log1p
from collections import Counter

# ==========================================
# COSTANTI
# ==========================================
AUTH_TOKENS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "password", "credential", "authentication",
    "auth", "portal", "access", "sso"
]

BRAND_TOKENS = [
    "paypal", "amazon", "microsoft", "apple", "google", "facebook",
    "instagram", "netflix", "spotify", "t-mobile", "verizon", "att",
    "chase", "wellsfargo", "bankofamerica", "citibank", "usbank",
    "capitalone", "github", "linkedin", "dropbox", "meta"
]

SUSPICIOUS_TLDS = [".cc", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top"]
WEB_PORTS = {80, 443, 8080, 8443, 9443}

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
# HELPER DNS
# ==========================================
def extract_dns_names(resource):
    """
    Estrae tutti i nomi DNS disponibili:
    - dns.names
    - dns.reverse_dns.names

    Deduplica e normalizza in lowercase.
    """
    dns = resource.get("dns") or {}
    names = []

    direct_names = dns.get("names") or []
    names.extend([str(n).strip().lower() for n in direct_names if n])

    reverse_dns = dns.get("reverse_dns") or {}
    reverse_names = reverse_dns.get("names") or []
    names.extend([str(n).strip().lower() for n in reverse_names if n])

    # dedup preservando ordine
    seen = set()
    deduped = []
    for n in names:
        if n and n not in seen:
            deduped.append(n)
            seen.add(n)

    return deduped


def split_labels(name):
    if not name:
        return []
    return [lbl for lbl in str(name).strip(".").lower().split(".") if lbl]


def dns_num_labels(dns_names) -> int:
    """
    Numero massimo di label osservato tra i DNS names.
    Esempio:
    - dzen.ru -> 2
    - www.dzen.ru -> 3
    """
    if not dns_names:
        return 0
    return max(len(split_labels(n)) for n in dns_names)


def dns_max_label_length(dns_names) -> int:
    """
    Lunghezza massima di una singola label.
    """
    if not dns_names:
        return 0

    max_len = 0
    for n in dns_names:
        for lbl in split_labels(n):
            max_len = max(max_len, len(lbl))
    return max_len


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def dns_label_entropy(dns_names) -> float:
    """
    Entropia media delle label DNS.
    Più è alta, più il nome può sembrare artificiale/randomico.
    """
    if not dns_names:
        return 0.0

    entropies = []
    for n in dns_names:
        for lbl in split_labels(n):
            if lbl:
                entropies.append(shannon_entropy(lbl))

    return sum(entropies) / len(entropies) if entropies else 0.0


def tokenize_dns_names(dns_names):
    """
    Tokenizzazione semplice su separatori tipici.
    """
    tokens = []
    for n in dns_names or []:
        pieces = []
        for label in split_labels(n):
            pieces.extend(label.replace("_", "-").split("-"))
        tokens.extend([p for p in pieces if p])
    return tokens


def dns_has_brand_token(dns_names) -> int:
    if not dns_names:
        return 0
    dns_lower = " ".join(map(str, dns_names)).lower()
    return int(any(t in dns_lower for t in BRAND_TOKENS))


def dns_brand_plus_auth_combo(dns_names) -> int:
    """
    1 se compare almeno un brand token e almeno un auth token.
    """
    if not dns_names:
        return 0

    dns_lower = " ".join(map(str, dns_names)).lower()
    has_brand = any(t in dns_lower for t in BRAND_TOKENS)
    has_auth = any(t in dns_lower for t in AUTH_TOKENS)

    return int(has_brand and has_auth)


def dns_suspicious_token_count(dns_names) -> int:
    """
    Conteggio euristico compatto dei segnali sospetti DNS.
    Manteniamo questa feature ma senza duplicare dns_has_auth_token,
    che viene rimossa come feature separata.
    """
    if not dns_names:
        return 0

    dns_lower = " ".join(map(str, dns_names)).lower()
    count = 0

    # auth cluster
    if any(t in dns_lower for t in AUTH_TOKENS):
        count += 1

    # brand cluster
    if any(t in dns_lower for t in BRAND_TOKENS):
        count += 1

    # suspicious TLD
    if any(tld in dns_lower for tld in SUSPICIOUS_TLDS):
        count += 1

    # prefissi ripetuti
    prefixes = [str(n).split(".")[0] for n in dns_names if "." in str(n)]
    prefix_counts = Counter(prefixes)
    if any(c > 5 for c in prefix_counts.values()):
        count += 1

    # pattern numerici
    if any(any(ch.isdigit() for ch in str(n)) for n in dns_names):
        count += 1

    # molti trattini
    if any(str(n).count("-") >= 2 for n in dns_names):
        count += 1

    return count


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
# HELPER RETE E PORTE
# ==========================================
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
def get_root_http_endpoint(services, prefer_ports=(443, 80, 8443, 9443)):
    """
    Cerca l'endpoint HTTP alla root '/' preferendo 443, poi 80.
    """
    for port in prefer_ports:
        for s in services or []:
            if s.get("port") != port:
                continue
            for ep in s.get("endpoints", []) or []:
                if ep.get("endpoint_type") == "HTTP" and ep.get("path") == "/":
                    return ep
    return None


def get_http_obj(endpoint):
    if not endpoint:
        return {}
    return endpoint.get("http") or {}


def content_type_is_html(http_obj) -> int:
    if not http_obj:
        return 0

    headers = http_obj.get("headers") or {}

    ct = headers.get("Content-Type") or headers.get("content-type")
    if isinstance(ct, dict):
        vals = ct.get("headers") or []
        joined = " ".join(map(str, vals)).lower()
        return int("text/html" in joined or "application/xhtml+xml" in joined)

    if isinstance(ct, list):
        joined = " ".join(map(str, ct)).lower()
        return int("text/html" in joined or "application/xhtml+xml" in joined)

    if ct:
        cts = str(ct).lower()
        return int("text/html" in cts or "application/xhtml+xml" in cts)

    for k, v in headers.items():
        if str(k).lower() == "content-type":
            if isinstance(v, dict):
                vals = v.get("headers") or []
                joined = " ".join(map(str, vals)).lower()
                return int("text/html" in joined or "application/xhtml+xml" in joined)
            v_str = str(v).lower()
            return int("text/html" in v_str or "application/xhtml+xml" in v_str)

    return 0


def supports_http2(http_obj) -> int:
    if not http_obj:
        return 0
    versions = http_obj.get("supported_versions") or []
    versions = [str(v).upper() for v in versions]
    return int("HTTP/2" in versions or "H2" in versions)


def status_code(http_obj) -> int:
    if not http_obj:
        return 0
    try:
        return int(http_obj.get("status_code", 0))
    except Exception:
        return 0


def root_2xx_html(endpoint) -> int:
    """
    Più rigorosa della bozza precedente:
    vale 1 solo se root è 2xx e Content-Type indica HTML.
    """
    http_obj = get_http_obj(endpoint)
    code = status_code(http_obj)
    is_html = content_type_is_html(http_obj)
    return int(200 <= code < 300 and is_html == 1)


def root_redirect_like(endpoint) -> int:
    http_obj = get_http_obj(endpoint)
    code = status_code(http_obj)
    return int(300 <= code < 400)


def http_any_is_html(endpoint) -> int:
    http_obj = get_http_obj(endpoint)
    return content_type_is_html(http_obj)


def http_any_supports_http2(endpoint) -> int:
    http_obj = get_http_obj(endpoint)
    return supports_http2(http_obj)


def extract_web_server(services):
    """
    Preferisce software metadata, fallback su header Server.
    """
    for s in services or []:
        if s.get("protocol") == "HTTP":
            sw_list = s.get("software") or []
            for sw in sw_list:
                vendor = (sw.get("vendor") or "").strip().lower()
                product = (sw.get("product") or "").strip().lower()
                if product:
                    return f"{vendor}:{product}".strip(":") if vendor else product

    for s in services or []:
        for ep in s.get("endpoints", []) or []:
            if ep.get("endpoint_type") != "HTTP":
                continue
            http_obj = ep.get("http") or {}
            headers = http_obj.get("headers") or {}
            server = headers.get("Server") or headers.get("server")
            if isinstance(server, dict):
                vals = server.get("headers") or []
                if vals:
                    return str(vals[0]).strip().lower()
            elif isinstance(server, list) and server:
                return str(server[0]).strip().lower()
            elif server:
                return str(server).strip().lower()

    return "unknown"


def simplify_webserver_family(web_server: str) -> str:
    if not web_server:
        return "unknown"

    ws = web_server.lower()

    if any(x in ws for x in ["cloudflare", "akamai", "fastly", "cloudfront", "cdn"]):
        return "edge_or_cdn"
    if any(x in ws for x in ["nginx", "apache", "iis", "microsoft", "litespeed"]):
        return "common_self_managed"
    if ws == "unknown":
        return "unknown"
    return "other"


# ==========================================
# HELPER TLS E CERTIFICATI
# ==========================================
def get_first_cert(services, prefer_ports=(443, 8443, 9443)):
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


def cert_chain_len(services, prefer_ports=(443, 8443, 9443)):
    """
    Usa la struttura tls.presented_chain vista nella v3,
    coerente col JSON esempio allegato.
    """
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


def cert_remaining_days(cert: dict) -> int:
    if not cert:
        return 0
    validity = ((cert.get("parsed") or {}).get("validity_period")) or {}
    return days_until(validity.get("not_after"))


# ==========================================
# ESTRATTORE PRINCIPALE v4
# ==========================================
def extract_features_from_censys_json_v4(json_file: str, label: int) -> dict:
    with open(json_file, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return None

    resource = (data.get("result") or {}).get("resource") or {}
    if not resource:
        resource = data.get("result", data) if isinstance(data, dict) else {}

    ip = resource.get("ip", "unknown")

    # --------------------------
    # Network
    # --------------------------
    whois_net = ((resource.get("whois") or {}).get("network")) or {}
    whois_network_age_days = days_since(whois_net.get("created"))

    # --------------------------
    # Services / Ports
    # --------------------------
    services = resource.get("services") or []
    ports = [s.get("port") for s in services if isinstance(s.get("port"), int) and s.get("port") > 0]
    distinct_ports_raw = len(set(ports))

    port_bucket = port_count_bucket(distinct_ports_raw)
    non_web_ports = has_non_web_ports(ports)

    # --------------------------
    # HTTP
    # --------------------------
    root_endpoint = get_root_http_endpoint(services)

    feat_root_2xx_html = root_2xx_html(root_endpoint)
    feat_root_redirect_like = root_redirect_like(root_endpoint)
    feat_http_any_is_html = http_any_is_html(root_endpoint)
    feat_http_any_supports_http2 = http_any_supports_http2(root_endpoint)

    # --------------------------
    # Web server
    # --------------------------
    web_server_raw = extract_web_server(services)
    server_family = simplify_webserver_family(web_server_raw)

    # --------------------------
    # TLS / Cert
    # --------------------------
    cert = get_first_cert(services, prefer_ports=(443, 8443, 9443))
    cert_present_flag = int(cert is not None)

    cert_val_group = cert_validation_group(cert)
    cert_remaining = cert_remaining_days(cert)
    cert_chain = cert_chain_len(services, prefer_ports=(443, 8443, 9443))
    cert_recent = cert_recently_issued(cert)
    cert_short = cert_short_lived(cert)
    cert_ratio = cert_age_ratio(cert)

    # --------------------------
    # DNS
    # --------------------------
    dns_names = extract_dns_names(resource)

    features = {
        "ip": ip,
        "label": label,

        # Network
        "whois_network_age_days": log1p(whois_network_age_days),

        # Ports
        "port_count_bucket": port_bucket,
        "has_non_web_ports": non_web_ports,

        # HTTP
        "root_2xx_html": feat_root_2xx_html,
        "root_redirect_like": feat_root_redirect_like,
        "http_any_is_html": feat_http_any_is_html,
        "http_any_supports_http2": feat_http_any_supports_http2,

        # Web server
        "server_family": server_family,

        # TLS
        "cert_present": cert_present_flag,
        "cert_validation_group": cert_val_group,
        "cert_remaining_days": log1p(cert_remaining),
        "cert_chain_len": log1p(cert_chain),
        "cert_recently_issued": cert_recent,
        "cert_short_lived": cert_short,
        "cert_age_ratio": cert_ratio,

        # DNS
        "has_dns_names_data": int(len(dns_names) > 0),
        "dns_num_labels": dns_num_labels(dns_names),
        "dns_max_label_length": dns_max_label_length(dns_names),
        "dns_label_entropy": dns_label_entropy(dns_names),
        "dns_brand_plus_auth_combo": dns_brand_plus_auth_combo(dns_names),
        "dns_has_brand_token": dns_has_brand_token(dns_names),
        "dns_suspicious_token_count": dns_suspicious_token_count(dns_names),
        "dns_has_digit_hyphen_pattern": dns_has_digit_hyphen_pattern(dns_names),
        "dns_has_punycode": dns_has_punycode(dns_names),
    }

    return features


# ==========================================
# DATASET CREATION
# ==========================================
def process_directory(directory_path: str, label: int):
    records = []
    json_files = glob.glob(os.path.join(directory_path, "*.json"))
    for f in json_files:
        feats = extract_features_from_censys_json_v4(f, label)
        if feats:
            records.append(feats)
    return records


def create_dataset_v4(phishing_dir: str, legit_dir: str, output_csv: str):
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
    print("DATASET CREATED - V4")
    print("=" * 60)
    print(f"Output: {output_csv}")
    print(f"Samples: {len(df)} | Shape: {df.shape}")

    if not df.empty:
        print("\nLabel distribution:")
        print(df["label"].value_counts())

        numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns
        cat_cols = df.select_dtypes(include=["object"]).columns

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
    OUTPUT_CSV = os.path.join(OUTPUT_DIR, "dataset_features_final_v4.csv")

    df = create_dataset_v4(PHISHING_DIR, LEGIT_DIR, OUTPUT_CSV)