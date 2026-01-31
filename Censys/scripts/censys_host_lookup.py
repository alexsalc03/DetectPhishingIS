import requests
import json
import csv
import os
from datetime import datetime
import time
import ipaddress

# Configurazione Censys API
CENSYS_API_TOKEN = "censys_aLN8cFxD_Psjwf11XDCaySuBFdeHdZg3i"  # Sostituisci con il tuo PAT
CENSYS_API_BASE_URL = "https://api.platform.censys.io/v3/global/asset/host"

# Path base
BASE_DIR = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/Censys"
RAW_DIR = os.path.join(BASE_DIR, "raw", "hosts")
LOG_FILE = os.path.join(BASE_DIR, "logs", "host_lookup_log.csv")

def init_log_file():
    """Inizializza il file di log con l'intestazione se non esiste"""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'status_code', 'found', 'has_tls', 'timestamp', 'error'])

def is_valid_public_ip(ip):
    """Verifica se l'IP è pubblico e valido"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False

def censys_host_lookup(ip):
    """
    Effettua host lookup su Censys per un singolo IP
    
    Returns:
        tuple: (response_dict, status_code, error_message)
    """
    url = f"{CENSYS_API_BASE_URL}/{ip}"
    
    headers = {
        'Authorization': f'Bearer {CENSYS_API_TOKEN}',
        'Accept': 'application/vnd.censys.api.v3.host.v1+json'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        status_code = response.status_code
        
        if status_code == 200:
            return (response.json(), status_code, None)
        elif status_code == 404:
            return (None, status_code, "not_found")
        elif status_code == 401:
            return (None, status_code, "invalid_token")
        elif status_code == 403:
            return (None, status_code, "permission_denied")
        elif status_code == 422:
            return (None, status_code, "unprocessable_entity")
        elif status_code == 500:
            return (None, status_code, "internal_server_error")
        else:
            return (None, status_code, f"http_error_{status_code}")
            
    except requests.exceptions.Timeout:
        return (None, 0, "timeout")
    except requests.exceptions.RequestException as e:
        return (None, 0, f"request_error: {str(e)}")
    except Exception as e:
        return (None, 0, f"error: {str(e)}")

def save_raw_response(ip, data):
    """Salva la risposta raw in formato JSON"""
    filename = os.path.join(RAW_DIR, f"{ip}.json")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def log_result(ip, status_code, found, has_tls, error):
    """Aggiunge un record al file di log"""
    timestamp = datetime.now().strftime("%Y-%m-%d")
    
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            ip,
            status_code,
            1 if found else 0,
            1 if has_tls else 0,
            timestamp,
            error if error else ''
        ])

def check_has_tls(data):
    """Verifica se l'host ha servizi TLS/HTTPS"""
    if not data or 'result' not in data:
        return False
    
    services = data['result'].get('services', [])
    for service in services:
        service_name = service.get('service_name', '').lower()
        port = service.get('port', 0)
        
        if port in [443, 8443] or 'https' in service_name or 'tls' in service_name:
            return True
    
    return False

def process_ips(input_file):
    """Processa tutti gli IP dal file di input"""
    init_log_file()
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Errore: File '{input_file}' non trovato")
        return
    
    # Rimuovi duplicati preservando l'ordine
    ips = list(dict.fromkeys(ips))
    
    print(f"IP totali da processare: {len(ips)}")
    print(f"Inizio lookup su Censys...\n")
    
    if CENSYS_API_TOKEN == "YOUR_PERSONAL_ACCESS_TOKEN":
        print("ATTENZIONE: Devi configurare il tuo Personal Access Token!")
        return
    
    stats = {
        'found': 0, 
        'not_found': 0, 
        'errors': 0, 
        'invalid_private': 0,
        'skipped_duplicates': 0
    }
    
    for i, ip in enumerate(ips, 1):
        print(f"[{i}/{len(ips)}] Processing {ip}...", end=' ')
        
        # Verifica se l'IP è pubblico e valido
        if not is_valid_public_ip(ip):
            log_result(ip, 0, False, False, "invalid_or_private_ip")
            stats['invalid_private'] += 1
            print(f"SKIPPED (invalid/private IP)")
            continue
        
        data, status_code, error = censys_host_lookup(ip)
        
        if status_code == 200 and data:
            has_tls = check_has_tls(data)
            save_raw_response(ip, data)
            log_result(ip, status_code, True, has_tls, None)
            stats['found'] += 1
            print(f"TROVATO (TLS: {has_tls})")
        elif status_code == 404:
            log_result(ip, status_code, False, False, error)
            stats['not_found'] += 1
            print(f"NON TROVATO")
        else:
            log_result(ip, status_code, False, False, error)
            stats['errors'] += 1
            print(f"ERRORE: {error}")
        
        if i < len(ips):
            time.sleep(1.5)
    
    print(f"\n{'='*60}")
    print(f"STATISTICHE FINALI:")
    print(f"{'='*60}")
    print(f"Host trovati: {stats['found']}")
    print(f"Host non trovati: {stats['not_found']}")
    print(f"IP invalidi/privati skippati: {stats['invalid_private']}")
    print(f"Errori: {stats['errors']}")
    print(f"Totale: {len(ips)}")
    print(f"\nRaw responses salvate in: {RAW_DIR}")
    print(f"Log salvato in: {LOG_FILE}")

if __name__ == "__main__":
    input_file = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/DataProcessing/NOT_phishing_site_ips.csv"
    process_ips(input_file)