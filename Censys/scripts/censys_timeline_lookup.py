import requests
import json
import csv
import os
from datetime import datetime, timedelta
import time
from dotenv import load_dotenv
import os

load_dotenv()

CENSYS_API_TOKEN = os.getenv("CENSYS_API_TOKEN")
CENSYS_ORG_ID = os.getenv("CENSYS_ORG_ID")


CENSYS_API_BASE_URL = "https://api.platform.censys.io/v3/global/asset/host"

# Path
BASE_DIR = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/Censys"
TIMELINE_RAW_DIR = os.path.join(BASE_DIR, "raw", "timeline")
TIMELINE_LOG_FILE = os.path.join(BASE_DIR, "logs", "host_timeline_log.csv")

def init_timeline_log_file():
    """Inizializza il file di log per timeline"""
    if not os.path.exists(TIMELINE_LOG_FILE):
        with open(TIMELINE_LOG_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'status_code', 'found', 'num_observations', 'timestamp', 'error'])

def get_time_window(days_back=180):
    """Calcola finestra temporale (ultimi N giorni)"""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days_back)
    
    return (
        start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    )

def censys_host_timeline(ip, start_time, end_time, max_retries=3):
    """
    Effettua timeline lookup su Censys per un singolo IP
    
    Returns:
        tuple: (response_dict, status_code, error_message)
    """
    url = f"{CENSYS_API_BASE_URL}/{ip}/timeline"
    
    headers = {
        'Authorization': f'Bearer {CENSYS_API_TOKEN}',
        'Accept': 'application/vnd.censys.api.v3.host.v1+json',
        'X-Organization-ID': CENSYS_ORG_ID
    }
    
    params = {
        'start_time': start_time,
        'end_time': end_time
    }
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            status_code = response.status_code
            
            if status_code == 200:
                return (response.json(), status_code, None)
            elif status_code == 404:
                return (None, status_code, "timeline_not_found")
            elif status_code == 401:
                return (None, status_code, "invalid_token")
            elif status_code == 403:
                return (None, status_code, "permission_denied")
            elif status_code == 422:
                return (None, status_code, "unprocessable_entity")
            elif status_code == 429:
                # Rate limit - backoff exponenziale
                wait_time = 2 ** attempt
                print(f"  Rate limit hit, waiting {wait_time}s...")
                time.sleep(wait_time)
                continue
            elif status_code == 500:
                return (None, status_code, "internal_server_error")
            else:
                return (None, status_code, f"http_error_{status_code}")
                
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return (None, 0, "timeout")
        except requests.exceptions.RequestException as e:
            return (None, 0, f"request_error: {str(e)}")
        except Exception as e:
            return (None, 0, f"error: {str(e)}")
    
    return (None, 429, "max_retries_exceeded")

def save_timeline_response(ip, data):
    """Salva la risposta timeline raw in formato JSON"""
    filename = os.path.join(TIMELINE_RAW_DIR, f"{ip}.json")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def log_timeline_result(ip, status_code, found, num_observations, error):
    """Aggiunge un record al file di log timeline"""
    timestamp = datetime.now().strftime("%Y-%m-%d")
    
    with open(TIMELINE_LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            ip,
            status_code,
            1 if found else 0,
            num_observations if num_observations is not None else 0,
            timestamp,
            error if error else ''
        ])

def count_timeline_observations(data):
    """Conta le osservazioni nella timeline"""
    if not data or 'result' not in data:
        return 0
    
    # La struttura esatta dipende dalla risposta di Censys
    # Potrebbe essere 'observations', 'events', 'timeline', etc.
    result = data['result']
    
    if 'observations' in result:
        return len(result['observations'])
    elif 'events' in result:
        return len(result['events'])
    elif 'timeline' in result:
        return len(result['timeline'])
    
    return 0

def process_timeline_for_ips(ip_list_file, days_back=180):
    """
    Processa timeline per tutti gli IP dal file
    
    Args:
        ip_list_file: path al file con lista IP (uno per riga)
        days_back: quanti giorni indietro guardare
    """
    init_timeline_log_file()
    
    # Leggi IP
    try:
        with open(ip_list_file, 'r', encoding='utf-8') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Errore: File '{ip_list_file}' non trovato")
        return
    
    # Rimuovi duplicati
    ips = list(dict.fromkeys(ips))
    
    # Calcola finestra temporale
    start_time, end_time = get_time_window(days_back)
    
    print(f"IP totali da processare: {len(ips)}")
    print(f"Finestra temporale: {start_time} to {end_time} ({days_back} giorni)")
    print(f"Inizio timeline lookup su Censys...\n")
    
    if CENSYS_ORG_ID == "YOUR_ORG_ID":
        print("ATTENZIONE: Devi configurare il tuo Organization ID!")
        return
    
    stats = {
        'found': 0,
        'not_found': 0,
        'errors': 0,
        'total_observations': 0
    }
    
    for i, ip in enumerate(ips, 1):
        print(f"[{i}/{len(ips)}] Processing timeline for {ip}...", end=' ')
        
        data, status_code, error = censys_host_timeline(ip, start_time, end_time)
        
        if status_code == 200 and data:
            num_obs = count_timeline_observations(data)
            save_timeline_response(ip, data)
            log_timeline_result(ip, status_code, True, num_obs, None)
            stats['found'] += 1
            stats['total_observations'] += num_obs
            print(f"TROVATO ({num_obs} observations)")
        elif status_code == 404:
            log_timeline_result(ip, status_code, False, 0, error)
            stats['not_found'] += 1
            print(f"TIMELINE NON DISPONIBILE")
        else:
            log_timeline_result(ip, status_code, False, 0, error)
            stats['errors'] += 1
            print(f"ERRORE: {error}")
        
        # Rate limiting - più conservativo per timeline
        if i < len(ips):
            time.sleep(2.0)
    
    print(f"\n{'='*60}")
    print(f"STATISTICHE FINALI:")
    print(f"{'='*60}")
    print(f"Timeline trovate: {stats['found']}")
    print(f"Timeline non disponibili: {stats['not_found']}")
    print(f"Errori: {stats['errors']}")
    print(f"Totale osservazioni: {stats['total_observations']}")
    print(f"Media osservazioni per IP: {stats['total_observations']/max(stats['found'], 1):.1f}")
    print(f"\nTimeline raw salvate in: {TIMELINE_RAW_DIR}")
    print(f"Log salvato in: {TIMELINE_LOG_FILE}")

if __name__ == "__main__":
    # PHISHING IPs
    print("="*60)
    print("ELABORAZIONE TIMELINE PHISHING IPs")
    print("="*60)
    process_timeline_for_ips(
        "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/DataProcessing/phishing_site_ips.csv",
        days_back=180
    )
    
