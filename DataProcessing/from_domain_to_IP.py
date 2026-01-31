import socket
import time

def resolve_domain_to_ip(domain):
    """
    Risolve un dominio in IP. Se fallisce, prova con www.
    
    Returns:
        str or None: IP address se risolto, None altrimenti
    """
    domain = domain.strip()
    
    # Prima prova: dominio originale
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        pass
    
    # Seconda prova: aggiungi www. se non c'è già
    if not domain.startswith('www.'):
        try:
            www_domain = f'www.{domain}'
            ip = socket.gethostbyname(www_domain)
            return ip
        except socket.gaierror:
            pass
    
    return None

def domains_to_ips(input_file, output_file):
    """
    Legge un file con domini e crea un nuovo file con solo gli IP risolti.
    """
    try:
        # Leggi i domini
        with open(input_file, 'r', encoding='utf-8') as infile:
            domains = [line.strip() for line in infile if line.strip()]
        
        print(f"Domini totali da risolvere: {len(domains)}")
        print("Inizio risoluzione DNS...\n")
        
        resolved_ips = []
        failed_count = 0
        
        for i, domain in enumerate(domains, 1):
            ip = resolve_domain_to_ip(domain)
            
            if ip:
                resolved_ips.append(ip)
                if i <= 10:  # Mostra i primi 10
                    print(f"✓ {i}. {domain} → {ip}")
            else:
                failed_count += 1
                if i <= 10:
                    print(f"✗ {i}. {domain} → NON RISOLTO (scartato)")
            
            # Progress ogni 50 domini
            if i % 50 == 0:
                print(f"Progresso: {i}/{len(domains)} domini processati...")
            
            # Piccola pausa per non sovraccaricare il DNS
            time.sleep(0.01)
        
        # Scrivi solo gli IP risolti nel file di output
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for ip in resolved_ips:
                outfile.write(ip + '\n')
        
        # Statistiche finali
        print(f"\n{'='*50}")
        print(f"STATISTICHE FINALI:")
        print(f"{'='*50}")
        print(f"✓ IP risolti: {len(resolved_ips)}")
        print(f"✗ Domini scartati: {failed_count}")
        print(f"Totale domini: {len(domains)}")
        print(f"\n✓ File salvato: {output_file}")
        
    except FileNotFoundError:
        print(f"✗ Errore: File '{input_file}' non trovato")
    except Exception as e:
        print(f"✗ Errore durante l'elaborazione: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    input_file = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/DataProcessing/Not_phishing_sites.csv"
    output_file = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/DataProcessing/NOT_phishing_site_ips.csv"
    
    domains_to_ips(input_file, output_file)