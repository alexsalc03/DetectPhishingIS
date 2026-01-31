from urllib.parse import urlparse

def extract_domain(url):
    url = url.strip()
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Rimuove credenziali e porta
        if '@' in domain:
            domain = domain.split('@')[1]
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Lista di TLD a due parti comuni (country code TLDs)
        double_tlds = ['co.uk', 'com.au', 'co.jp', 'com.br', 'co.za', 'com.mx', 
                       'com.kz', 'com.py', 'com.ge', 'com.ml', 'com.ps', 'com.ar',
                       'co.in', 'co.nz', 'com.my', 'com.sg', 'com.ph', 'com.tr']
        
        parts = domain.split('.')
        
        # Controlla se ha un TLD a due parti
        if len(parts) >= 3:
            # Controlla gli ultimi due segmenti
            possible_double_tld = '.'.join(parts[-2:])
            if possible_double_tld in double_tlds:
                # Prendi dominio + TLD a due parti (es. roblox.com.kz)
                domain = '.'.join(parts[-3:])
            else:
                # TLD normale, prendi solo dominio + TLD (es. google.com)
                domain = '.'.join(parts[-2:])
        elif len(parts) == 2:
            # È già dominio.tld
            domain = '.'.join(parts)
        
        return domain
    except Exception as e:
        print(f"Errore nel parsing di '{url}': {e}")
        return url

def sanitize_csv(file_path):
    try:
        # Leggi tutte le righe
        with open(file_path, 'r', encoding='utf-8') as infile:
            urls = infile.readlines()
        
        print(f"Totale righe lette: {len(urls)}")
        
        # Sanitizza gli URL
        sanitized_urls = []
        for i, url in enumerate(urls):
            url = url.strip()
            if url:  # Ignora righe vuote
                sanitized = extract_domain(url)
                sanitized_urls.append(sanitized)
                
                # Mostra le prime 5 conversioni
                if i < 5:
                    print(f"Riga {i+1}: '{url}' → '{sanitized}'")
        
        # Sovrascrivi il file con gli URL sanitizzati
        with open(file_path, 'w', encoding='utf-8') as outfile:
            for url in sanitized_urls:
                outfile.write(url + '\n')
        
        print(f"\n✓ File sanitizzato con successo")
        print(f"✓ Processate {len(sanitized_urls)} righe")
        
    except FileNotFoundError:
        print(f"✗ Errore: File '{file_path}' non trovato")
    except Exception as e:
        print(f"✗ Errore durante l'elaborazione: {e}")

if __name__ == "__main__":
    file_csv = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/DataProcessing/phishing_site.csv"
    sanitize_csv(file_csv)
