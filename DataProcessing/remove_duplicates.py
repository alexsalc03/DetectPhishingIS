def remove_duplicates(file_path):
    try:
        
        with open(file_path, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        
        print(f"Righe totali prima: {len(lines)}")
        
     
        seen = set()
        unique_lines = []
        duplicates_count = 0
        
        for line in lines:
            line_clean = line.strip()
            if line_clean and line_clean not in seen:
                seen.add(line_clean)
                unique_lines.append(line_clean)
            elif line_clean in seen:
                duplicates_count += 1
        
        with open(file_path, 'w', encoding='utf-8') as outfile:
            for line in unique_lines:
                outfile.write(line + '\n')
        
        print(f"Righe totali dopo: {len(unique_lines)}")
        print(f"Duplicati rimossi: {duplicates_count}")
        print(f"\n✓ File '{file_path}' aggiornato con successo")
        
    except FileNotFoundError:
        print(f"✗ Errore: File '{file_path}' non trovato")
    except Exception as e:
        print(f"✗ Errore durante l'elaborazione: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    file_csv = "/home/alelxsalc03/Desktop/IS/DetectPhishingIS/DataProcessing/phishing_site.csv"
    remove_duplicates(file_csv)