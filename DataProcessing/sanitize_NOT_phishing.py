# sanitize file with NOT phishing sites

import csv 
from pathlib import Path

def clean_line(text):
    """
    Example of sanitization: "123,google.com" -> "google.com"
    """
    text = text.strip()
    
    if len(text) > 0 and text[0].isdigit():
        comma_pos = text.find(',')
        if comma_pos != -1 and comma_pos <= 3:
            return text[comma_pos + 1:].strip()
    
    return text

def sanitize_csv(input_file):
   
    cleaned_lines = []
    
    with open(input_file, 'r', encoding='utf-8') as file:
        for line in file:
            cleaned = clean_line(line)
            if cleaned:
                cleaned_lines.append(cleaned)
    
    with open(input_file, 'w', encoding='utf-8', newline='') as file:
        for line in cleaned_lines:
            file.write(line + '\n')
    
    print(f"File updated: {input_file}")
    
    return cleaned_lines

input_file = r"/home/alelxsalc03/Desktop/IS/DetectPhishingIS/DataProcessing/Not_phishing_sites.csv"
sanitize_csv(input_file)
