import csv
import json
from pathlib import Path

from crateshield.config import ROOT

KB_DIR = ROOT / "data" / "knowledge_base"
CSV_PATH = ROOT / "data" / "reference" / "known_supply_chain_incidents.csv"

def build_kb():
    KB_DIR.mkdir(parents=True, exist_ok=True)
    
    if not CSV_PATH.exists():
        print(f"Error: {CSV_PATH} not found.")
        return
        
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        count = 0
        for i, row in enumerate(reader):
            incident_id = row.get("id", f"incident_{i}")
            if not incident_id.strip():
                incident_id = f"incident_{i}"
                
            pkg = row.get("package", "").split(" (")[0].strip()
            if not pkg:
                continue
                
            # Convert CSV to KB JSON schema
            doc = {
                "id": incident_id,
                "title": f"Supply Chain Attack on {pkg}",
                "source": row.get("source", "Unknown"),
                "source_url": "",
                "ecosystem": row.get("ecosystem", "Rust"),
                "attack_category": row.get("attack_category", "malicious"),
                "technical_mechanism": row.get("technical_mechanism", ""),
                "indicators": [pkg],
                "severity": "CRITICAL",
                "summary": f"A malicious package '{pkg}' was discovered in the {row.get('ecosystem', 'Rust')} ecosystem. The attack involved {row.get('attack_category')}. Mechanism: {row.get('technical_mechanism')}",
                "date": row.get("discovered_date", "")
            }
            
            # Clean filename
            safe_id = "".join(c if c.isalnum() else "_" for c in incident_id).strip("_")
            out_file = KB_DIR / f"{safe_id}.json"
            out_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            count += 1
            
    print(f"Built {count} knowledge base documents in {KB_DIR}")

if __name__ == "__main__":
    build_kb()
