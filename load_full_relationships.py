import os
import sys
import pandas as pd
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

URI = os.getenv("NEO4J_URI")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")

if not URI or not USERNAME or not PASSWORD:
    print("❌ Error: Missing Neo4j credentials in .env file.")
    sys.exit(1)

print(f"Connecting to Neo4j at {URI}...")
try:
    driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
    with driver.session() as s:
        s.run("RETURN 1")
    print("✅ Connected to Neo4j successfully!")
except Exception as e:
    print(f"❌ Failed to connect to Neo4j: {e}")
    sys.exit(1)

BATCH_SIZE = 250

def batch_import(session, query, data, desc="Importing"):
    total = len(data)
    print(f"{desc} ({total} records)...")
    for i in range(0, total, BATCH_SIZE):
        batch = data[i:i+BATCH_SIZE]
        session.run(query, rows=batch)
        print(f"  Processed {min(i+BATCH_SIZE, total)}/{total}...", end="\r")
    print(f"  ✅ Completed {total} records.")

# 1. Load MITRE Relationships
rel_path = "backup/datasets/mitre_relationships.csv"
if not os.path.exists(rel_path):
    rel_path = "datasets/mitre_relationships.csv"

if os.path.exists(rel_path):
    df = pd.read_csv(rel_path)
    
    # Actor -> Malware
    malware_rels = df[df["target_type"] == "Malware"][["source", "target"]].dropna().to_dict("records")
    with driver.session() as session:
        batch_import(session, """
            UNWIND $rows AS row
            MERGE (a:ThreatActor {name: row.source})
            MERGE (m:Malware {name: row.target})
            MERGE (a)-[:USES]->(m)
        """, malware_rels, "Loading Actor -> Malware (USES)")

    # Actor -> Technique
    tech_rels = df[df["target_type"] == "Technique"][["source", "target", "tech_id"]].dropna(subset=["source", "target"]).to_dict("records")
    with driver.session() as session:
        batch_import(session, """
            UNWIND $rows AS row
            MERGE (a:ThreatActor {name: row.source})
            MERGE (t:Technique {id: coalesce(row.tech_id, row.target)})
            SET t.name = row.target
            MERGE (a)-[:USES]->(t)
        """, tech_rels, "Loading Actor -> Technique (USES)")
else:
    print(f"⚠️ Warning: {rel_path} not found.")

# 2. Load IOC -> Malware Relationships
iocs_path = "backup/datasets/iocs.csv"
if not os.path.exists(iocs_path):
    iocs_path = "datasets/iocs.csv"

if os.path.exists(iocs_path):
    iocs_df = pd.read_csv(iocs_path).dropna(subset=["ioc", "malware"])
    ioc_rows = [
        {"ioc": str(r["ioc"]).strip(), "malware": str(r["malware"]).strip(), "type": str(r.get("ioc_type", "domain"))}
        for _, r in iocs_df.iterrows()
    ]
    with driver.session() as session:
        batch_import(session, """
            UNWIND $rows AS row
            MERGE (i:IOC {value: row.ioc})
            SET i.type = row.type
            MERGE (m:Malware {name: row.malware})
            MERGE (i)-[:INDICATES]->(m)
        """, ioc_rows[:1500], "Loading IOC -> Malware (INDICATES)")

# 3. Load Sample CVE Links
cve_links = [
    {"malware": "WannaCry", "cve": "CVE-2017-0144"},
    {"malware": "WannaCry", "cve": "CVE-2017-0145"},
    {"malware": "NotPetya", "cve": "CVE-2017-0144"},
    {"malware": "Industroyer2", "cve": "CVE-2022-30190"},
    {"malware": "Cobalt Strike", "cve": "CVE-2021-44228"},
    {"malware": "Cobalt Strike", "cve": "CVE-2021-40444"},
    {"malware": "BlackCat", "cve": "CVE-2021-31207"},
    {"malware": "BlackByte", "cve": "CVE-2022-26134"},
    {"malware": "TrickBot", "cve": "CVE-2020-0796"},
    {"malware": "Emotet", "cve": "CVE-2017-11882"},
    {"malware": "LockBit", "cve": "CVE-2023-4966"},
    {"malware": "BlackEnergy", "cve": "CVE-2014-4114"},
    {"malware": "PlugX", "cve": "CVE-2023-23397"},
    {"malware": "Zebrocy", "cve": "CVE-2021-34473"},
    {"malware": "BabyShark", "cve": "CVE-2024-3400"},
    {"malware": "WellMail", "cve": "CVE-2024-21413"},
    {"malware": "SOGU", "cve": "CVE-2024-3821"}
]
with driver.session() as session:
    batch_import(session, """
        UNWIND $rows AS row
        MERGE (m:Malware {name: row.malware})
        MERGE (c:CVE {id: row.cve})
        MERGE (m)-[:EXPLOITS]->(c)
    """, cve_links, "Loading Malware -> CVE (EXPLOITS)")

driver.close()
print("\n=======================================================")
print("🎉 Full Graph Relationships Successfully Loaded to Neo4j!")
print("=======================================================")
