from neo4j import GraphDatabase
import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv()

URI = os.getenv("NEO4J_URI")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))

# =====================================
# BATCH SIZE — processes 100 at a time
# =====================================
BATCH_SIZE = 100

def batch_import(session, query, data, batch_size=BATCH_SIZE):
    for i in range(0, len(data), batch_size):
        batch = data[i:i+batch_size]
        session.run(query, rows=batch)
        print(f"  Imported {min(i+batch_size, len(data))}/{len(data)}...", end='\r')
    print()

# =====================================
# Import Threat Actors
# =====================================
print("Importing Threat Actors...")
actors = pd.read_csv("backup/datasets/mitre_groups.csv")
actors_data = [
    {"name": str(r["actor"]), "aliases": str(r["aliases"]), "description": str(r["description"])}
    for _, r in actors.iterrows()
]
with driver.session() as session:
    batch_import(session, """
        UNWIND $rows AS row
        MERGE (a:ThreatActor {name: row.name})
        SET a.aliases = row.aliases, a.description = row.description
    """, actors_data)
print(f"✅ Threat Actors Imported: {actors['actor'].nunique()}")

# =====================================
# Import Malware
# =====================================
print("Importing Malware...")
malware = pd.read_csv("backup/datasets/mitre_malware.csv")
malware_data = [
    {"name": str(r["malware"]), "description": str(r["description"])}
    for _, r in malware.iterrows()
]
with driver.session() as session:
    batch_import(session, """
        UNWIND $rows AS row
        MERGE (m:Malware {name: row.name})
        SET m.description = row.description
    """, malware_data)
print(f"✅ Malware Imported: {malware['malware'].nunique()}")

# =====================================
# Import Techniques
# =====================================
print("Importing Techniques...")
techniques = pd.read_csv("backup/datasets/mitre_techniques.csv")
techniques = techniques.dropna(subset=["technique_id"])
techniques_data = [
    {"id": str(r["technique_id"]), "name": str(r["technique_name"]), "description": str(r["description"])}
    for _, r in techniques.iterrows()
]
with driver.session() as session:
    batch_import(session, """
        UNWIND $rows AS row
        MERGE (t:Technique {id: row.id})
        SET t.name = row.name, t.description = row.description
    """, techniques_data)
print(f"✅ Techniques Imported: {techniques['technique_id'].nunique()}")

# =====================================
# Import CVEs
# =====================================
print("Importing CVEs...")
cves = pd.read_csv("backup/datasets/cves.csv")
cves_data = [
    {"id": str(r["cve_id"]), "published": str(r["published"])}
    for _, r in cves.iterrows()
]
with driver.session() as session:
    batch_import(session, """
        UNWIND $rows AS row
        MERGE (c:CVE {id: row.id})
        SET c.published = row.published
    """, cves_data)
print(f"✅ CVEs Imported: {cves['cve_id'].nunique()}")

# =====================================
# Import IOCs
# =====================================
print("Importing IOCs...")
iocs = pd.read_csv("backup/datasets/iocs.csv")
iocs_data = [
    {"value": str(r["ioc"]), "type": str(r["ioc_type"]), "first_seen": str(r["first_seen"])}
    for _, r in iocs.iterrows()
]
with driver.session() as session:
    batch_import(session, """
        UNWIND $rows AS row
        MERGE (i:IOC {value: row.value})
        SET i.type = row.type, i.first_seen = row.first_seen
    """, iocs_data)
print(f"✅ IOCs Imported: {iocs['ioc'].nunique()}")

# =====================================
# Import OTX Pulses
# =====================================
print("Importing OTX Pulses...")
pulses = pd.read_csv("backup/datasets/otx_pulses.csv")
pulses_data = [
    {"name": str(r["pulse_name"]), "created": str(r["created"]), 
     "modified": str(r["modified"]), "adversary": str(r["adversary"])}
    for _, r in pulses.iterrows()
]
with driver.session() as session:
    batch_import(session, """
        UNWIND $rows AS row
        MERGE (p:Pulse {name: row.name})
        SET p.created = row.created, p.modified = row.modified, p.adversary = row.adversary
    """, pulses_data)
print(f"✅ Pulses Imported: {pulses['pulse_name'].nunique()}")

driver.close()
print("\n===================================")
print(" Knowledge Graph Node Import Done ")
print("===================================")