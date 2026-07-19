import json
from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()

URI = os.getenv("NEO4J_URI")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))

print("Loading MITRE ATT&CK STIX data...")
with open('cti-master/enterprise-attack/enterprise-attack.json', 'r') as f:
    data = json.load(f)

objects = data['objects']
print(f"Total STIX objects: {len(objects)}")

# Build lookup maps
groups = {}  # id -> name
software = {}  # id -> name
techniques = {}  # id -> {id, name}

for obj in objects:
    if obj.get('type') == 'intrusion-set':
        groups[obj['id']] = obj.get('name')
    elif obj.get('type') in ('malware', 'tool'):
        software[obj['id']] = obj.get('name')
    elif obj.get('type') == 'attack-pattern':
        ext_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                ext_id = ref.get('external_id')
        if ext_id:
            techniques[obj['id']] = {'id': ext_id, 'name': obj.get('name')}

print(f"Groups (actors): {len(groups)}")
print(f"Software (malware): {len(software)}")
print(f"Techniques: {len(techniques)}")

# Extract relationships: group USES malware, group USES technique
uses_malware = []
uses_technique = []

for obj in objects:
    if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses':
        src = obj.get('source_ref')
        tgt = obj.get('target_ref')
        if src in groups:
            actor_name = groups[src]
            if tgt in software:
                uses_malware.append({'actor': actor_name, 'malware': software[tgt]})
            elif tgt in techniques:
                uses_technique.append({'actor': actor_name, 'technique_id': techniques[tgt]['id'], 'technique_name': techniques[tgt]['name']})

print(f"Actor->Malware relationships: {len(uses_malware)}")
print(f"Actor->Technique relationships: {len(uses_technique)}")

# Batch load into Neo4j
BATCH = 100

def batch_load(session, query, data):
    for i in range(0, len(data), BATCH):
        batch = data[i:i+BATCH]
        session.run(query, rows=batch)
        print(f"  {min(i+BATCH,len(data))}/{len(data)}...", end='\r')
    print()

with driver.session() as session:
    print("\nLoading Actor->Malware (USES) relationships...")
    batch_load(session, """
        UNWIND $rows AS row
        MERGE (a:ThreatActor {name: row.actor})
        MERGE (m:Malware {name: row.malware})
        MERGE (a)-[:USES]->(m)
    """, uses_malware)

    print("Loading Actor->Technique (USES) relationships...")
    batch_load(session, """
        UNWIND $rows AS row
        MERGE (a:ThreatActor {name: row.actor})
        MERGE (t:Technique {id: row.technique_id})
        SET t.name = row.technique_name
        MERGE (a)-[:USES]->(t)
    """, uses_technique)

driver.close()
print("\n✅ Full MITRE relationships loaded!")
