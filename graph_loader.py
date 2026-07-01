from neo4j import GraphDatabase
import pandas as pd

# =====================================
# Neo4j Connection
# =====================================

URI = "neo4j://127.0.0.1:7687"
USERNAME = "neo4j"
PASSWORD = "threat123"

driver = GraphDatabase.driver(
    URI,
    auth=(USERNAME, PASSWORD)
)

# =====================================
# Import Threat Actors
# =====================================

actors = pd.read_csv("datasets/mitre_groups.csv")

with driver.session() as session:

    for _, row in actors.iterrows():

        session.run(
            """
            MERGE (a:ThreatActor {name:$name})

            SET
                a.aliases=$aliases,
                a.description=$description
            """,

            name=str(row["actor"]),
            aliases=str(row["aliases"]),
            description=str(row["description"])
        )

print(f"✅ Threat Actors Imported : {actors['actor'].nunique()}")

# =====================================
# Import Malware
# =====================================

malware = pd.read_csv("datasets/mitre_malware.csv")

with driver.session() as session:

    for _, row in malware.iterrows():

        session.run(
            """
            MERGE (m:Malware {name:$name})

            SET
                m.description=$description
            """,

            name=str(row["malware"]),
            description=str(row["description"])
        )

print(f"✅ Malware Imported : {malware['malware'].nunique()}")

# =====================================
# Import MITRE Techniques
# =====================================

techniques = pd.read_csv("datasets/mitre_techniques.csv")

# Ignore rows without technique_id
techniques = techniques.dropna(subset=["technique_id"])

with driver.session() as session:

    for _, row in techniques.iterrows():

        session.run(
            """
            MERGE (t:Technique {id:$id})

            SET
                t.name=$name,
                t.description=$description
            """,

            id=str(row["technique_id"]),
            name=str(row["technique_name"]),
            description=str(row["description"])
        )

print(f"✅ Techniques Imported : {techniques['technique_id'].nunique()}")

# =====================================
# Import CVEs
# =====================================

cves = pd.read_csv("datasets/cves.csv")

with driver.session() as session:

    for _, row in cves.iterrows():

        session.run(
            """
            MERGE (c:CVE {id:$id})

            SET
                c.published=$published
            """,

            id=str(row["cve_id"]),
            published=str(row["published"])
        )

print(f"✅ CVEs Imported : {cves['cve_id'].nunique()}")

# =====================================
# Import IOCs
# =====================================

iocs = pd.read_csv("datasets/iocs.csv")

with driver.session() as session:

    for _, row in iocs.iterrows():

        session.run(
            """
            MERGE (i:IOC {value:$value})

            SET
                i.type=$type,
                i.first_seen=$first_seen
            """,

            value=str(row["ioc"]),
            type=str(row["ioc_type"]),
            first_seen=str(row["first_seen"])
        )

print(f"✅ IOCs Imported : {iocs['ioc'].nunique()}")

# =====================================
# Import OTX Pulses
# =====================================

pulses = pd.read_csv("datasets/otx_pulses.csv")

with driver.session() as session:

    for _, row in pulses.iterrows():

        session.run(
            """
            MERGE (p:Pulse {name:$name})

            SET
                p.created=$created,
                p.modified=$modified,
                p.adversary=$adversary
            """,

            name=str(row["pulse_name"]),
            created=str(row["created"]),
            modified=str(row["modified"]),
            adversary=str(row["adversary"])
        )

print(f"✅ Pulses Imported : {pulses['pulse_name'].nunique()}")

# =====================================
# Close Connection
# =====================================

driver.close()

print("\n===================================")
print(" Knowledge Graph Node Import Done ")
print("===================================")