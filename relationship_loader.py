from neo4j import GraphDatabase
import pandas as pd

# -------------------------
# Neo4j Connection
# -------------------------

URI = "neo4j://127.0.0.1:7687"
USERNAME = "neo4j"
PASSWORD = "threat123"

driver = GraphDatabase.driver(
    URI,
    auth=(USERNAME, PASSWORD)
)

# -------------------------
# Read entities.csv
# -------------------------

df = pd.read_csv("datasets/entities.csv")

with driver.session() as session:

    for _, row in df.iterrows():

        actor = str(row["threat_actor"]).strip()
        malware = str(row["malware"]).strip()

        session.run(
            """
            MATCH (a:ThreatActor {name:$actor})
            MATCH (m:Malware {name:$malware})

            MERGE (a)-[:USES]->(m)
            """,

            actor=actor,
            malware=malware
        )

driver.close()

print("✅ ThreatActor -> Malware relationships created.")