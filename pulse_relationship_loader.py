from neo4j import GraphDatabase
import pandas as pd

URI = "neo4j://127.0.0.1:7687"
USERNAME = "neo4j"
PASSWORD = "threat123"

driver = GraphDatabase.driver(
    URI,
    auth=(USERNAME, PASSWORD)
)

df = pd.read_csv("datasets/otx_pulses.csv")

with driver.session() as session:

    for _, row in df.iterrows():

        pulse = str(row["pulse_name"]).strip()

        if pd.isna(row["adversary"]):
            continue

        actor = str(row["adversary"]).strip()

        session.run(
            """
            MATCH (p:Pulse {name:$pulse})
            MATCH (a:ThreatActor {name:$actor})

            MERGE (p)-[:MENTIONS]->(a)
            """,

            pulse=pulse,
            actor=actor
        )

driver.close()

print("✅ Pulse -> ThreatActor relationships created.")