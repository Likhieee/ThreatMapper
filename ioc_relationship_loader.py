from neo4j import GraphDatabase
import pandas as pd

URI = "neo4j://127.0.0.1:7687"
USERNAME = "neo4j"
PASSWORD = "threat123"

driver = GraphDatabase.driver(
    URI,
    auth=(USERNAME, PASSWORD)
)

df = pd.read_csv("datasets/iocs.csv")

with driver.session() as session:

    for _, row in df.iterrows():

        malware = str(row["malware"]).strip()
        ioc = str(row["ioc"]).strip()

        session.run(
            """
            MATCH (i:IOC {value:$ioc})
            MATCH (m:Malware {name:$malware})

            MERGE (i)-[:INDICATES]->(m)
            """,

            ioc=ioc,
            malware=malware
        )

driver.close()

print("✅ IOC -> Malware relationships created.")