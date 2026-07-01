from graph.connection import get_driver

driver = get_driver()


def calculate_scores():

    with driver.session() as session:

        result = session.run("""

        MATCH (a:ThreatActor)-[:USES]->(m:Malware)<-[:USES]-(b:ThreatActor)

        WHERE a.name < b.name

        RETURN

        a.name AS actor1,

        b.name AS actor2,

        collect(m.name) AS malware,

        count(m) AS score

        ORDER BY score DESC

        """)

        return list(result)


if __name__ == "__main__":

    scores = calculate_scores()

    print("\n========== Relationship Scores ==========\n")

    for row in scores:

        similarity = row["score"] * 25

        if similarity > 100:
            similarity = 100

        print(f"{row['actor1']}  <---->  {row['actor2']}")

        print(f"Similarity : {similarity}%")

        print("Shared Malware :")

        for malware in row["malware"]:
            print("   •", malware)

        print("-" * 60)