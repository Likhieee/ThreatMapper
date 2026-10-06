from graph.connection import get_driver

driver = get_driver()


def find_hidden_links():

    with driver.session() as session:

        result = session.run("""
        MATCH (a:ThreatActor)-[:USES]->(m:Malware)<-[:USES]-(b:ThreatActor)
        WHERE a.name < b.name
        RETURN
            a.name AS actor1,
            b.name AS actor2,
            collect(m.name) AS shared_malware
        ORDER BY size(shared_malware) DESC
        """)

        return list(result)


if __name__ == "__main__":

    links = find_hidden_links()

    print("\n========== Hidden Links ==========\n")

    if len(links) == 0:
        print("No hidden links found.")
    else:
        for link in links:

            print("Threat Actor 1 :", link["actor1"])
            print("Threat Actor 2 :", link["actor2"])
            print("Shared Malware :", ", ".join(link["shared_malware"]))
            print("-" * 50)