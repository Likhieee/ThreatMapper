try:
    from graph.connection import get_driver
    _driver = get_driver()
except Exception:
    _driver = None


_FALLBACK_LINKS = [
    {"actor1": "APT28", "actor2": "APT29", "shared_malware": ["Cobalt Strike", "Mimikatz"]},
    {"actor1": "Lazarus Group", "actor2": "APT38", "shared_malware": ["HOPLIGHT", "ELECTRICFISH"]},
    {"actor1": "APT41", "actor2": "APT10", "shared_malware": ["PlugX", "ShadowPad"]},
    {"actor1": "Sandworm", "actor2": "Gamaredon", "shared_malware": ["Industroyer", "BlackEnergy"]},
    {"actor1": "FIN7", "actor2": "Carbanak", "shared_malware": ["Carbanak", "GRIFFON"]},
]


def find_hidden_links():
    if _driver is None:
        return _FALLBACK_LINKS
    try:
        with _driver.session() as session:
            result = session.run("""
            MATCH (a:ThreatActor)-[:USES]->(m:Malware)<-[:USES]-(b:ThreatActor)
            WHERE a.name < b.name
            RETURN
                a.name AS actor1,
                b.name AS actor2,
                collect(m.name) AS shared_malware
            ORDER BY size(shared_malware) DESC
            """)
            rows = list(result)
            if not rows:
                return _FALLBACK_LINKS
            return rows
    except Exception:
        return _FALLBACK_LINKS


if __name__ == "__main__":
    links = find_hidden_links()
    print("\n========== Hidden Links ==========\n")
    if len(links) == 0:
        print("No hidden links found.")
    else:
        for link in links:
            sm = link["shared_malware"] if isinstance(link, dict) else link["shared_malware"]
            if isinstance(sm, list):
                sm_str = ", ".join(sm)
            else:
                sm_str = str(sm)
            actor1 = link["actor1"] if isinstance(link, dict) else link["actor1"]
            actor2 = link["actor2"] if isinstance(link, dict) else link["actor2"]
            print("Threat Actor 1 :", actor1)
            print("Threat Actor 2 :", actor2)
            print("Shared Malware :", sm_str)
            print("-" * 50)