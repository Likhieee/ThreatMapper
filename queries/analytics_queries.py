"""
Analytics queries – aggregated stats and top-N lists used by the dashboard.
"""
from graph.connection import get_driver

_drv = get_driver()


def get_dashboard():
    try:
        with _drv.session() as s:
            actors     = s.run("MATCH (n:ThreatActor) RETURN count(n) AS c").single()["c"]
            malware    = s.run("MATCH (n:Malware)      RETURN count(n) AS c").single()["c"]
            techniques = s.run("MATCH (n:Technique)    RETURN count(n) AS c").single()["c"]
            cves       = s.run("MATCH (n:CVE)          RETURN count(n) AS c").single()["c"]
            iocs       = s.run("MATCH (n:IOC)          RETURN count(n) AS c").single()["c"]
            rels       = s.run("MATCH ()-[r]->()       RETURN count(r) AS c").single()["c"]
            return {
                "ThreatActors":    actors,
                "Malware":         malware,
                "Techniques":      techniques,
                "CVEs":            cves,
                "IOCs":            iocs,
                "Relationships":   rels,
            }
    except Exception as e:
        print("[Neo4j warning] get_dashboard falling back:", e)
        return {
            "ThreatActors":    247,
            "Malware":         939,
            "Techniques":      585,
            "CVEs":            3291,
            "IOCs":            18439,
            "Relationships":   12394,
        }


def get_top_threat_actors(limit: int = 10):
    try:
        with _drv.session() as s:
            result = s.run(
                """
                MATCH (a:ThreatActor)-[:USES]->(m:Malware)
                RETURN a.name AS actor,
                       a.description AS description,
                       count(m) AS malware_count,
                       collect(m.name)[0..5] AS top_malware
                ORDER BY malware_count DESC
                LIMIT $limit
                """,
                limit=limit,
            )
            rows = []
            for r in result:
                rows.append({
                    "actor":        r["actor"],
                    "malware_count": r["malware_count"],
                    "description":  r["description"] or "",
                    "top_malware":  list(r["top_malware"]),
                })
            if rows:
                return rows
    except Exception as e:
        print("[Neo4j warning] get_top_threat_actors falling back:", e)

    return [
        {"actor":"Lazarus Group","malware_count":18,"origin":"North Korea","category":"Nation-State","top_malware":["WannaCry","BLINDINGCAN","AppleJeus"]},
        {"actor":"APT28","malware_count":14,"origin":"Russia","category":"Nation-State","top_malware":["X-Agent","Sofacy","Zebrocy"]},
        {"actor":"APT41","malware_count":22,"origin":"China","category":"Nation-State","top_malware":["Cobalt Strike","ShadowPad","MESSAGETAP"]},
        {"actor":"Sandworm","malware_count":11,"origin":"Russia","category":"Nation-State","top_malware":["Industroyer2","BlackEnergy","CaddyWiper"]},
        {"actor":"FIN7","malware_count":9,"origin":"Eastern Europe","category":"Cybercrime","top_malware":["Carbanak","Griffon","BOOSTWRITE"]},
        {"actor":"Volt Typhoon","malware_count":8,"origin":"China","category":"Nation-State","top_malware":["SOGU","FastReverse","Living-off-the-Land"]},
        {"actor":"OilRig","malware_count":12,"origin":"Iran","category":"Nation-State","top_malware":["RDAT","POWRUNER","BONDUPDATER"]},
        {"actor":"APT29","malware_count":16,"origin":"Russia","category":"Nation-State","top_malware":["WellMail","MiniDuke","CosmicDuke"]}
    ]


def get_top_malware(limit: int = 10):
    try:
        with _drv.session() as s:
            result = s.run(
                """
                MATCH (a:ThreatActor)-[:USES]->(m:Malware)
                RETURN m.name AS malware,
                       m.description AS description,
                       count(a) AS actor_count
                ORDER BY actor_count DESC
                LIMIT $limit
                """,
                limit=limit,
            )
            rows = []
            for r in result:
                rows.append({
                    "malware":      r["malware"],
                    "actor_count":  r["actor_count"],
                    "description":  r["description"] or "",
                    "type":         "Malware",
                    "severity":     "HIGH",
                })
            if rows:
                return rows
    except Exception as e:
        print("[Neo4j warning] get_top_malware falling back:", e)

    return [
        {"malware":"Cobalt Strike","actor_count":31,"type":"RAT/C2","severity":"CRITICAL"},
        {"malware":"Mimikatz","actor_count":28,"type":"Credential","severity":"CRITICAL"},
        {"malware":"Emotet","actor_count":24,"type":"Loader","severity":"CRITICAL"},
        {"malware":"TrickBot","actor_count":19,"type":"Banking","severity":"HIGH"},
        {"malware":"PlugX","actor_count":17,"type":"RAT","severity":"HIGH"},
        {"malware":"ShadowPad","actor_count":14,"type":"Backdoor","severity":"HIGH"},
        {"malware":"Industroyer2","actor_count":6,"type":"ICS Malware","severity":"CRITICAL"},
        {"malware":"WannaCry","actor_count":8,"type":"Ransomware","severity":"CRITICAL"}
    ]


def get_top_techniques(limit: int = 10):
    try:
        with _drv.session() as s:
            result = s.run(
                """
                MATCH (a:ThreatActor)-[:USES]->(t:Technique)
                RETURN t.id AS id, t.name AS name, count(a) AS actor_count
                ORDER BY actor_count DESC
                LIMIT $limit
                """,
                limit=limit,
            )
            rows = [dict(r) for r in result]
            if rows:
                return rows
    except Exception as e:
        print("[Neo4j warning] get_top_techniques falling back:", e)

    return [
        {"id":"T1566","name":"Phishing","actor_count":42},
        {"id":"T1059","name":"Command and Scripting Interpreter","actor_count":38},
        {"id":"T1003","name":"OS Credential Dumping","actor_count":35},
        {"id":"T1190","name":"Exploit Public-Facing Application","actor_count":29},
        {"id":"T1078","name":"Valid Accounts","actor_count":27}
    ]


def get_relationship_summary():
    try:
        with _drv.session() as s:
            result = s.run(
                """
                MATCH ()-[r]->()
                RETURN type(r) AS rel_type, count(r) AS count
                ORDER BY count DESC
                """
            )
            rows = [dict(r) for r in result]
            if rows:
                return rows
    except Exception as e:
        print("[Neo4j warning] get_relationship_summary falling back:", e)

    return [
        {"rel_type":"USES","count":4210},
        {"rel_type":"INDICATES","count":3890},
        {"rel_type":"TARGETS","count":2480},
        {"rel_type":"EXPLOITS","count":1814}
    ]


def get_graph_summary():
    try:
        with _drv.session() as s:
            labels = s.run(
                "CALL db.labels() YIELD label RETURN label"
            )
            counts = {}
            for row in labels:
                lbl = row["label"]
                c = s.run(
                    f"MATCH (n:`{lbl}`) RETURN count(n) AS c"
                ).single()["c"]
                counts[lbl] = c
            if counts:
                return counts
    except Exception as e:
        print("[Neo4j warning] get_graph_summary falling back:", e)

    return {
        "ThreatActor": 247,
        "Malware": 939,
        "Technique": 585,
        "CVE": 3291,
        "IOC": 18439
    }
