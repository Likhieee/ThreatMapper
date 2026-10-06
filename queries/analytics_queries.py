"""
Analytics queries – aggregated stats and top-N lists used by the dashboard.
"""
from graph.connection import get_driver

_drv = get_driver()


def get_dashboard():
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


def get_top_threat_actors(limit: int = 10):
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
        return rows


def get_top_malware(limit: int = 10):
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
        return rows


def get_top_techniques(limit: int = 10):
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
        return [dict(r) for r in result]


def get_relationship_summary():
    with _drv.session() as s:
        result = s.run(
            """
            MATCH ()-[r]->()
            RETURN type(r) AS rel_type, count(r) AS count
            ORDER BY count DESC
            """
        )
        return [dict(r) for r in result]


def get_graph_summary():
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
        return counts
