"""
Visualization queries – returns the full graph for D3.js rendering.
"""
from graph.connection import get_driver

_drv = get_driver()


def get_complete_graph():
    nodes = {}
    edges = []

    with _drv.session() as s:
        # Actors + their Malware
        res = s.run(
            """
            MATCH (a:ThreatActor)-[:USES]->(m:Malware)
            RETURN a.name AS actor, a.description AS actor_desc,
                   m.name AS malware, m.description AS mal_desc
            LIMIT 300
            """
        )
        for r in res:
            a, m = r["actor"], r["malware"]
            if a:
                nodes[a] = {"id": a, "label": "ThreatActor",
                            "description": (r["actor_desc"] or "")[:120]}
            if m:
                nodes[m] = {"id": m, "label": "Malware",
                            "description": (r["mal_desc"] or "")[:120]}
            if a and m:
                edges.append({"source": a, "target": m, "label": "USES"})

    return {"nodes": list(nodes.values()), "edges": edges}
