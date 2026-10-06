"""
Visualization queries – returns the full graph for D3.js rendering.
"""
from graph.connection import get_driver

_drv = get_driver()


def get_complete_graph():
    nodes = {}
    edges = []

    try:
        with _drv.session() as s:
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

        if nodes and edges:
            return {"nodes": list(nodes.values()), "edges": edges}
    except Exception as e:
        print("[Neo4j warning] get_complete_graph fallback:", e)

    fb_nodes = [
        {"id":"APT28","label":"ThreatActor","description":"Fancy Bear"},
        {"id":"Lazarus Group","label":"ThreatActor","description":"Hidden Cobra"},
        {"id":"APT41","label":"ThreatActor","description":"Double Dragon"},
        {"id":"Sandworm","label":"ThreatActor","description":"Voodoo Bear"},
        {"id":"FIN7","label":"ThreatActor","description":"Carbanak"},
        {"id":"Cobalt Strike","label":"Malware","description":"C2 Framework"},
        {"id":"Mimikatz","label":"Malware","description":"Credential Dumper"},
        {"id":"WannaCry","label":"Malware","description":"Ransomware"},
        {"id":"Industroyer2","label":"Malware","description":"ICS Payload"},
        {"id":"ShadowPad","label":"Malware","description":"Modular Backdoor"}
    ]
    fb_edges = [
        {"source":"APT28","target":"Mimikatz","label":"USES"},
        {"source":"Lazarus Group","target":"WannaCry","label":"USES"},
        {"source":"APT41","target":"Cobalt Strike","label":"USES"},
        {"source":"APT41","target":"ShadowPad","label":"USES"},
        {"source":"Sandworm","target":"Industroyer2","label":"USES"},
        {"source":"FIN7","target":"Cobalt Strike","label":"USES"}
    ]
    return {"nodes": fb_nodes, "edges": fb_edges}
