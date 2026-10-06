"""
Visualization queries – returns the full graph for rendering.
"""
import os
import pandas as pd
from graph.connection import get_driver

_drv = get_driver()


def get_complete_graph():
    nodes = {}
    edges = []

    try:
        with _drv.session() as s:
            # ThreatActor -> Malware
            res = s.run("""
                MATCH (a:ThreatActor)-[:USES]->(m:Malware)
                RETURN a.name AS actor, a.description AS actor_desc,
                       m.name AS malware, m.description AS mal_desc
                LIMIT 400
            """)
            for r in res:
                a, m = r["actor"], r["malware"]
                if a:
                    nodes[a] = {"id": a, "label": "ThreatActor", "description": (r["actor_desc"] or f"Threat Actor: {a}")[:120]}
                if m:
                    nodes[m] = {"id": m, "label": "Malware", "description": (r["mal_desc"] or f"Malware: {m}")[:120]}
                if a and m:
                    edges.append({"source": a, "target": m, "label": "USES"})

            # ThreatActor -> Technique
            res2 = s.run("""
                MATCH (a:ThreatActor)-[:USES]->(t:Technique)
                RETURN a.name AS actor, coalesce(t.name, t.id) AS tech_name,
                       t.id AS tech_id, t.description AS tech_desc
                LIMIT 300
            """)
            for r in res2:
                a = r["actor"]
                tname = r["tech_name"] or r["tech_id"]
                tid = r["tech_id"] or tname
                if a and a not in nodes:
                    nodes[a] = {"id": a, "label": "ThreatActor", "description": f"Threat Actor: {a}"}
                if tname:
                    nodes[tname] = {"id": tname, "label": "Technique", "description": f"Technique {tid}: {(r['tech_desc'] or '')[:100]}"}
                    if a:
                        edges.append({"source": a, "target": tname, "label": "USES"})
    except Exception as e:
        print("[Neo4j warning] get_complete_graph query error:", e)

    # Enrich from datasets if graph is small
    if len(nodes) < 60 or len(edges) < 60:
        csv_path = "backup/datasets/mitre_relationships.csv"
        if not os.path.exists(csv_path):
            csv_path = "datasets/mitre_relationships.csv"
        if os.path.exists(csv_path):
            try:
                df = pd.read_csv(csv_path)
                for _, r in df[df["target_type"] == "Malware"].head(160).iterrows():
                    s, t = str(r["source"]), str(r["target"])
                    if s not in nodes:
                        nodes[s] = {"id": s, "label": "ThreatActor", "description": f"Adversary: {s}"}
                    if t not in nodes:
                        nodes[t] = {"id": t, "label": "Malware", "description": f"Malware: {t}"}
                    edges.append({"source": s, "target": t, "label": "USES"})

                for _, r in df[df["target_type"] == "Technique"].head(160).iterrows():
                    s, t = str(r["source"]), str(r["target"])
                    tid = str(r.get("tech_id", ""))
                    if s not in nodes:
                        nodes[s] = {"id": s, "label": "ThreatActor", "description": f"Adversary: {s}"}
                    if t not in nodes:
                        nodes[t] = {"id": t, "label": "Technique", "description": f"MITRE Technique {tid}: {t}"}
                    edges.append({"source": s, "target": t, "label": "USES"})
            except Exception as ex:
                print("Enrichment error in get_complete_graph:", ex)

        # IOCs
        iocs_path = "backup/datasets/iocs.csv"
        if not os.path.exists(iocs_path):
            iocs_path = "datasets/iocs.csv"
        if os.path.exists(iocs_path):
            try:
                idf = pd.read_csv(iocs_path).dropna(subset=["ioc", "malware"])
                for _, r in idf.head(50).iterrows():
                    ioc, mal = str(r["ioc"]), str(r["malware"])
                    itype = str(r.get("ioc_type", "domain"))
                    if ioc not in nodes:
                        nodes[ioc] = {"id": ioc, "label": "IOC", "description": f"{itype.upper()}: {ioc}"}
                    if mal not in nodes:
                        nodes[mal] = {"id": mal, "label": "Malware", "description": f"Malware: {mal}"}
                    edges.append({"source": ioc, "target": mal, "label": "INDICATES"})
            except Exception:
                pass

        # CVEs
        CVE_LINKS = [
            ("WannaCry", "CVE-2017-0144"), ("WannaCry", "CVE-2017-0145"),
            ("NotPetya", "CVE-2017-0144"), ("Industroyer2", "CVE-2022-30190"),
            ("Cobalt Strike", "CVE-2021-44228"), ("Cobalt Strike", "CVE-2021-40444"),
            ("BlackCat", "CVE-2021-31207"), ("BlackByte", "CVE-2022-26134"),
            ("TrickBot", "CVE-2020-0796"), ("Emotet", "CVE-2017-11882"),
            ("LockBit", "CVE-2023-4966"), ("BlackEnergy", "CVE-2014-4114"),
            ("Lazarus Group", "CVE-2021-44228"), ("PlugX", "CVE-2023-23397"),
            ("Volt Typhoon", "CVE-2024-3400"), ("APT29", "CVE-2024-21413"),
            ("APT41", "CVE-2024-3821"), ("Carbanak", "CVE-2019-0708"),
            ("Sandworm", "CVE-2022-30190"), ("FIN7", "CVE-2017-0199")
        ]
        for src, cve in CVE_LINKS:
            if cve not in nodes:
                nodes[cve] = {"id": cve, "label": "CVE", "description": f"Exploited Vulnerability: {cve}"}
            if src not in nodes:
                nodes[src] = {"id": src, "label": "ThreatActor", "description": f"Entity: {src}"}
            edges.append({"source": src, "target": cve, "label": "EXPLOITS"})

    # Deduplicate edges
    seen_edges = set()
    dedup_edges = []
    for e in edges:
        key = (e["source"], e["target"], e.get("label", ""))
        if key not in seen_edges and e["source"] in nodes and e["target"] in nodes:
            seen_edges.add(key)
            dedup_edges.append(e)

    return {"nodes": list(nodes.values()), "edges": dedup_edges}
