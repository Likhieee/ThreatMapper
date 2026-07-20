from fastapi import FastAPI

from ai.graph_reasoner import ask_graph
from ai.hidden_links import find_hidden_links
from ai.scoring import calculate_scores

from graph.connection import get_driver

from queries.visualization_queries import get_complete_graph

from queries.search_queries import (
    get_actor_by_name,
    get_malware_by_name,
    get_technique_by_id,
    get_cve_by_id,
    get_ioc_by_value,
    get_pulse_by_name,
)

from queries.analytics_queries import (
    get_dashboard,
    get_top_threat_actors,
    get_top_malware,
    get_top_techniques,
    get_relationship_summary,
    get_graph_summary,
)

app = FastAPI(
    title="ThreatWeave API",
    version="1.0"
)

driver = get_driver()


# -------------------------------------------------------
# HOME
# -------------------------------------------------------

@app.get("/")
def home():
    return {"message": "ThreatWeave API Running"}


# -------------------------------------------------------
# ACTORS
# -------------------------------------------------------

@app.get("/actors")
def get_actors():

    with driver.session() as session:

        result = session.run("""

            MATCH (a:ThreatActor)
            RETURN a.name AS actor
            ORDER BY actor
            LIMIT 100

        """)

        return [r["actor"] for r in result]


# -------------------------------------------------------
# MALWARE
# -------------------------------------------------------

@app.get("/malware")
def get_malware():

    with driver.session() as session:

        result = session.run("""

            MATCH (m:Malware)
            RETURN m.name AS malware
            ORDER BY malware
            LIMIT 100

        """)

        return [r["malware"] for r in result]


# -------------------------------------------------------
# GRAPH
# -------------------------------------------------------

@app.get("/graph")
def graph():

    with driver.session() as session:

        result = session.run("""

            MATCH (a:ThreatActor)-[:USES]->(m:Malware)

            RETURN
                a.name AS actor,
                m.name AS malware

            LIMIT 50

        """)

        return [

            {

                "actor": r["actor"],
                "malware": r["malware"]

            }

            for r in result

        ]


# -------------------------------------------------------
# IOCS
# -------------------------------------------------------

@app.get("/iocs")
def get_iocs():

    with driver.session() as session:

        result = session.run("""

            MATCH (i:IOC)
            OPTIONAL MATCH (i)-[:INDICATES]->(m:Malware)<-[:USES]-(a:ThreatActor)

            RETURN
                i.value AS value,
                i.type  AS type,
                collect(DISTINCT a.name)[0] AS actor,
                collect(DISTINCT m.name)[0] AS malware

            LIMIT 100

        """)

        import re as _re
        rows = []
        for r in result:
            val = r["value"] or ""
            ioc_type = r["type"] or (
                "CVE"    if val.upper().startswith("CVE-") else
                "IP"     if _re.match(r"^\d{1,3}(\.\d{1,3}){3}", val) else
                "HASH"   if len(val) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in val) else
                "DOMAIN"
            )
            rows.append({
                "value":    val,
                "type":     ioc_type,
                "actor":    r["actor"]   or "Unknown",
                "malware":  r["malware"] or "—",
                "severity": "HIGH",
            })
        return rows


# -------------------------------------------------------
# PULSES
# -------------------------------------------------------

@app.get("/pulses")
def get_pulses():

    with driver.session() as session:

        result = session.run("""

            MATCH (p:Pulse)

            RETURN p.name AS pulse

        """)

        return [r["pulse"] for r in result]


# -------------------------------------------------------
# STATISTICS
# -------------------------------------------------------

@app.get("/statistics")
def statistics():

    with driver.session() as session:

        actors = session.run(
            "MATCH (n:ThreatActor) RETURN count(n) AS c"
        ).single()["c"]

        malware = session.run(
            "MATCH (n:Malware) RETURN count(n) AS c"
        ).single()["c"]

        techniques = session.run(
            "MATCH (n:Technique) RETURN count(n) AS c"
        ).single()["c"]

        cves = session.run(
            "MATCH (n:CVE) RETURN count(n) AS c"
        ).single()["c"]

        iocs = session.run(
            "MATCH (n:IOC) RETURN count(n) AS c"
        ).single()["c"]

        pulses = session.run(
            "MATCH (n:Pulse) RETURN count(n) AS c"
        ).single()["c"]

        return {

            "ThreatActors": actors,
            "Malware": malware,
            "Techniques": techniques,
            "CVEs": cves,
            "IOCs": iocs,
            "Pulses": pulses

        }


# -------------------------------------------------------
# AI QUESTION ANSWERING
# -------------------------------------------------------

@app.get("/ask")
def ask(question: str):

    answer = ask_graph(question)

    return {

        "question": question,
        "answer": answer

    }


# -------------------------------------------------------
# HIDDEN LINKS
# -------------------------------------------------------

@app.get("/hidden-links")
def hidden_links():

    links = find_hidden_links()

    data = []

    for link in links:

        data.append({

            "actor1": link["actor1"],
            "actor2": link["actor2"],
            "shared_malware": link["shared_malware"]

        })

    return data


# -------------------------------------------------------
# RELATIONSHIP SCORES
# -------------------------------------------------------

@app.get("/scores")
def scores():

    rows = calculate_scores()

    data = []

    for row in rows:

        similarity = row["score"] * 25

        if similarity > 100:
            similarity = 100

        data.append({

            "actor1": row["actor1"],
            "actor2": row["actor2"],
            "similarity": similarity,
            "shared_malware": row["malware"]

        })

    return data


# -------------------------------------------------------
# ACTOR DETAILS
# -------------------------------------------------------

@app.get("/actor/{name}")
def actor_details(name: str):

    return get_actor_by_name(name)


# -------------------------------------------------------
# MALWARE DETAILS
# -------------------------------------------------------

@app.get("/malware/{name}")
def malware_details(name: str):

    return get_malware_by_name(name)


# -------------------------------------------------------
# TECHNIQUE DETAILS
# -------------------------------------------------------

@app.get("/technique/{technique_id}")
def technique_details(technique_id: str):

    return get_technique_by_id(technique_id)


# -------------------------------------------------------
# CVE DETAILS
# -------------------------------------------------------

@app.get("/cve/{cve_id}")
def cve_details(cve_id: str):

    return get_cve_by_id(cve_id)


# -------------------------------------------------------
# IOC DETAILS
# -------------------------------------------------------

@app.get("/ioc/{value}")
def ioc_details(value: str):

    return get_ioc_by_value(value)


# -------------------------------------------------------
# PULSE DETAILS
# -------------------------------------------------------

@app.get("/pulse/{name}")
def pulse_details(name: str):

    return get_pulse_by_name(name)


# -------------------------------------------------------
# GRAPH VISUALIZATION
# -------------------------------------------------------



@app.get("/graph-data")
def graph_data():

    with driver.session() as session:

        result = session.run("""

            MATCH (a:ThreatActor)-[r:USES]->(m:Malware)

            RETURN
                a.name AS actor,
                m.name AS malware

        """)

        nodes = {}
        edges = []

        for record in result:

            actor = record["actor"]
            malware = record["malware"]

            nodes[actor] = {
                "id": actor,
                "label": "ThreatActor"
            }

            nodes[malware] = {
                "id": malware,
                "label": "Malware"
            }

            edges.append({

                "source": actor,
                "target": malware,
                "label": "USES"

            })

        return {

            "nodes": list(nodes.values()),
            "edges": edges

        }
    
@app.get("/malware/{name}")
def malware_details(name: str):

    result = get_malware_by_name(name)

    if result is None:
        return {"error": "Malware not found"}

    return result

@app.get("/technique/{technique_id}")
def technique_details(technique_id: str):

    result = get_technique_by_id(technique_id)

    if result is None:
        return {"error": "Technique not found"}

    return result

@app.get("/cve/{cve_id}")
def cve_details(cve_id: str):

    result = get_cve_by_id(cve_id)

    if result is None:
        return {"error": "CVE not found"}

    return result

@app.get("/cve/{cve_id}")
def cve_details(cve_id: str):

    result = get_cve_by_id(cve_id)

    if result is None:
        return {"error": "CVE not found"}

    return result

@app.get("/pulse/{name}")
def pulse_details(name: str):

    result = get_pulse_by_name(name)

    if result is None:
        return {"error": "Pulse not found"}

    return result

@app.get("/visualization")
def visualization():

    return get_complete_graph()

@app.get("/dashboard")
def dashboard():
    return get_dashboard()


@app.get("/top-threat-actors")
def top_threat_actors():
    return get_top_threat_actors()


@app.get("/top-malware")
def top_malware():
    return get_top_malware()


@app.get("/top-techniques")
def top_techniques():
    return get_top_techniques()


@app.get("/relationship-summary")
def relationship_summary():
    return get_relationship_summary()


@app.get("/graph-summary")
def graph_summary():
    return get_graph_summary()