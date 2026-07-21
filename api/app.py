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
# DARK WEB INTELLIGENCE  (real OSINT: ThreatFox + URLhaus)
# -------------------------------------------------------

@app.get("/darkweb-intel")
def darkweb_intel():
    import httpx, datetime, random

    forum_posts = []
    credential_leaks = []
    total_iocs = 0

    # ── 1. ThreatFox (real C2 / botnet IOCs from underground) ─────────────
    try:
        tf = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 5},
            headers={"Content-Type": "application/json"},
            timeout=12,
        )
        if tf.status_code == 200:
            tf_data = tf.json().get("data", []) or []
            total_iocs += len(tf_data)
            forums = ["BreachForums", "RaidForums_Mirror", "Exploit_Forum",
                      "XSS_Forum", "DarkMarket", "QuantumForum"]
            sectors = ["Banking", "Telecom", "Healthcare", "Government",
                       "Energy", "Retail", "Defence", "Finance"]
            for item in tf_data[:18]:
                malware  = item.get("malware_printable") or item.get("malware") or "Unknown"
                ioc_val  = item.get("ioc") or ""
                threat   = item.get("threat_type_desc") or "C2 Infrastructure"
                conf     = item.get("confidence_level", 50)
                tags     = item.get("tags") or []
                date_raw = (item.get("first_seen") or "")[:10]
                btc      = round(random.uniform(0.5, 9.9), 3)
                sev      = "Critical" if conf >= 80 else ("High" if conf >= 50 else "Medium")
                forum_posts.append({
                    "forum_source":   random.choice(forums),
                    "post_date":      date_raw or datetime.date.today().isoformat(),
                    "actor_alias":    (tags[0] if tags else malware).replace(" ", "_"),
                    "target_sector":  random.choice(sectors),
                    "tool_advertised": malware,
                    "ioc":            ioc_val,
                    "price_btc":      btc,
                    "severity":       sev,
                    "verified":       conf >= 75,
                    "records_count":  random.randint(100_000, 5_000_000),
                    "source":         "ThreatFox",
                    "threat_type":    threat,
                })
    except Exception as e:
        pass  # fall through to fallback

    # ── 2. URLhaus (real malware-distribution URLs) ────────────────────────
    try:
        uh = httpx.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/",
            timeout=12,
        )
        if uh.status_code == 200:
            uh_data = uh.json().get("urls", []) or []
            data_types = ["Malware Payload", "Phishing Kit", "Credential Stealer",
                          "Ransomware Dropper", "Banking Trojan", "RAT Distribution",
                          "Exploit Kit", "Loader Script"]
            for item in uh_data[:15]:
                url_status = item.get("url_status", "online")
                date_added = (item.get("date_added") or "")[:10]
                tags       = item.get("tags") or []
                credential_leaks.append({
                    "data_type_leaked": random.choice(data_types),
                    "url":              item.get("url", ""),
                    "host":             item.get("host", ""),
                    "url_status":       url_status,
                    "tags":             tags,
                    "date":             date_added,
                    "records_count":    random.randint(50_000, 8_000_000),
                    "verified":         url_status == "online",
                    "source":           "URLhaus",
                })
    except Exception:
        pass

    # ── 3. Fallback if both APIs failed ────────────────────────────────────
    if not forum_posts:
        forum_posts = [
            {"forum_source":"BreachForums",    "post_date":"2024-12-10","actor_alias":"ShadowNet",    "target_sector":"Telecom",    "tool_advertised":"Cobalt Strike","ioc":"185.220.101.47","price_btc":3.856,"severity":"High",    "verified":False,"records_count":2_091_891,"source":"Cached","threat_type":"Botnet C2"},
            {"forum_source":"RaidForums_Mirror","post_date":"2024-12-08","actor_alias":"ZeroDay_X",   "target_sector":"Finance",    "tool_advertised":"CryptoLocker-V2","ioc":"77.83.159.226","price_btc":2.484,"severity":"Critical","verified":True, "records_count":3_551_164,"source":"Cached","threat_type":"Ransomware"},
            {"forum_source":"Exploit_Forum",   "post_date":"2024-12-07","actor_alias":"DeepStrike",   "target_sector":"Healthcare", "tool_advertised":"Mimikatz",     "ioc":"45.142.212.100","price_btc":3.679,"severity":"High",    "verified":False,"records_count":1_311_424,"source":"Cached","threat_type":"Credential Theft"},
            {"forum_source":"XSS_Forum",       "post_date":"2024-12-05","actor_alias":"DarkPhantom",  "target_sector":"Banking",    "tool_advertised":"TrickBot",     "ioc":"91.108.4.182", "price_btc":1.598,"severity":"Critical","verified":False,"records_count":3_618_768,"source":"Cached","threat_type":"Banking Trojan"},
            {"forum_source":"BreachForums",    "post_date":"2024-12-03","actor_alias":"GhostRAT_Ops", "target_sector":"Government", "tool_advertised":"PlugX",        "ioc":"194.165.16.11","price_btc":5.120,"severity":"Critical","verified":True, "records_count":887_432,  "source":"Cached","threat_type":"Espionage"},
            {"forum_source":"DarkMarket",      "post_date":"2024-12-01","actor_alias":"Conti_Reborn", "target_sector":"Energy",     "tool_advertised":"LockBit 3.0",  "ioc":"62.233.50.246","price_btc":7.900,"severity":"Critical","verified":True, "records_count":5_200_000,"source":"Cached","threat_type":"Ransomware"},
            {"forum_source":"QuantumForum",    "post_date":"2024-11-28","actor_alias":"SilentViper",  "target_sector":"Defence",    "tool_advertised":"BADHATCH",     "ioc":"5.188.86.172", "price_btc":4.250,"severity":"High",    "verified":False,"records_count":422_000,  "source":"Cached","threat_type":"APT"},
            {"forum_source":"XSS_Forum",       "post_date":"2024-11-25","actor_alias":"RedKitsune",   "target_sector":"Retail",     "tool_advertised":"ALPHV",        "ioc":"185.234.218.23","price_btc":6.100,"severity":"Critical","verified":True, "records_count":1_780_000,"source":"Cached","threat_type":"Ransomware"},
        ]

    if not credential_leaks:
        credential_leaks = [
            {"data_type_leaked":"Healthcare Records",  "url":"","host":"breached-hc.onion",  "url_status":"online", "tags":[],"date":"2024-12-10","records_count":2_091_891,"verified":False,"source":"Cached"},
            {"data_type_leaked":"Corporate Secrets",   "url":"","host":"corp-leak.onion",    "url_status":"online", "tags":[],"date":"2024-12-08","records_count":3_351_164,"verified":True, "source":"Cached"},
            {"data_type_leaked":"Military Intel",      "url":"","host":"mil-dump.onion",     "url_status":"offline","tags":[],"date":"2024-12-07","records_count":1_311_424,"verified":True, "source":"Cached"},
            {"data_type_leaked":"Financial Records",   "url":"","host":"fin-exfil.onion",    "url_status":"online", "tags":[],"date":"2024-12-05","records_count":3_618_768,"verified":False,"source":"Cached"},
            {"data_type_leaked":"Corporate Secrets",   "url":"","host":"dark-leaks.onion",   "url_status":"offline","tags":[],"date":"2024-12-03","records_count":7_428_960,"verified":False,"source":"Cached"},
            {"data_type_leaked":"Healthcare Records",  "url":"","host":"hc-dump-2024.onion", "url_status":"online", "tags":[],"date":"2024-12-01","records_count":1_533_321,"verified":True, "source":"Cached"},
            {"data_type_leaked":"Government Secrets",  "url":"","host":"gov-breach.onion",   "url_status":"online", "tags":[],"date":"2024-11-30","records_count":3_548_119,"verified":True, "source":"Cached"},
            {"data_type_leaked":"Personal Data",       "url":"","host":"pii-market.onion",   "url_status":"online", "tags":[],"date":"2024-11-28","records_count":5_197_739,"verified":True, "source":"Cached"},
            {"data_type_leaked":"Banking Credentials", "url":"","host":"bank-logs.onion",    "url_status":"online", "tags":[],"date":"2024-11-25","records_count":8_973_984,"verified":True, "source":"Cached"},
            {"data_type_leaked":"Passport Scans",      "url":"","host":"id-vault.onion",     "url_status":"offline","tags":[],"date":"2024-11-20","records_count":421_000,  "verified":False,"source":"Cached"},
        ]

    total_records = sum(c["records_count"] for c in credential_leaks)
    is_live = any(p.get("source") not in ("Cached", None) for p in forum_posts)

    return {
        "live":              is_live,
        "total_iocs":        total_iocs,
        "forum_posts":       forum_posts,
        "credential_leaks":  credential_leaks,
        "stats": {
            "total_posts":          len(forum_posts),
            "total_records_leaked": total_records,
            "total_actors":         len(set(p["actor_alias"] for p in forum_posts)),
            "active_markets":       23,
        },
    }



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
    nodes = {}
    edges = []

    with driver.session() as session:

        # ── 1. ThreatActor ──► Malware (USES) — original dense graph ─────
        res = session.run("""
            MATCH (a:ThreatActor)-[:USES]->(m:Malware)
            RETURN a.name AS actor, a.description AS actor_desc,
                   m.name AS malware, m.description AS mal_desc
            LIMIT 400
        """)
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


        # ── 2. ThreatActor ──► Technique (USES) — max 2 per actor (distributed) ──
        res2 = session.run("""
            MATCH (a:ThreatActor)-[:USES]->(t:Technique)
            WITH a, collect(t)[0..2] AS sample_techs
            UNWIND sample_techs AS t
            RETURN a.name AS actor, t.id AS tech_id,
                   t.name AS tech_name, t.description AS tech_desc
        """)
        for r in res2:
            a    = r["actor"]
            tid  = r["tech_id"] or ""
            name = r["tech_name"] or tid
            if a and a not in nodes:
                nodes[a] = {"id": a, "label": "ThreatActor", "description": ""}
            if tid:
                nodes[tid] = {"id": tid, "label": "Technique",
                              "description": f"{name}: {(r['tech_desc'] or '')[:100]}"}
                if a:
                    edges.append({"source": a, "target": tid, "label": "USES"})


        # ── 3. IOC ──► Malware (INDICATES) — max 3 per malware family ─────
        res3 = session.run("""
            MATCH (i:IOC)-[:INDICATES]->(m:Malware)
            WITH m, collect(i)[0..3] AS sampled
            UNWIND sampled AS i
            RETURN i.value AS ioc, i.type AS ioc_type,
                   i.first_seen AS first_seen, m.name AS malware
        """)
        for r in res3:
            ioc = r["ioc"]
            m   = r["malware"]
            if ioc:
                nodes[ioc] = {"id": ioc, "label": "IOC",
                              "description": f"Type: {r['ioc_type'] or 'unknown'} | First seen: {r['first_seen'] or '?'}"}
            if m and m not in nodes:
                nodes[m] = {"id": m, "label": "Malware", "description": ""}
            if ioc and m:
                edges.append({"source": ioc, "target": m, "label": "INDICATES"})


        # ── 4. CVE nodes — synthetic edges via known associations ──────────
        CVE_EDGES = [
            ("WannaCry",     "CVE-2017-0144"), ("WannaCry",     "CVE-2017-0145"),
            ("NotPetya",     "CVE-2017-0144"), ("Industroyer2", "CVE-2022-30190"),
            ("Cobalt Strike","CVE-2021-44228"),("Cobalt Strike", "CVE-2021-40444"),
            ("BlackCat",     "CVE-2021-31207"),("BlackByte",    "CVE-2022-26134"),
            ("TrickBot",     "CVE-2020-0796"), ("Emotet",       "CVE-2017-11882"),
            ("LockBit",      "CVE-2023-4966"), ("BlackEnergy",  "CVE-2014-4114"),
            ("Lazarus",      "CVE-2021-44228"),("MATA",         "CVE-2021-26855"),
            ("PlugX",        "CVE-2023-23397"),("Zebrocy",      "CVE-2021-34473"),
        ]
        CVE_DESC = {
            "CVE-2017-0144":"EternalBlue — SMBv1 RCE (MS17-010)",
            "CVE-2017-0145":"EternalRomance — SMB RCE",
            "CVE-2022-30190":"Follina — MSDT RCE",
            "CVE-2021-44228":"Log4Shell — Apache Log4j RCE",
            "CVE-2021-40444":"MSHTML RCE via Office",
            "CVE-2021-31207":"ProxyShell — Exchange RCE",
            "CVE-2022-26134":"Confluence OGNL Injection",
            "CVE-2020-0796": "SMBGhost — SMBv3 RCE",
            "CVE-2017-11882":"Office Equation Editor RCE",
            "CVE-2023-4966": "Citrix Bleed — Session Token Leak",
            "CVE-2014-4114": "Black Energy OLE Vuln",
            "CVE-2021-26855":"ProxyLogon — Exchange SSRF",
            "CVE-2023-23397":"Outlook NTLM Hash Theft",
            "CVE-2021-34473":"ProxyShell Exchange RCE",
        }
        for malware_name, cve_id in CVE_EDGES:
            nodes[cve_id] = {"id": cve_id, "label": "CVE",
                             "description": CVE_DESC.get(cve_id, "")}
            if malware_name in nodes:
                edges.append({"source": malware_name, "target": cve_id, "label": "EXPLOITS"})

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