from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import random

app = FastAPI(title="ThreatMapper API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────
# REAL DATA — Member 1 will replace this
# ─────────────────────────────────────────

ACTORS = [
    {"id":1,"name":"APT28","origin":"Russia","type":"Espionage","severity":"CRITICAL","tools":["X-Agent","Mimikatz","Sofacy"],"targets":["Government","Military","Energy"],"attacks":34,"first_seen":"2014-01-01","last_seen":"2024-12-01"},
    {"id":2,"name":"Lazarus Group","origin":"North Korea","type":"Financial","severity":"CRITICAL","tools":["Emotet","WannaCry","BLINDINGCAN"],"targets":["Banking","Crypto","Defence"],"attacks":28,"first_seen":"2009-01-01","last_seen":"2024-11-15"},
    {"id":3,"name":"APT41","origin":"China","type":"Espionage","severity":"HIGH","tools":["Mimikatz","Cobalt Strike","POISONPLUG"],"targets":["Healthcare","Technology","Telecom"],"attacks":41,"first_seen":"2012-01-01","last_seen":"2024-12-10"},
    {"id":4,"name":"Carbanak","origin":"Unknown","type":"Banking","severity":"HIGH","tools":["Carbanak RAT","Cobalt Strike"],"targets":["Banking","Finance"],"attacks":19,"first_seen":"2013-01-01","last_seen":"2024-10-20"},
    {"id":5,"name":"FIN7","origin":"Eastern Europe","type":"Retail","severity":"MEDIUM","tools":["Babadeda","Griffon","BOOSTWRITE"],"targets":["Retail","Restaurant","Hospitality"],"attacks":22,"first_seen":"2015-01-01","last_seen":"2024-11-01"},
    {"id":6,"name":"Sandworm","origin":"Russia","type":"Infrastructure","severity":"CRITICAL","tools":["BlackEnergy","Industroyer","NotPetya"],"targets":["Energy","Government","Industrial"],"attacks":15,"first_seen":"2009-01-01","last_seen":"2024-12-05"},
    {"id":7,"name":"OilRig","origin":"Iran","type":"Government","severity":"HIGH","tools":["POWRUNER","BONDUPDATER","RDAT"],"targets":["Government","Telecom","Finance"],"attacks":17,"first_seen":"2014-01-01","last_seen":"2024-11-20"},
]

PREDICTIONS = [
    {"sector":"Indian Banking","risk":78,"actor":"Lazarus Group","confidence":"HIGH","timeframe":"30 days"},
    {"sector":"EU Government","risk":71,"actor":"APT28","confidence":"HIGH","timeframe":"30 days"},
    {"sector":"US Healthcare","risk":54,"actor":"APT41","confidence":"MEDIUM","timeframe":"45 days"},
    {"sector":"APAC Energy","risk":48,"actor":"Sandworm","confidence":"MEDIUM","timeframe":"60 days"},
    {"sector":"ME Telecom","risk":31,"actor":"OilRig","confidence":"LOW","timeframe":"90 days"},
]

IOCS = [
    {"type":"IP","indicator":"185.220.101.x","actor":"APT28","severity":"HIGH","date":"2024-12-01"},
    {"type":"URL","indicator":"malware.evil/payload","actor":"FIN7","severity":"HIGH","date":"2024-11-28"},
    {"type":"HASH","indicator":"a3f4b2c1d9e8f7...","actor":"Lazarus","severity":"CRITICAL","date":"2024-12-05"},
    {"type":"CVE","indicator":"CVE-2024-3821","actor":"APT41","severity":"HIGH","date":"2024-11-15"},
    {"type":"IP","indicator":"91.108.4.x","actor":"Carbanak","severity":"MEDIUM","date":"2024-10-20"},
]

STATS = {
    "total_actors": 247,
    "total_relationships": 1893,
    "total_vulnerabilities": 456,
    "total_predictions": 89,
}

LOGS = [
    {"time":"03:14:22","type":"alert","message":"APT28 IOC match — IP 185.220.101.x flagged"},
    {"time":"03:14:18","type":"info","message":"New CVE-2024-3821 ingested from CISA KEV"},
    {"time":"03:14:11","type":"warn","message":"Carbanak tool signature detected in feed"},
    {"time":"03:14:05","type":"info","message":"Graph updated — 3 new relationships mapped"},
    {"time":"03:13:58","type":"alert","message":"Lazarus Group — new TTP pattern observed"},
    {"time":"03:13:44","type":"info","message":"AlienVault OTX sync complete — 847 IOCs"},
    {"time":"03:13:31","type":"warn","message":"FIN7 targeting retail sector — risk elevated"},
    {"time":"03:13:20","type":"info","message":"Prediction model retrained — accuracy 87.3%"},
]

# ─────────────────────────────────────────
# ARTIFICIAL DARK WEB DATA
# Generated synthetically — realistic patterns
# ─────────────────────────────────────────

def generate_darkweb_data():
    actors = ["DarkPhantom","ShadowNet","VoidCrew","BlackMirror","NightOwl","DeepStrike","CryptoGhost","DarkWarden","NetReaper","PhantomCell","ZeroDay_X","RedMatrix"]
    forums = ["BreachForums","RaidForums_Mirror","XSS_Forum","Exploit_Forum","DarkMarket","HiddenHub","BlackHatForums","UndergroundMKT"]
    tools = ["RansomKit-X","DataStealer-Pro","BotNet-Z","CryptoLocker-V2","PhishKit-Elite","ZeroDay-Pack","CredHarvester","DDoS-Storm","KeyLogger-Pro","SQLi-Bot"]
    sectors = ["Banking","Government","Healthcare","Energy","Defence","Telecom","Education","Retail"]
    countries = ["Russia","China","North Korea","Iran","Unknown","Eastern Europe","Southeast Asia"]
    data_types = ["Credentials","Financial Records","Personal Data","Government Documents","Healthcare Records","Military Intel","Corporate Secrets","Credit Cards"]
    
    data = []
    base_date = datetime(2024, 1, 1)
    
    for i in range(200):
        days_offset = random.randint(0, 364)
        post_date = base_date + timedelta(days=days_offset)
        
        entry = {
            "id": i + 1,
            "actor_alias": random.choice(actors),
            "origin": random.choice(countries),
            "forum_source": random.choice(forums),
            "tool_advertised": random.choice(tools),
            "target_sector": random.choice(sectors),
            "post_date": post_date.strftime("%Y-%m-%d"),
            "price_btc": round(random.uniform(0.1, 5.0), 3),
            "severity": random.choice(["Low","Medium","High","Critical"]),
            "data_type_leaked": random.choice(data_types),
            "records_count": random.randint(1000, 10000000),
            "verified": random.choice([True, False]),
            "active": random.choice([True, False]),
        }
        data.append(entry)
    
    return data

DARKWEB_DATA = generate_darkweb_data()

def generate_darkweb_stats():
    return {
        "total_actors": len(set(d["actor_alias"] for d in DARKWEB_DATA)),
        "total_posts": len(DARKWEB_DATA),
        "critical_threats": len([d for d in DARKWEB_DATA if d["severity"] == "Critical"]),
        "active_threats": len([d for d in DARKWEB_DATA if d["active"] == True]),
        "top_targeted_sector": "Banking",
        "top_forum": "BreachForums",
        "total_records_leaked": sum(d["records_count"] for d in DARKWEB_DATA),
    }

# ─────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────

@app.get("/")
def home():
    return {"status":"ThreatMapper API running","version":"1.0"}

@app.get("/stats")
def get_stats():
    return STATS

@app.get("/actors")
def get_actors():
    return {"actors": ACTORS}

@app.get("/actors/{actor_id}")
def get_actor(actor_id: int):
    for a in ACTORS:
        if a["id"] == actor_id:
            return a
    return {"error": "Actor not found"}

@app.get("/predictions")
def get_predictions():
    return {"predictions": PREDICTIONS}

@app.get("/iocs")
def get_iocs():
    return {"iocs": IOCS}

@app.get("/logs")
def get_logs():
    return {"logs": LOGS}

# ─────────────────────────────────────────
# DARK WEB ENDPOINTS
# ─────────────────────────────────────────

@app.get("/darkweb")
def get_darkweb():
    return {"data": DARKWEB_DATA}

@app.get("/darkweb/stats")
def get_darkweb_stats():
    return generate_darkweb_stats()

@app.get("/darkweb/critical")
def get_critical_darkweb():
    critical = [d for d in DARKWEB_DATA if d["severity"] == "Critical"]
    return {"data": critical, "count": len(critical)}

@app.get("/darkweb/sector/{sector}")
def get_darkweb_by_sector(sector: str):
    filtered = [d for d in DARKWEB_DATA if d["target_sector"].lower() == sector.lower()]
    return {"data": filtered, "count": len(filtered)}

@app.get("/darkweb/actor/{actor}")
def get_darkweb_by_actor(actor: str):
    filtered = [d for d in DARKWEB_DATA if actor.lower() in d["actor_alias"].lower()]
    return {"data": filtered, "count": len(filtered)}

# ─────────────────────────────────────────
# GRAPH ENDPOINTS — Member 2 will replace
# ─────────────────────────────────────────

@app.get("/graph/nodes")
def get_graph_nodes():
    return {
        "nodes": [
            {"id":"APT28","type":"actor","color":"#ff2020"},
            {"id":"Lazarus","type":"actor","color":"#ff2020"},
            {"id":"APT41","type":"actor","color":"#ff6600"},
            {"id":"Carbanak","type":"actor","color":"#ff6600"},
            {"id":"FIN7","type":"actor","color":"#ffaa00"},
            {"id":"Sandworm","type":"actor","color":"#ff2020"},
            {"id":"OilRig","type":"actor","color":"#ff6600"},
            {"id":"X-Agent","type":"tool","color":"#00e5ff"},
            {"id":"Mimikatz","type":"tool","color":"#00e5ff"},
            {"id":"Emotet","type":"tool","color":"#00e5ff"},
            {"id":"Banking","type":"target","color":"#00ff88"},
            {"id":"Government","type":"target","color":"#00ff88"},
            {"id":"Healthcare","type":"target","color":"#00ff88"},
            {"id":"Energy","type":"target","color":"#ffe600"},
        ],
        "note":"Member 2 will replace with real Neo4j data"
    }

@app.get("/graph/edges")
def get_graph_edges():
    return {
        "edges": [
            {"source":"APT28","target":"X-Agent","type":"USES"},
            {"source":"APT28","target":"Government","type":"TARGETS"},
            {"source":"APT28","target":"Energy","type":"TARGETS"},
            {"source":"Lazarus","target":"Emotet","type":"USES"},
            {"source":"Lazarus","target":"Banking","type":"TARGETS"},
            {"source":"APT41","target":"Mimikatz","type":"USES"},
            {"source":"APT41","target":"Healthcare","type":"TARGETS"},
            {"source":"Carbanak","target":"Banking","type":"TARGETS"},
            {"source":"FIN7","target":"Banking","type":"TARGETS"},
            {"source":"Sandworm","target":"Energy","type":"TARGETS"},
            {"source":"OilRig","target":"Government","type":"TARGETS"},
        ],
        "note":"Member 2 will replace with real Neo4j data"
    }

# ─────────────────────────────────────────
# DATA FEED ENDPOINTS — Member 1 will replace
# ─────────────────────────────────────────

@app.get("/feed/otx")
def get_otx_feed():
    return {"status":"Member 1 will connect real AlienVault OTX data here"}

@app.get("/feed/cisa")
def get_cisa_feed():
    return {"status":"Member 1 will connect real CISA KEV data here"}

@app.get("/feed/threatfox")
def get_threatfox_feed():
    return {"status":"Member 1 will connect real ThreatFox data here"}