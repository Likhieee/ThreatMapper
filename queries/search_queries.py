"""
Search queries – look up individual entities by name/ID.
"""
from graph.connection import get_driver

_drv = get_driver()


def get_actor_by_name(name: str):
    with _drv.session() as s:
        r = s.run(
            """
            MATCH (a:ThreatActor {name:$name})
            OPTIONAL MATCH (a)-[:USES]->(m:Malware)
            RETURN a.name AS name,
                   a.description AS description,
                   a.aliases AS aliases,
                   collect(m.name) AS malware
            """,
            name=name,
        ).single()
        if r is None:
            return {"error": "Actor not found"}
        return dict(r)


def get_malware_by_name(name: str):
    with _drv.session() as s:
        r = s.run(
            """
            MATCH (m:Malware {name:$name})
            OPTIONAL MATCH (a:ThreatActor)-[:USES]->(m)
            RETURN m.name AS name,
                   m.description AS description,
                   collect(a.name) AS actors
            """,
            name=name,
        ).single()
        if r is None:
            return {"error": "Malware not found"}
        return dict(r)


def get_technique_by_id(technique_id: str):
    with _drv.session() as s:
        r = s.run(
            """
            MATCH (t:Technique {id:$id})
            RETURN t.id AS id, t.name AS name, t.description AS description
            """,
            id=technique_id,
        ).single()
        if r is None:
            return {"error": "Technique not found"}
        return dict(r)


def get_cve_by_id(cve_id: str):
    with _drv.session() as s:
        r = s.run(
            """
            MATCH (c:CVE {id:$id})
            RETURN c.id AS id, c.description AS description, c.cvss AS cvss
            """,
            id=cve_id,
        ).single()
        if r is None:
            return {"error": "CVE not found"}
        return dict(r)


def get_ioc_by_value(value: str):
    with _drv.session() as s:
        r = s.run(
            """
            MATCH (i:IOC {value:$value})
            OPTIONAL MATCH (i)-[:INDICATES]->(m:Malware)
            RETURN i.value AS value, i.type AS type,
                   i.first_seen AS first_seen, m.name AS malware
            """,
            value=value,
        ).single()
        if r is None:
            return {"error": "IOC not found"}
        return dict(r)


def get_pulse_by_name(name: str):
    with _drv.session() as s:
        r = s.run(
            "MATCH (p:Pulse {name:$name}) RETURN p.name AS name, p.description AS description",
            name=name,
        ).single()
        if r is None:
            return {"error": "Pulse not found"}
        return dict(r)
