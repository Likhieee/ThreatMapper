import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

_driver = None


def get_driver():
    global _driver
    if _driver is None:
        uri      = os.getenv("NEO4J_URI",      "neo4j+s://0fe30a1e.databases.neo4j.io")
        username = os.getenv("NEO4J_USERNAME", "0fe30a1e")
        password = os.getenv("NEO4J_PASSWORD", "")
        database = os.getenv("NEO4J_DATABASE", "neo4j")
        _driver  = GraphDatabase.driver(uri, auth=(username, password))
    return _driver
