from graph.connection import get_driver

driver = get_driver()

with driver.session() as session:
    result = session.run("RETURN 'Neo4j Connected!' AS msg")
    print(result.single()["msg"])

driver.close()