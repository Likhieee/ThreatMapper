from queries.graph_queries import get_graph

graph = get_graph()

print()

print("Nodes")

print(len(graph["nodes"]))

print()

print("Edges")

print(len(graph["edges"]))

print()

print(graph["nodes"][:5])

print()

print(graph["edges"][:5])