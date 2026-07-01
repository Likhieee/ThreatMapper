from typing import TypedDict
from langgraph.graph import StateGraph, END

from ai.graph_reasoner import ask_graph


# -------------------------------
# State Definition
# -------------------------------

class GraphState(TypedDict):
    question: str
    answer: str


# -------------------------------
# AI Node
# -------------------------------

def graph_node(state: GraphState):

    question = state["question"]

    answer = ask_graph(question)

    return {
        "question": question,
        "answer": answer
    }


# -------------------------------
# Build LangGraph
# -------------------------------

workflow = StateGraph(GraphState)

workflow.add_node("GraphReasoner", graph_node)

workflow.set_entry_point("GraphReasoner")

workflow.add_edge("GraphReasoner", END)

app = workflow.compile()


# -------------------------------
# Test
# -------------------------------

if __name__ == "__main__":

    question = input("Ask Question: ")

    result = app.invoke({

        "question": question

    })

    print("\n========== FINAL ANSWER ==========\n")

    print(result["answer"])