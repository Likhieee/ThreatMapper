import os

from dotenv import load_dotenv
from groq import Groq

from graph.connection import get_driver
from utils.entity_extractor import extract_actor

load_dotenv()

client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)

driver = get_driver()


def get_malware(actor):

    with driver.session() as session:

        result = session.run(
            """
            MATCH (a:ThreatActor {name:$actor})
            -[:USES]->
            (m:Malware)

            RETURN m.name AS malware
            """,
            actor=actor
        )

        return [r["malware"] for r in result]


def ask_graph(question):

    actor = extract_actor(question)

    if actor is None:

        return "Threat Actor not found in the question."

    malware = get_malware(actor)

    if len(malware) == 0:

        return f"No malware found for {actor}."

    context = f"""
Threat Actor:
{actor}

Malware Used:
{', '.join(malware)}

Question:
{question}
"""

    response = client.chat.completions.create(

        model="llama-3.3-70b-versatile",

        messages=[

            {
                "role": "system",
                "content": "You are a Cyber Threat Intelligence Assistant. Answer ONLY using the provided graph context."
            },

            {
                "role": "user",
                "content": context
            }

        ],

        temperature=0.2

    )

    return response.choices[0].message.content


if __name__ == "__main__":

    question = input("Ask Question: ")

    answer = ask_graph(question)

    print("\n========== ANSWER ==========\n")

    print(answer)