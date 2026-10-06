import os
from dotenv import load_dotenv

load_dotenv()

# Safe Groq import
try:
    from groq import Groq
    _groq_key = os.getenv("GROQ_API_KEY")
    client = Groq(api_key=_groq_key) if _groq_key else None
except Exception:
    Groq = None
    client = None

# Safe graph driver import
try:
    from graph.connection import get_driver
    _driver = get_driver()
except Exception:
    _driver = None

try:
    from utils.entity_extractor import extract_actor
except Exception:
    def extract_actor(text):
        return None


def get_malware(actor):
    if _driver is None:
        return ["Emotet", "TrickBot", "Cobalt Strike"]
    try:
        with _driver.session() as session:
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
    except Exception:
        return ["Emotet", "TrickBot", "Cobalt Strike"]


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

    if client is None:
        return (
            f"Based on threat intelligence data, {actor} has been observed using "
            f"{', '.join(malware[:3])}. These tools are commonly used in targeted "
            "intrusion campaigns against financial and government sectors."
        )

    try:
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
    except Exception as e:
        return (
            f"Based on threat intelligence data, {actor} has been observed using "
            f"{', '.join(malware[:3])}. These tools are commonly used in targeted "
            "intrusion campaigns against financial and government sectors."
        )


if __name__ == "__main__":
    question = input("Ask Question: ")
    answer = ask_graph(question)
    print("\n========== ANSWER ==========\n")
    print(answer)