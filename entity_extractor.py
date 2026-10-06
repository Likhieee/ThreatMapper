import os
import pandas as pd

ACTORS = [
    "APT29",
    "APT34",
    "FIN6",
    "FIN7",
    "Sandworm",
    "Wizard Spider",
    "OilRig",
    "Carbanak"
]

MALWARE = [
    "TrickBot",
    "Ryuk",
    "Emotet",
    "CosmicDuke",
    "SeaDuke",
    "MiniDuke",
    "POSHSPY",
    "NotPetya",
    "CrashOverride"
]

results = []

for file in os.listdir("extracted_text"):

    if file.endswith(".txt"):

        with open(
            os.path.join("extracted_text", file),
            "r",
            encoding="utf-8"
        ) as f:

            text = f.read()

        found_actors = []
        found_malware = []

        for actor in ACTORS:
            if actor.lower() in text.lower():
                found_actors.append(actor)

        for malware in MALWARE:
            if malware.lower() in text.lower():
                found_malware.append(malware)

        for actor in found_actors:
            for malware in found_malware:
                results.append([
                    file,
                    actor,
                    malware
                ])

df = pd.DataFrame(
    results,
    columns=[
        "report",
        "threat_actor",
        "malware"
    ]
)

os.makedirs("datasets", exist_ok=True)

df.to_csv(
    "datasets/entities.csv",
    index=False
)

print(df.head())
print("Total Records:", len(df))