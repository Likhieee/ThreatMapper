import os
import json
import pandas as pd

results = []

for root, dirs, files in os.walk("cti-master"):

    if "intrusion-set" not in root:
        continue

    for file in files:

        if file.endswith(".json"):

            path = os.path.join(root, file)

            try:

                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if "objects" not in data:
                    continue

                for obj in data["objects"]:

                    if obj.get("type") == "intrusion-set":

                        results.append([
                            obj.get("name", ""),
                            ", ".join(
                                obj.get("aliases", [])
                            ),
                            obj.get("description", "")[:300]
                        ])

            except Exception:
                pass

df = pd.DataFrame(
    results,
    columns=[
        "actor",
        "aliases",
        "description"
    ]
)

df.to_csv(
    "datasets/mitre_groups.csv",
    index=False
)

print(df.head())
print("Groups:", len(df))