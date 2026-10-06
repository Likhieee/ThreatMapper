import os
import json
import pandas as pd

results = []

for root, dirs, files in os.walk("cti-master"):

    if "attack-pattern" not in root:
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

                    if obj.get("type") == "attack-pattern":

                        technique_id = ""

                        if "external_references" in obj:

                            for ref in obj["external_references"]:

                                if ref.get("source_name") == "mitre-attack":

                                    technique_id = ref.get(
                                        "external_id",
                                        ""
                                    )

                        results.append([
                            technique_id,
                            obj.get("name", ""),
                            obj.get(
                                "description",
                                ""
                            )[:300]
                        ])

            except Exception:
                pass

df = pd.DataFrame(
    results,
    columns=[
        "technique_id",
        "technique_name",
        "description"
    ]
)

df.to_csv(
    "datasets/mitre_techniques.csv",
    index=False
)

print(df.head())
print("Techniques:", len(df))