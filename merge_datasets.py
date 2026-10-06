import pandas as pd

datasets = {}

files = [
    "entities.csv",
    "mitre_groups.csv",
    "mitre_malware.csv",
    "mitre_techniques.csv",
    "cves.csv",
    "iocs.csv",
    "otx_pulses.csv"
]

for file in files:
    path = f"datasets/{file}"

    try:
        df = pd.read_csv(path)

        df["source"] = file

        datasets[file] = df

        print(f"Loaded {file}: {len(df)} rows")

    except Exception as e:
        print(e)

final_df = pd.concat(
    datasets.values(),
    ignore_index=True,
    sort=False
)

final_df.to_csv(
    "datasets/final_threat_dataset.csv",
    index=False
)

print()
print("Total Records:", len(final_df))
print("Saved: datasets/final_threat_dataset.csv")