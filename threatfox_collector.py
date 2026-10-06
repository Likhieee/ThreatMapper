import requests
import pandas as pd

url = "https://threatfox.abuse.ch/export/json/recent/"

response = requests.get(url)

data = response.json()

results = []

for key, value in data.items():

    if isinstance(value, list):

        for item in value:

            results.append([
                item.get("ioc_value", ""),
                item.get("ioc_type", ""),
                item.get("malware_printable", ""),
                item.get("first_seen_utc", "")
            ])

df = pd.DataFrame(
    results,
    columns=[
        "ioc",
        "ioc_type",
        "malware",
        "first_seen"
    ]
)

df.to_csv(
    "datasets/iocs.csv",
    index=False
)

print(df.head())
print("IOCs:", len(df))