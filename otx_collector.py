import requests
import pandas as pd

OTX_API_KEY = "78ca6fd11967e396f93c5c828195ce8970473de271fb82fd08c6eae4925e9827"

headers = {
    "X-OTX-API-KEY": OTX_API_KEY
}

url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

response = requests.get(url, headers=headers)

data = response.json()

results = []

for pulse in data.get("results", []):

    results.append([
        pulse.get("name", ""),
        pulse.get("created", ""),
        pulse.get("modified", ""),
        pulse.get("adversary", "")
    ])

df = pd.DataFrame(
    results,
    columns=[
        "pulse_name",
        "created",
        "modified",
        "adversary"
    ]
)

df.to_csv(
    "datasets/otx_pulses.csv",
    index=False
)

print(df.head())
print("Pulses:", len(df))