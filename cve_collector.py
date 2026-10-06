import requests
import pandas as pd

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

response = requests.get(url)

data = response.json()

results = []

for vuln in data.get("vulnerabilities", []):

    cve = vuln.get("cve", {})

    cve_id = cve.get("id", "")

    published = cve.get("published", "")

    results.append([
        cve_id,
        published
    ])

df = pd.DataFrame(
    results,
    columns=[
        "cve_id",
        "published"
    ]
)

df.to_csv(
    "datasets/cves.csv",
    index=False
)

print(df.head())
print("CVEs:", len(df))