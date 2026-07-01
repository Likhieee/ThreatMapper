import pandas as pd
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("datasets/training_data.csv")

X = df[
    ["cve_count",
     "ioc_count",
     "otx_mentions"]
]

y = df["risk"]

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)

scores = []

for _, row in df.iterrows():

    risk_score = model.predict_proba([[
        row["cve_count"],
        row["ioc_count"],
        row["otx_mentions"]
    ]])[0][1]

    scores.append(risk_score)

df["risk_score"] = scores

df[
    ["actor", "risk_score"]
].to_csv(
    "datasets/predictions.csv",
    index=False
)

print(
    df[["actor", "risk_score"]]
    .head()
)