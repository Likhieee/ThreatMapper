import pandas as pd
from sklearn.ensemble import RandomForestClassifier

data = pd.DataFrame({
    "cve_count": [5,10,20,50,100,150],
    "ioc_count": [20,40,80,200,500,1000],
    "risk": [0,0,1,1,1,1]
})

X = data[["cve_count","ioc_count"]]
y = data["risk"]

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X,y)

prediction = model.predict([[75,300]])

print("Predicted Risk:", prediction[0])