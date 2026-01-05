from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def run_anomaly_detection(df):
    scaler = StandardScaler()
    scaled = scaler.fit_transform(df)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )

    df["anomaly"] = model.fit_predict(scaled)
    df["score"] = model.decision_function(scaled)

    return df
