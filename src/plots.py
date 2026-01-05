import matplotlib.pyplot as plt

def anomaly_scatter(df):
    normal = df[df["anomaly"] == 1]
    anomaly = df[df["anomaly"] == -1]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.scatter(normal.iloc[:, 0], normal.iloc[:, 1], label="Normal", alpha=0.6)
    ax.scatter(anomaly.iloc[:, 0], anomaly.iloc[:, 1], label="Anomaly", color="red")

    ax.set_title("Network Anomaly Detection")
    ax.legend()
    return fig
