import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

OUTPUT_DIR = "../data/raw"
os.makedirs(OUTPUT_DIR, exist_ok=True)

rows = []
start_time = datetime.now()

for i in range(1500):
    timestamp = start_time + timedelta(seconds=i)
    src_ip = f"192.168.1.{random.randint(2, 40)}"
    dst_ip = f"192.168.1.{random.randint(50, 100)}"

    protocol = random.choice(["TCP", "UDP", "ICMP"])
    protocol_num = {"TCP": 6, "UDP": 17, "ICMP": 1}[protocol]

    packet_size = abs(np.random.normal(500, 100))
    packet_rate = abs(np.random.normal(25, 6))
    duration = np.random.uniform(0.1, 1.5)

    label = 0
    if random.random() < 0.1:
        packet_size = abs(np.random.normal(1500, 300))
        packet_rate = abs(np.random.normal(120, 30))
        duration = np.random.uniform(2, 5)
        label = 1

    rows.append([
        timestamp, src_ip, dst_ip, protocol,
        protocol_num, packet_size, packet_rate, duration, label
    ])

df = pd.DataFrame(rows, columns=[
    "timestamp", "src_ip", "dst_ip", "protocol",
    "protocol_num", "packet_size", "packet_rate",
    "duration", "label"
])

path = os.path.join(OUTPUT_DIR, "dummy_network_raw.csv")
df.to_csv(path, index=False, encoding="utf-8")

print(f"Dummy CSV generated: {path}")
