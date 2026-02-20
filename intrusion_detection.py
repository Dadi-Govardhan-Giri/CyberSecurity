from datetime import datetime

import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP
from sklearn.ensemble import IsolationForest

packets_data = []

def process_packet(packet):
    if packet.haslayer(IP):
        packets_data.append({
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "length": len(packet),
            "time": datetime.now().timestamp()
        })

# def detect_anomalies():
#     df = pd.DataFrame(packets_data)
#     model = IsolationForest(contamination=0.05)
#     df["anomaly"] = model.fit_predict(df[["length"]])
#     print(df[df["anomaly"] == -1])

def detect_anomalies():
    if len(packets_data) == 0:
        print("⚠️ No packets captured. Try running with sudo.")
        return

    df = pd.DataFrame(packets_data)

    if "length" not in df.columns:
        print("⚠️ Length column missing.")
        return

    model = IsolationForest(contamination=0.05)
    df["anomaly"] = model.fit_predict(df[[[
  "length",
  "src_port",
  "dst_port",
  "protocol",
  "packet_rate",
  "tcp_flags"
]]])
    print(df[df["anomaly"] == -1])

print("🚀 Starting Packet Capture...")
sniff(prn=process_packet, count=100)
detect_anomalies()