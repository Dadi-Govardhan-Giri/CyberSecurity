import time
from collections import defaultdict
from datetime import datetime

import pandas as pd
from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from tabulate import tabulate

LOCAL_IP = "192.168.0.113"

packets_data = []
alerts = []

port_tracker = defaultdict(set)
syn_tracker = defaultdict(int)
beacon_tracker = defaultdict(list)

SUSPICIOUS_PORTS = [4444, 1337, 5555]

def classify_threat(packet, src_ip, dst_ip):
    threat = "NORMAL"

    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        flags = packet[TCP].flags

        # Red Team - SYN Scan
        if flags == "S":
            syn_tracker[src_ip] += 1
            if syn_tracker[src_ip] > 20:
                threat = "SYN SCAN"

        # Malware Reverse Shell
        if dport in SUSPICIOUS_PORTS:
            threat = "REVERSE SHELL"

        # Port Scan
        port_tracker[src_ip].add(dport)
        if len(port_tracker[src_ip]) > 15:
            threat = "PORT SCAN"

    # Beaconing detection
    now = time.time()
    beacon_tracker[src_ip].append(now)
    beacon_tracker[src_ip] = [t for t in beacon_tracker[src_ip] if now - t < 10]

    if len(beacon_tracker[src_ip]) > 30:
        threat = "POSSIBLE BEACONING"

    return threat

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    src = packet[IP].src
    dst = packet[IP].dst
    length = len(packet)
    protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"

    threat = classify_threat(packet, src, dst)

    packet_info = {
        "Time": timestamp,
        "From": src,
        "To": dst,
        "Protocol": protocol,
        "Length": length,
        "Threat": threat
    }

    packets_data.append(packet_info)

def run_ml_detection():
    df = pd.DataFrame(packets_data)

    if len(df) < 20:
        return

    model = IsolationForest(contamination=0.05)
    df["ML_Anomaly"] = model.fit_predict(df[["Length"]])

    df.loc[df["ML_Anomaly"] == -1, "Threat"] = "ML_ANOMALY"

    return df

print(" Elite SOC IDS Running...")
sniff(prn=process_packet, count=200, iface="en0", filter="ip")

df = run_ml_detection()

if df is not None:
    print(tabulate(df.tail(20), headers="keys", tablefmt="fancy_grid"))

print("\n Detection Completed")