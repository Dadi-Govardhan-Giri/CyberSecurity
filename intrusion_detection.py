import csv
import time
from datetime import datetime

import pandas as pd
from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP
from sklearn.ensemble import IsolationForest

LOCAL_IP = "192.168.0.113"
LOG_FILE = "advanced_ids_logs.csv"

packets_data = []

with open(LOG_FILE, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow([
        "timestamp", "direction", "src_ip", "src_port",
        "dst_ip", "dst_port", "protocol",
        "length", "tcp_flags", "dns_query",
        "http_host", "alert_type"
    ])

def log_packet(data):
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data)

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    length = len(packet)

    direction = "OUTBOUND" if src_ip == LOCAL_IP else "INBOUND"

    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"
    tcp_flags = "-"
    dns_query = "-"
    http_host = "-"
    alert_type = "NORMAL"

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags

    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if packet.haslayer(DNS):
        dns_query = packet[DNS].qd.qname.decode()

    if packet.haslayer(HTTPRequest):
        http_host = packet[HTTPRequest].Host.decode()

    packets_data.append({"length": length})

    log_packet([
        timestamp, direction, src_ip, src_port,
        dst_ip, dst_port, protocol,
        length, tcp_flags, dns_query,
        http_host, alert_type
    ])

def detect_ml_anomalies():
    if len(packets_data) < 20:
        print("Not enough data for ML detection...")
        return

    df = pd.DataFrame(packets_data)
    model = IsolationForest(contamination=0.05)
    df["anomaly"] = model.fit_predict(df[["length"]])

    anomalies = df[df["anomaly"] == -1]

    for index in anomalies.index:
        print("🚨 ML Anomaly Detected at packet index:", index)

print("🚀 Advanced SOC-Level IDS Started...")
sniff(prn=process_packet, count=200, iface="en0", filter="ip")
detect_ml_anomalies()

print("✅ Logs saved to advanced_ids_logs.csv")