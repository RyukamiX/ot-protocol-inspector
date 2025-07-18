#!/usr/bin/env python3

import argparse
import string
import re
import hashlib
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
from datetime import datetime

def is_printable(data):
    return all(chr(b) in string.printable for b in data)

def contains_sensitive_strings(data):
    try:
        decoded = data.decode(errors="ignore")
        if re.search(r"(user(name)?|login|admin|pass(word)?|token)[=:\s]", decoded, re.IGNORECASE):
            return decoded
    except Exception:
        pass
    return None

def get_modbus_function(payload):
    if len(payload) < 8:
        return None, None
    func_code = payload[7]
    func_names = {
        1: "Read Coils",
        2: "Read Discrete Inputs",
        3: "Read Holding Registers",
        4: "Read Input Registers",
        5: "Write Single Coil",
        6: "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers"
    }
    return func_code, func_names.get(func_code, f"Unknown (0x{func_code:02X})")

def fingerprint_packet(pkt):
    if IP in pkt:
        ip = pkt[IP]
        payload = bytes(pkt[TCP].payload) if TCP in pkt else bytes(pkt[UDP].payload) if UDP in pkt else b""
        return f"{ip.src}->{ip.dst}:{hashlib.md5(payload).hexdigest()}"
    return None

def detect_replay(packets, threshold=3, window=60):
    seen = defaultdict(list)
    alerts = []
    for pkt in packets:
        fp = fingerprint_packet(pkt)
        if not fp or not hasattr(pkt, 'time'):
            continue
        seen[fp].append(pkt.time)
    for fp, times in seen.items():
        times.sort()
        for i in range(len(times) - threshold + 1):
            if times[i + threshold - 1] - times[i] <= window:
                alerts.append((fp, times[i:i + threshold]))
                break
    for alert in alerts:
        print(f"[!] Replay detected for {alert[0]} {len(alert[1])} times within {window}s")

def detect_timing_anomalies(packets, thresholds=(0.001, 5.0)):
    pairs = defaultdict(list)
    for pkt in packets:
        if IP in pkt and hasattr(pkt, 'time'):
            key = (pkt[IP].src, pkt[IP].dst)
            pairs[key].append(pkt.time)
    for key, times in pairs.items():
        times.sort()
        for i in range(1, len(times)):
            gap = times[i] - times[i-1]
            if gap < thresholds[0] or gap > thresholds[1]:
                print(f"[!] Timing anomaly between {key[0]} → {key[1]}: gap of {gap:.4f}s")

def check_malformed_profinet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        udp = pkt[UDP]
        if udp.dport in [34964, 34965, 34966]:
            payload = bytes(udp.payload)
            src = pkt[IP].src
            dst = pkt[IP].dst
            if not payload.startswith(b'\x04'):
                print(f"[!] Malformed Profinet from {src} → {dst}: bad start byte")
            if b'DeviceName' not in payload or b'StationType' not in payload:
                print(f"[!] Incomplete Profinet data from {src} → {dst}: missing fields")
            if len(payload) < 20:
                print(f"[!] Short Profinet packet from {src} → {dst}: length={len(payload)})")

def analyze_modbus(pkt, count):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.sport == 502 or tcp.dport == 502:
            payload = bytes(tcp.payload)
            src = pkt[IP].src
            dst = pkt[IP].dst
            func_code, func_name = get_modbus_function(payload)
            if func_name:
                print(f"[Modbus] {src} → {dst} | Function: {func_name}")
                count[func_name] = count.get(func_name, 0) + 1
                if func_code not in range(1, 17):
                    print("  [!] Unusual Modbus function code")
                if is_printable(payload):
                    flagged = contains_sensitive_strings(payload)
                    if flagged:
                        print("  [!] Possible sensitive data:", flagged)

def analyze_dnp3(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.sport == 20000 or tcp.dport == 20000:
            payload = bytes(tcp.payload)
            if payload.startswith(b'\x05\x64') and len(payload) > 6:
                src = pkt[IP].src
                dst = pkt[IP].dst
                func_code = payload[6]
                print(f"[DNP3] {src} → {dst} | Function Code: 0x{func_code:02X}")
                if func_code > 0x1F:
                    print("  [!] Nonstandard DNP3 function code")
                if is_printable(payload):
                    flagged = contains_sensitive_strings(payload)
                    if flagged:
                        print("  [!] Possible sensitive data:", flagged)

def analyze_profinet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        udp = pkt[UDP]
        if udp.dport in [34964, 34965, 34966]:
            payload = bytes(udp.payload)
            src = pkt[IP].src
            dst = pkt[IP].dst
            if b'DeviceName' in payload or b'StationType' in payload:
                print(f"[Profinet] {src} → {dst}")
                if is_printable(payload):
                    flagged = contains_sensitive_strings(payload)
                    if flagged:
                        print("  [!] Possible sensitive data:", flagged)
            check_malformed_profinet(pkt)

def analyze_enip(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.dport == 44818:
            payload = bytes(tcp.payload)
            src = pkt[IP].src
            dst = pkt[IP].dst
            if b'Tag' in payload or b'Session' in payload:
                print(f"[ENIP] {src} → {dst}")
                if is_printable(payload):
                    flagged = contains_sensitive_strings(payload)
                    if flagged:
                        print("  [!] Possible sensitive data:", flagged)

def main():
    parser = argparse.ArgumentParser(description="OT PCAP Inspector - Protocols: Modbus, DNP3, ENIP, Profinet")
    parser.add_argument("pcap", help="Path to PCAP file")
    args = parser.parse_args()

    try:
        packets = rdpcap(args.pcap)
    except FileNotFoundError:
        print(f"File not found: {args.pcap}")
        return

    modbus_counts = {}
    for pkt in packets:
        analyze_modbus(pkt, modbus_counts)
        analyze_dnp3(pkt)
        analyze_profinet(pkt)
        analyze_enip(pkt)

    if modbus_counts:
        print("\n[Modbus Function Usage]")
        for func, hits in modbus_counts.items():
            print(f"  {func}: {hits}")

    detect_replay(packets)
    detect_timing_anomalies(packets)

if __name__ == "__main__":
    main()