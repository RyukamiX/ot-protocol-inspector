# OT Protocol Inspector

A Python-based analyzer for inspecting Operational Technology (OT) network traffic from PCAP files. Designed for ICS security analysts, engineers, and defenders working with protocols like:

- **Modbus TCP**
- **DNP3**
- **Profinet**
- **EtherNet/IP**

 Detects unencrypted data, malformed protocol behavior, and potential replay activity — all without needing Wireshark.

---

## Features

- **Protocol Parsing**
  - Identifies OT protocol traffic (Modbus, DNP3, Profinet, EtherNet/IP)
  - Parses Modbus function codes (e.g., Read Coils, Write Registers)
  - Flags uncommon or nonstandard DNP3 function codes

- **Sensitive Data Detection**
  - Extracts printable ASCII content
  - Alerts on usernames, passwords, tokens, and similar terms in payloads

- **Replay Pattern Detection**
  - Tracks repeated packets between endpoints
  - Flags identical payloads seen more than 3 times within 60 seconds

- **Timing Anomaly Detection**
  - Leverages packet timestamps
  - Flags abnormal gaps or bursts in communication flow

- **Malformed Profinet Structure Checks**
  - Detects missing fields like `DeviceName` or `StationType`
  - Verifies basic structure length and expected byte patterns
  - 
    
Why Use This?
This tool gives you:

Lightweight protocol insight without relying on full-blown Wireshark setups

A way to detect potential plaintext leaks in sensitive OT traffic

An early warning system for replay or malformed packet behavior

---
 Roadmap Ideas
HTML/CSV report generation

CVE pattern matching in payloads

Visualization of timing jitter


##  Usage

```bash
python ot-protocol-inspector.py path/to/your.pcap
Requirements
Python 3.7+

Scapy

Install with:

bash
Copy
Edit
pip install scapy

