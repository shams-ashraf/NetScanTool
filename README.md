# 🛠️ Network Toolkit

**Network Toolkit** is a Python-based desktop application designed for analyzing and monitoring network activity. It uses `tkinter` for the graphical user interface and `scapy` for low-level network packet manipulation. This toolkit provides functionalities such as ARP scanning, packet sniffing and filtering, custom packet generation, performance measurement, and real-time traffic logging.

---

## 🚀 Features

### 📡 ARP Scanning
- Discover active devices on a local network.
- Input a network interface and IP range (e.g., `192.168.1.1/24`).
- View the scan results live within the application.

### 🧪 Packet Analysis
- Capture and analyze network packets in real-time.
- Filter by:
  - Target IP Address (e.g., `10.9.0.6`)
  - Protocol: `TCP`, `UDP`, `ICMP`, or all protocols
- Displays detailed packet information including headers and sizes.

### 📤 Custom Packet Creation & Network Performance Measurement
- Generate and send custom:
  - **ICMP (Ping)** packets
  - **TCP (SYN)** packets
- Define:
  - Target IP and Port
  - Number of packets
  - Packet size (ICMP)
- Automatically calculates:
  - Latency
  - Jitter
  - Throughput
  - Data Rate

### 📊 Traffic Monitoring & Logging
- Continuously sniff network traffic on a selected interface.
- Log packet details such as:
  - Timestamp
  - Protocol
  - Source IP
  - Destination IP
  - Packet size
- Logs are saved in `traffic.log` for further inspection.

---

## ⚙️ Requirements

- Python 3.x
- `scapy` library
- `tkinter` (usually included with Python)

---

## 📦 Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/shams-ashraf/network-toolkit.git
   cd network-toolkit
   
2-Install the required dependencies:
   pip install scapy
   
🧑‍💻 Usage

  python network_toolkit.py
  
🧭 Application Interface

When launched, the main menu provides the following options:

1. ARP Scanning
Enter a network interface (e.g., Wi-Fi, eth0).

Enter an IP range (e.g., 192.168.1.1/24).

Click Start ARP Scan to discover hosts.

2. Packet Analysis
Input an IP address to filter.

Choose a protocol: TCP, UDP, ICMP, or All.

Click Start Capture to begin sniffing.

Click Stop Capture to stop.

3. Custom Packet Creation & Performance Measurement
Choose ICMP or TCP packet type.

Enter:

Target IP address

Port number (TCP)

Number of packets

Packet size (ICMP)

Click Send Packet to begin.

View latency, jitter, throughput, and data rate.

4. Traffic Monitoring & Logging
Input the interface name (e.g., Wi-Fi, eth0).

Click Start Traffic Monitoring to begin sniffing and logging.

Logs are saved to traffic.log.

📁 Output Files
traffic.log – Contains timestamped logs of network packets.

GUI – Displays live output for all functions.
