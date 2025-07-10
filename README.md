Network Toolkit

This is a Python-based network toolkit built using tkinter for the GUI and scapy for network operations. It provides several functionalities including ARP scanning, packet analysis, custom packet creation for performance measurement, and network traffic monitoring and logging.

Features
ARP Scanning: Discover active hosts on your local network by performing an ARP scan on a specified IP range and network interface.

Packet Analysis: 

Sniff and analyze network packets based on a target IP address and protocol (TCP, UDP, ICMP, or all). Displays detailed information about captured packets.

Custom Packet Creation & Network Performance Measurement:

ICMP (Ping): Send custom ICMP packets to a target IP, measure latency, jitter, throughput, and data rate.

TCP (SYN): Send TCP SYN packets to a target IP and port, measure latency, jitter, throughput, and data rate for SYN-ACK responses.

Traffic Monitoring and Logging: 

Continuously sniff network traffic on a specified interface and log packet details (timestamp, protocol, source IP, destination IP, size) to a traffic.log file.

Requirements

Before running the application, ensure you have the following installed:

Python 3.x

scapy library

tkinter (usually comes pre-installed with Python)

Installation
Clone the repository (or download the script):

git clone https://github.com/shams-ashraf/network-toolkit.git
cd network-toolkit

Install scapy:

pip install scapy

Note for Linux users: You might need to run pip with sudo or install libpcap-dev first:

sudo apt-get update
sudo apt-get install libpcap-dev
pip install scapy

Note for Windows users: You might need to install Npcap (or WinPcap) for Scapy to function correctly.

Usage
Run the application:

python network_toolkit.py

(Replace network_toolkit.py with the actual name of your Python script if it's different.)

Main Menu:
A main window will appear with four options:

ARP Scanning

Packet Analysis

Custom Packet Creation & Network Performance Measure

Traffic Monitoring and Logging

Exit

Select an option:

ARP Scanning:

Enter the Network Interface (e.g., Wi-Fi, eth0).

Enter the IP Range (e.g., 192.168.1.1/24).

Click Start ARP Scan. Results will be displayed in the text box.

Packet Analysis:

Enter the Filter by IP Address (e.g., 10.9.0.6).

Select Filter by Protocol (All, TCP, UDP, ICMP).

Click Start Capture to begin sniffing and displaying packets matching your criteria.

Click Stop Capture to halt the sniffing process.

Custom Packet Creation & Network Performance Measure:

Choose between ICMP (Ping) or TCP (SYN).

For ICMP (Ping):

Enter the IP Address of the target.

Enter the Number of Packets to send.

Enter the Size of Packets (in bytes).

Click Send Packet.

For TCP (SYN):

Enter the IP Address of the target.

Enter the Port Number to target.

Enter the Number of Packets to send.

Click Send Packet.

Performance metrics (latency, jitter, throughput, data rate) will be displayed.

Traffic Monitoring and Logging:

Enter the Network Interface (e.g., Wi-Fi, eth0).

Click Start Traffic Monitoring. Packet details will be logged to traffic.log in the same directory as the script. The output box will also show recent logs.
