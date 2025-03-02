# NSafe: A Network Security Tool for Detecting and Blocking Nmap Scans

NSafe is a Python-based tool designed to detect and block Nmap scans in real-time. It uses Scapy for packet capture, iptables for IP blocking, and notify-send for desktop notifications.

## Features
- Detects SYN, NULL, FIN, and XMAS scans.
- Blocks source IP addresses using iptables.
- Sends real-time desktop notifications.
- Logs detected events for future analysis.

## Setup

### Prerequisites
- Python 3.x
- Scapy (`pip install scapy`)
- iptables (pre-installed on most Linux systems)
- notify-send (`sudo apt install libnotify-bin`)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/nsafe-tool.git
   cd nsafe-tool
