# Packet Capture and Analysis Tool

## Overview
This tool captures TCP and UDP packets on a network interface, analyzes traffic patterns, and optionally runs Nmap scans on destination IPs to provide basic security insights.

---

## Features
- Capture a user-defined number of TCP and UDP packets
- Log packet details to a file (scan_log.txt)
- Analyze captured traffic (top destination IPs, targeted ports, protocol usage)
- View detailed information about individual packets
- Run on-demand Nmap scans for destination IPs
- Generate security insights based on Nmap scan results

---

## Requirements
- Python 3.x
- Nmap installed on your system
- Root/admin privileges to capture raw packets

---

## How It Works
1. *Capture Packets*
   - Uses raw sockets to capture Ethernet frames
   - Extracts IP layer and TCP/UDP segment information
   - Saves captured packets into a list and writes basic information into a log file

2. *Traffic Analysis*
   - Counts destination IPs, ports, and protocol types
   - Prints top 5 destination IPs and ports targeted

3. *Packet Details and Nmap Scan*
   - Allows user to select a captured packet
   - Resolves hostnames of source/destination IPs
   - Runs nmap -Pn <destination IP> via subprocess
   - Analyzes Nmap output to generate security insights

---

## Usage

1. Run the script with administrator/root privileges:

```bash
sudo python3 packet_capture_tool.py
```

2. Follow the prompts:
   - Enter the number of packets you want to capture
   - View traffic analysis summary
   - Select specific packets to inspect further and run security scans

3. All logs and analysis will be saved in scan_log.txt.

---

## Example

```bash
Enter number of TCP/UDP packets to capture: 10
[*] Capturing 10 TCP/UDP packets...
[*] Capture complete!

[*] Packet Summary:
  Packet #1: TCP — 192.168.1.5 -> 93.184.216.34
  Packet #2: UDP — 192.168.1.5 -> 8.8.8.8
...

Enter packet number to view details (or 'q' to quit): 1
[*] Running Nmap scan on 93.184.216.34...
```

---

## Notes
- Works only on Linux or macOS systems (uses AF_PACKET which is not available on Windows)
- Ensure you have appropriate permissions to run raw sockets
- Always use network scanning tools responsibly

---

## Future Improvements
- Add Windows support
- Provide live packet filtering (by port, IP, etc.)
- Integrate more detailed Nmap scan options
- Implement a GUI

---

## Disclaimer
This tool is intended for educational and authorized security auditing purposes only. Unauthorized network scanning is illegal and unethical.
