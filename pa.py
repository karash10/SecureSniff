import socket
import struct
import subprocess
from collections import Counter

captured_packets = []
LOG_FILE = "scan_log.txt"

# Clear the log file at the start
with open(LOG_FILE, "w") as f:
    f.write("=== Packet Capture Log ===\n\n")

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Hostname not found"

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return {
        "version": version_header_length >> 4,
        "header_length": header_length,
        "ttl": ttl,
        "protocol": proto,
        "src": socket.inet_ntoa(src),
        "dst": socket.inet_ntoa(target),
        "data": data[header_length:]
    }

def tcp_segment(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return {
        "src_port": src_port,
        "dst_port": dest_port,
        "sequence": sequence,
        "acknowledgment": ack
    }

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('!HHH2x', data[:8])
    return {
        "src_port": src_port,
        "dst_port": dest_port,
        "length": length
    }

def capture_packets(packet_limit):
    tcp_count = 0
    udp_count = 0

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print(f"\n[*] Capturing {packet_limit} TCP/UDP packets...\n")

    with open(LOG_FILE, "a") as f:
        while len(captured_packets) < packet_limit:
            raw_data, _ = conn.recvfrom(65536)
            ip_data = raw_data[14:]
            ip_info = ipv4_packet(ip_data)

            packet = {
                "src_ip": ip_info['src'],
                "dst_ip": ip_info['dst']
            }

            if ip_info['protocol'] == 6:  # TCP
                try:
                    tcp_info = tcp_segment(ip_info['data'])
                    packet.update({
                        "type": "TCP",
                        **tcp_info
                    })
                    captured_packets.append(packet)
                    tcp_count += 1
                except:
                    continue

            elif ip_info['protocol'] == 17:  # UDP
                try:
                    udp_info = udp_segment(ip_info['data'])
                    packet.update({
                        "type": "UDP",
                        **udp_info
                    })
                    captured_packets.append(packet)
                    udp_count += 1
                except:
                    continue

        # Log packets
        for idx, pkt in enumerate(captured_packets, 1):
            f.write(f"Packet #{idx}\n")
            for key, value in pkt.items():
                f.write(f"  {key}: {value}\n")
            f.write("\n")

    print(f"\n[*] Capture complete!")
    print(f"  Total TCP packets: {tcp_count}")
    print(f"  Total UDP packets: {udp_count}\n")
    print("[*] Packet Summary:")
    for idx, pkt in enumerate(captured_packets, 1):
        print(f"  Packet #{idx}: {pkt['type']} — {pkt['src_ip']} -> {pkt['dst_ip']}")

def traffic_analysis():
    ip_counter = Counter()
    port_counter = Counter()
    protocol_counter = Counter()

    for pkt in captured_packets:
        ip_counter[pkt['dst_ip']] += 1
        port_counter[pkt['dst_port']] += 1
        protocol_counter[pkt['type']] += 1

    print("\n Traffic Analysis Summary:")
    with open(LOG_FILE, "a") as f:
        f.write("=== Traffic Analysis Summary ===\n")
        f.write("Top Destination IPs:\n")
        for ip, count in ip_counter.most_common(5):
            print(f"  {ip}: {count} packets")
            f.write(f"  {ip}: {count} packets\n")

        f.write("\nMost Targeted Ports:\n")
        print("\nMost Targeted Ports:")
        for port, count in port_counter.most_common(5):
            print(f"  Port {port}: {count} packets")
            f.write(f"  Port {port}: {count} packets\n")

        f.write("\nProtocol Usage:\n")
        print("\nProtocol Usage Breakdown:")
        for proto, count in protocol_counter.items():
            print(f"  {proto}: {count} packets")
            f.write(f"  {proto}: {count} packets\n")

def analyze_nmap_output(output):
    insights = []
    lines = output.splitlines()
    open_ports = []

    for line in lines:
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if parts:
                port = int(parts[0].split("/")[0])
                open_ports.append(port)

    if not open_ports:
        insights.append(" Host appears secure or behind a firewall (no open TCP ports detected).")
    else:
        insights.append("Open ports detected: " + ", ".join(map(str, open_ports)))
        if any(p in open_ports for p in [22, 23, 3389]):
            insights.append(" Remote access service detected (e.g., SSH/RDP). Ensure authentication and firewalls are strong.")
        if len(open_ports) > 5:
            insights.append("Multiple open ports indicate a broader attack surface. Limit exposure if not necessary.")
        if set(open_ports).issubset({80, 443}):
            insights.append("Standard web ports open (80/443). Typical for web servers.")

    return "\n".join(insights)

def show_packet_details():
    while True:
        choice = input("\nEnter packet number to view details (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            print("[*] Exiting...")
            break
        if not choice.isdigit():
            print("Please enter a valid number.")
            continue

        idx = int(choice)
        if 1 <= idx <= len(captured_packets):
            pkt = captured_packets[idx - 1]
            print(f"\n Details of Packet #{idx}")
            print(f"  Type              : {pkt.get('type', 'N/A')}")
            print(f"  Source IP         : {pkt.get('src_ip', 'N/A')}")
            print(f"  Source Host       : {resolve_hostname(pkt.get('src_ip', ''))}")
            print(f"  Destination IP    : {pkt.get('dst_ip', 'N/A')}")
            print(f"  Destination Host  : {resolve_hostname(pkt.get('dst_ip', ''))}")
            print(f"  Source Port       : {pkt.get('src_port', 'N/A')}")
            print(f"  Destination Port  : {pkt.get('dst_port', 'N/A')}")
            if pkt['type'] == 'TCP':
                print(f"  Sequence Number   : {pkt.get('sequence', 'N/A')}")
                print(f"  Acknowledgment    : {pkt.get('acknowledgment', 'N/A')}")
            elif pkt['type'] == 'UDP':
                print(f"  Length            : {pkt.get('length', 'N/A')}")

            # Run Nmap scan on destination IP
            dst_ip = pkt.get("dst_ip")
            print(f"\n[*] Running Nmap scan on {dst_ip}...\n")
            try:
                result = subprocess.run(["nmap", "-sV", dst_ip], capture_output=True, text=True, timeout=15)
                nmap_output = result.stdout
                insight = analyze_nmap_output(nmap_output)

                print(nmap_output)
                print("Security Insights:")
                print(insight)

                with open(LOG_FILE, "a") as f:
                    f.write(f"\n=== Nmap Scan for Packet #{idx} — {dst_ip} ===\n")
                    f.write(nmap_output)
                    f.write("\n Security Insights:\n")
                    f.write(insight)
                    f.write("\n" + "="*50 + "\n")
            except Exception as e:
                print(f"[!] Error running nmap: {e}")
        else:
            print(f"Invalid number. Choose 1 to {len(captured_packets)}.")

def main():
    try:
        packet_limit = int(input("Enter number of TCP/UDP packets to capture: "))
        if packet_limit <= 0:
            print("Enter a positive number.")
            return
    except ValueError:
        print("Invalid input.")
        return

    capture_packets(packet_limit)
    traffic_analysis()
    show_packet_details()

if __name__ == "__main__":
    main()
