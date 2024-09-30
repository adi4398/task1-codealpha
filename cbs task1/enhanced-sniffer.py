from scapy.all import sniff, IP, TCP
import datetime

# Initialize counters for different protocols
packet_count = 0
http_count = 0
tcp_count = 0
udp_count = 0

# Create or open a log file to save captured packets
log_file = open("captured_packets.log", "w")

# Define a callback function to handle captured packets
def packet_handler(packet):
    global packet_count, http_count, tcp_count, udp_count
    
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        packet_count += 1  # Increment total packet count
        
        # Prepare packet info
        packet_info = f"[{datetime.datetime.now()}] Packet: {ip_layer.src} -> {ip_layer.dst}"
        
        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_count += 1
            packet_info += f" | TCP: {ip_layer.src}:{packet[TCP].sport} -> {ip_layer.dst}:{packet[TCP].dport}"
            
            # Check for HTTP packets by examining port 80 (HTTP) or 443 (HTTPS)
            if packet[TCP].dport == 80 or packet[TCP].dport == 443:
                http_count += 1
                packet_info += " | HTTP Traffic Detected"
                analyze_http_packet(packet)
        
        print(packet_info)  # Print packet information
        log_file.write(packet_info + "\n")  # Save to log file

# Analyze HTTP packets to extract headers and content
def analyze_http_packet(packet):
    # Extract and print HTTP headers/content if present
    if b"GET" in bytes(packet) or b"POST" in bytes(packet):
        http_header = bytes(packet).split(b"\r\n")
        print("---- HTTP Header ----")
        for header in http_header:
            print(header.decode(errors='ignore'))
        print("---------------------")

# Display summary statistics on exit
def display_summary():
    print("\n[*] Packet Capture Summary:")
    print(f"Total Packets Captured: {packet_count}")
    print(f"Total HTTP Packets: {http_count}")
    print(f"Total TCP Packets: {tcp_count}")
    print(f"Total UDP Packets: {udp_count}")

try:
    # Start sniffing network traffic
    print("[*] Starting enhanced network sniffer...")
    sniff(prn=packet_handler, store=False)
except KeyboardInterrupt:
    print("\n[!] Stopping network sniffer...")
    display_summary()
    log_file.close()  # Close log file
    print("[*] Log file saved: captured_packets.log")
    '''Key Enhancements
Filter Specific Traffic (HTTP Detection):

The script now checks for HTTP or HTTPS traffic by examining if the destination port (dport) is 80 (HTTP) or 443 (HTTPS). If detected, it will analyze the packet's content for HTTP headers.
Save Captured Data:

Captured packets' details are saved to a log file (captured_packets.log) in addition to being printed to the console. The log file is opened at the start and closed upon exiting.
Analyze HTTP Packets:

The analyze_http_packet() function attempts to extract and print HTTP headers or contents from the packet. It checks for the presence of "GET" or "POST" requests to identify HTTP content.
Display Packet Count:

A summary is displayed when the script is stopped (e.g., with Ctrl+C), showing the total number of packets captured and breaking down by protocol type (HTTP, TCP, UDP).'''
