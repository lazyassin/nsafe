from scapy.all import sniff, IP, TCP
import subprocess
import time
import os

# Configuration
BLOCK_IPS = True  # Set to False to disable IP blocking
LOG_FILE = "nsafe_server.log"  # File to log detected scans
RATE_LIMIT = 60  # Time (in seconds) to wait before blocking the same IP again

# Track recently blocked IPs to avoid rate-limiting
recently_blocked = {}

def send_notification(message):
    """Send a desktop notification using notify-send."""
    try:
        subprocess.run(["notify-send", "NSafe Server", message])
    except Exception as e:
        print(f"Failed to send notification: {e}")

def log_event(message):
    """Log events to a file."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.ctime()}: {message}\n")
        print(message)  # Print to console as well

        # Send a desktop notification
        send_notification(message)
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def detect_nmap(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        tcp_flags = packet[TCP].flags

        # Detect common Nmap scan types
        if tcp_flags == 2:  # SYN scan
            log_event(f"Possible Nmap SYN scan detected from {ip_src}")
            block_ip(ip_src)
        elif tcp_flags == 0:  # NULL scan
            log_event(f"Possible Nmap NULL scan detected from {ip_src}")
            block_ip(ip_src)
        elif tcp_flags == 1:  # FIN scan
            log_event(f"Possible Nmap FIN scan detected from {ip_src}")
            block_ip(ip_src)
        elif tcp_flags == 41:  # XMAS scan (FIN + URG + PUSH flags)
            log_event(f"Possible Nmap XMAS scan detected from {ip_src}")
            block_ip(ip_src)

def block_ip(ip):
    """Block the given IP using iptables."""
    if not BLOCK_IPS:
        log_event(f"IP blocking is disabled. Would have blocked {ip}.")
        return

    # Rate-limiting: Check if the IP was recently blocked
    if ip in recently_blocked:
        if time.time() - recently_blocked[ip] < RATE_LIMIT:
            log_event(f"IP {ip} was recently blocked. Skipping.")
            return

    try:
        subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
        log_event(f"Blocked IP: {ip}")
        recently_blocked[ip] = time.time()  # Record the time of blocking
    except subprocess.CalledProcessError as e:
        log_event(f"Failed to block IP {ip}: {e}")

if __name__ == "__main__":
    # Ensure the log file exists and is writable
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w") as f:
                f.write("NSafe Server Log\n")
        except Exception as e:
            print(f"Failed to create log file: {e}")
            exit(1)

    log_event("Starting NSafe Server...")
    print(f"Listening for Nmap scans. Logs will be saved to {LOG_FILE}.")
    sniff(filter="tcp", prn=detect_nmap, store=False)
