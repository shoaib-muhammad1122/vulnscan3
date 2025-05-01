
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import datetime

# === Spinner for user engagement ===
def animated_spinner(stop_event, message="🔍 Scanning in progress"):
    spinner = ['|', '/', '-', '\\']
    idx = 0
    while not stop_event.is_set():
        sys.stdout.write(f'\r{message} {spinner[idx % len(spinner)]}')
        sys.stdout.flush()
        idx += 1
        time.sleep(0.15)
    sys.stdout.write('\r' + ' ' * (len(message) + 5) + '\r')
    sys.stdout.flush()

# === Port Scanning ===
def scan_port(ip, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
    except:
        return None
    banner = ""
    try:
        sock.settimeout(2)
        banner = sock.recv(1024).decode(errors='ignore').strip()
    except:
        pass
    finally:
        sock.close()
    return (port, banner or "<no banner>")

def scan_all_ports(ip, max_workers=100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in range(1, 65536)}
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x[0])

# === HTTP Header Analysis ===
def analyze_http_headers(target):
    headers_to_check = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
    found_headers = {}
    response = None
    try:
        response = requests.get(f"http://{target}", timeout=5, verify=False)
    except:
        try:
            response = requests.get(f"https://{target}", timeout=5, verify=False)
        except:
            return None
    if not response:
        return None
    resp_headers = response.headers
    missing = []
    for header in headers_to_check:
        if header in resp_headers:
            found_headers[header] = resp_headers.get(header)
        else:
            missing.append(header)
    return missing, found_headers

# === Report Generation ===
def generate_report(target, open_ports, http_headers):
    filename = f"Scan_Report_{target.replace('.', '_')}.txt"
    with open(filename, "w") as f:
        f.write("=== VULNERABILITY SCAN REPORT ===\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date: {datetime.datetime.now()}\n")
        f.write("="*40 + "\n\n")

        f.write("[+] Open TCP Ports and Banners:\n")
        for port, banner in open_ports:
            f.write(f"  Port {port}: {banner}\n")
        if not open_ports:
            f.write("  No open ports found.\n")
        f.write("\n")

        f.write("[+] HTTP Security Header Analysis:\n")
        if http_headers is None:
            f.write("  Unable to connect to HTTP/HTTPS service.\n")
        else:
            missing, found = http_headers
            if missing:
                for h in missing:
                    f.write(f"  MISSING: {h}\n")
            else:
                f.write("  All recommended security headers are present.\n")
            f.write("\n  Full Headers:\n")
            for k, v in found.items():
                f.write(f"    {k}: {v}\n")

    print(f"\n[*] Report saved as: {filename}")

# === Main Program ===
def main():
    print("="*50)
    print("👋 Welcome Shoaib! This is your Python Vulnerability Scanner")
    print("="*50)
    target_input = input("Enter target IP or domain: ").strip()

    try:
        ip = socket.gethostbyname(target_input)
    except socket.gaierror:
        print("[!] Invalid IP/domain. Exiting.")
        return

    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=animated_spinner, args=(stop_event,))
    spinner_thread.start()

    try:
        open_ports = scan_all_ports(ip)
    finally:
        stop_event.set()
        spinner_thread.join()

    http_headers = analyze_http_headers(target_input)
    generate_report(target_input, open_ports, http_headers)

if __name__ == "__main__":
    main()
