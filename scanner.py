import socket
import sys
from datetime import datetime

# Port Scanner by Het
# Educational project - checks open ports and their common services

def get_local_ip():
    """Get local machine IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # Google DNS
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_service_name(port):
    """Try to resolve port number to common service name"""
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def scan_target(target, start_port, end_port):
    print(f"\n[+] Starting scan on {target}")
    print(f"[+] Time started: {datetime.now()}\n")
    print("PORT\tSTATE\tSERVICE")

    results = []

    try:
        for port in range(start_port, end_port + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))  # 0 = open

            if result == 0:
                service = get_service_name(port)
                line = f"{port}\tOPEN\t{service.upper()}"
                print(line)
                results.append(line)
            s.close()

    except KeyboardInterrupt:
        print("\n[!] Scan stopped by user.")
        sys.exit()
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("\n[!] Could not connect to server.")
        sys.exit()

    # Save results
    with open("results.txt", "w") as f:
        f.write(f"Scan results for {target}\n")
        f.write(f"Started at: {datetime.now()}\n\n")
        f.write("PORT\tSTATE\tSERVICE\n")
        for r in results:
            f.write(r + "\n")

    print(f"\n[+] Scan finished. Results saved in results.txt")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 scanner.py <target/local> <start_port> <end_port>")
        print("Example: python3 scanner.py scanme.nmap.org 20 100")
        print("         python3 scanner.py local 1 500")
        sys.exit()

    target_arg = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    # Detect local IP if "local" is used
    if target_arg.lower() == "local":
        target = get_local_ip()
        print(f"[+] Detected local IP: {target}")
    else:
        target = target_arg

    scan_target(target, start_port, end_port)

