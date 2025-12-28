import nmap
import requests
import subprocess
import argparse
import ipaddress
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# --- CONFIGURATION ---
WORDLIST = "/usr/share/wordlists/dirb/common.txt" 
OUTPUT_DIR = "results"
MAX_HOST_CONCURRENCY = 5

def log(msg):
    """
    Helper to print messages without breaking the progress bar.
    """
    tqdm.write(msg)

def parse_targets(target_str):
    ips = []
    if "-" in target_str:
        try:
            start_ip, end_val = target_str.split("-")
            base_ip = ".".join(start_ip.split(".")[:-1])
            start_octet = int(start_ip.split(".")[-1])
            end_octet = int(end_val)
            for i in range(start_octet, end_octet + 1):
                ips.append(f"{base_ip}.{i}")
        except ValueError:
            log(f"[!] Error parsing range: {target_str}")
            return []
    elif "/" in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            for ip in net.hosts():
                ips.append(str(ip))
        except ValueError:
            log(f"[!] Error parsing CIDR: {target_str}")
            return []
    else:
        ips.append(target_str)
    return ips

def port_scan(target_ip):
    nm = nmap.PortScanner()
    log(f"[{target_ip}] Starting Port Scan...")
    
    try:
        # -Pn: Treat host as online (fixes the "no output" issue)
        # -sS: SYN scan (faster, requires sudo)
        # -T4: Fast timing
        nm.scan(target_ip, arguments='-p- -T4 --open -n -Pn -sS')
        
        if target_ip not in nm.all_hosts():
            log(f"[{target_ip}] Host seems down (or blocks probes).")
            return []
            
        open_ports = []
        if 'tcp' in nm[target_ip]:
            for port in nm[target_ip]['tcp']:
                if nm[target_ip]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
        
        return open_ports
    except Exception as e:
        log(f"[{target_ip}] Nmap Error: {e}")
        return []

def identify_web_service(ip, port):
    protocols = ['http', 'https']
    for proto in protocols:
        url = f"{proto}://{ip}:{port}"
        try:
            requests.get(url, timeout=2, verify=False)
            return url
        except requests.exceptions.RequestException:
            pass
    return None

def run_gobuster(url, target_ip):
    # Safety clean for filename
    filename_safe_url = url.split("://")[1].replace(":", "_").replace("/", "")
    output_file = os.path.join(OUTPUT_DIR, f"{filename_safe_url}.txt")
    
    log(f"[{target_ip}] BRUTEFORCING: {url}")
    
    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", WORDLIST,
        "-t", "40",
        "-k", 
        "-o", output_file,
        "--no-error",
        "-q"
    ]
    
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log(f"[{target_ip}] FINISHED: {url} -> Saved to {output_file}")
    except Exception as e:
        log(f"[{target_ip}] Gobuster Error on {url}: {e}")

def workflow_per_host(ip):
    # 1. Scan Ports
    ports = port_scan(ip)
    if not ports:
        return

    log(f"[{ip}] Open ports: {ports}")

    # 2. Identify Web Services
    web_targets = []
    for port in ports:
        url = identify_web_service(ip, port)
        if url:
            web_targets.append(url)

    # 3. Directory Brute-Force
    if web_targets:
        log(f"[{ip}] Found {len(web_targets)} web services. Starting brute-force...")
        for url in web_targets:
            run_gobuster(url, ip)
    else:
        log(f"[{ip}] No web services found.")

def main():
    parser = argparse.ArgumentParser(description="Web-Sieve")
    parser.add_argument("target", help="Target IP, Range, or CIDR")
    args = parser.parse_args()

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    target_list = parse_targets(args.target)
    log(f"[*] Loaded {len(target_list)} targets.")
    
    # Check for sudo if using SYN scan
    if os.geteuid() != 0:
        log("[!] WARNING: You are not running as root. Nmap -sS scan will fail.")
        log("[!] Please run with sudo.")
        sys.exit(1)

    # PARALLEL EXECUTION WITH PROGRESS BAR
    with ThreadPoolExecutor(max_workers=MAX_HOST_CONCURRENCY) as executor:
        # Submit all tasks
        futures = [executor.submit(workflow_per_host, ip) for ip in target_list]
        
        # as_completed allows the bar to update as each host finishes
        # tqdm wraps the loop to create the bar
        for _ in tqdm(as_completed(futures), total=len(target_list), desc="Scanning Targets", unit="host"):
            pass

    log("[*] All scans completed.")

if __name__ == "__main__":
    main()
