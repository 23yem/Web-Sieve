import nmap
import requests
import subprocess
import argparse
import ipaddress
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress the "Insecure Request" warnings in the terminal
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- CONFIGURATION ---
WORDLIST = "/usr/share/wordlists/dirb/common.txt" 
OUTPUT_DIR = "results"
MAX_HOST_CONCURRENCY = 5

def log(msg):
    """
    Helper to print messages without breaking the progress bar.
    """
    tqdm.write(msg)

def discover_live_hosts(target_input):
    """
    Phase 1: Fast Host Discovery.
    Since ICMP is allowed, we use -PE (Standard Ping).
    We also keep -PS (TCP SYN) as a backup for weird firewalls.
    """
    nm = nmap.PortScanner()
    log(f"[*] Phase 1: Ping Sweeping [{target_input}] to find live hosts...")
    
    try:
        # -sn: Ping Scan only (No port scan yet)
        # -PE: ICMP Echo (Standard Ping)
        # -PS445,3389: TCP Probe to common Windows ports (Just in case ICMP fails)
        # -n: No DNS resolution (Speed boost)
        nm.scan(target_input, arguments='-sn -PE -PS445,3389 -n')
        
        # Get list of hosts that are 'up'
        live_hosts = nm.all_hosts()
        log(f"[*] Discovery complete. Found {len(live_hosts)} live hosts.")
        return live_hosts
    except Exception as e:
        log(f"[!] Discovery Error: {e}")
        return []

def port_scan(target_ip):
    """
    Phase 2: Deep Port Scan.
    Includes timeout safety to prevent hanging on zombie hosts.
    """
    nm = nmap.PortScanner()
    log(f"[{target_ip}] Starting Deep Port Scan (-p-)...")
    
    try:
        # --max-retries 1: Don't retry endlessly if a packet is dropped
        # --host-timeout 2m: If scan takes > 2 mins, kill it.
        nm.scan(target_ip, arguments='-p- -T4 --open -n -Pn -sS --max-retries 1 --host-timeout 2m')
        
        if target_ip not in nm.all_hosts():
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
    """
    Phase 3: Web Service Identification.
    Tries HTTPS first to avoid 400 Bad Request errors on SSL ports.
    """
    protocols = ['https', 'http']
    
    for proto in protocols:
        url = f"{proto}://{ip}:{port}"
        try:
            # We accept 400/401/403/200/etc, but if it's a protocol error, requests will raise an exception.
            requests.get(url, timeout=3, verify=False)
            return url
        except requests.exceptions.RequestException:
            # If HTTPS fails (e.g. it's a plaintext port), this catches it and we loop to HTTP.
            pass
    return None

def run_gobuster(url, target_ip):
    """
    Phase 4: Directory Brute-force.
    Handles Wildcard errors gracefully.
    """
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
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if Gobuster failed (non-zero exit code)
        if result.returncode != 0:
            # Check for the specific "Wildcard" error
            if "the server returns a status code that matches the provided options" in result.stderr:
                log(f"[{target_ip}] SKIPPING: {url} (Wildcard Response detected - Server responds to everything)")
            else:
                log(f"[!] Gobuster Error on {url}:\n{result.stderr}")
        else:
            # Only report success if the file has content
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                log(f"[{target_ip}] FINISHED: {url} -> Saved to {output_file}")
            else:
                log(f"[{target_ip}] FINISHED: {url} (No results found)")
                
    except Exception as e:
        log(f"[{target_ip}] Subprocess Error on {url}: {e}")

def workflow_per_host(ip):
    # 1. Scan Ports
    ports = port_scan(ip)
    if not ports:
        log(f"[{ip}] Scan finished. No open ports found.")
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

    # Ensure output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Check for Root privileges (Required for Nmap SYN scan)
    if os.geteuid() != 0:
        log("[!] WARNING: You are not running as root. Nmap -sS scan will fail.")
        sys.exit(1)

    # --- FIX FOR COMMA SEPARATED LISTS ---
    # Nmap prefers spaces between targets. We simply swap commas for spaces.
    formatted_target = args.target.replace(",", " ")

    # PHASE 1: HOST DISCOVERY
    # Filters the potential IPs down to just the alive ones.
    live_targets = discover_live_hosts(formatted_target)
    
    if not live_targets:
        log("[!] No live hosts found. Exiting.")
        sys.exit(0)

    # PHASE 2: DEEP SCANNING
    # Run heavy scans only on alive hosts
    log(f"[*] Starting deep scans on {len(live_targets)} hosts...")
    
    with ThreadPoolExecutor(max_workers=MAX_HOST_CONCURRENCY) as executor:
        futures = [executor.submit(workflow_per_host, ip) for ip in live_targets]
        
        for _ in tqdm(as_completed(futures), total=len(live_targets), desc="Scanning Targets", unit="host"):
            pass

    log("[*] All scans completed.")

if __name__ == "__main__":
    main()
