# Web-Sieve

**Web-Sieve** is a lightweight, multi-threaded reconnaissance orchestrator designed for Penetration Testing Competitions (CPTC, etc.). 

It automates the tedious process of finding web servers across a large scope. It scans for open ports, identifies HTTP/HTTPS services (on standard and non-standard ports), and automatically launches directory brute-forcing attacks, all while managing concurrency to prevent overloading target hosts.

## 🚀 Features

* **Smart Orchestration:** Scans multiple **Hosts** in parallel, but scans **Ports** on a single host sequentially to avoid DoS/crashing fragile services.
* **Service Detection:** Probes open ports to distinguish actual Web Servers from other TCP services.
* **Flexible Input:** Accepts Single IPs (`10.10.10.5`), Ranges (`10.10.10.1-50`), and CIDR (`10.10.10.0/24`).
* **Automated Brute-force:** Automatically runs `gobuster` against every confirmed web service.
* **Progress Tracking:** Includes a real-time progress bar (`tqdm`) for tracking long-running scans.

## 📋 Prerequisites

This tool relies on external binaries. You must have these installed on your system (Kali/Parrot):

* **Nmap** (`sudo apt install nmap`)
* **Gobuster** (`sudo apt install gobuster`)
* **Wordlists** (Default: `/usr/share/wordlists/dirb/common.txt`)

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/23yem/Web-Sieve.git
    cd Web-Sieve
    ```

2.  **Install Python Dependencies:**
    ```bash
    pip3 install -r requirements.txt
    # Or if on Kali (system-wide):
    sudo pip3 install -r requirements.txt --break-system-packages
    ```

## 💻 Usage

**Note:** This tool requires `sudo` privileges to perform Nmap SYN scans (`-sS`) which are faster and more reliable.

### Single Target
```bash
sudo python3 websieve.py 10.10.10.5
```

### Multiple Targets
Don't have to worry about spaces after comma. I strip away whitespace in my code.
```
sudo python3 websieve.py 10.10.10.5,10.10.10.17
```

### IP Range
```bash
sudo python3 websieve.py 10.10.10.1-50
```

### CIDR Subnet
```bash
sudo python3 websieve.py 192.168.1.0/24
```

## Output

Results are saved in the results/ directory. Each confirmed web service gets its own text file named after the IP and Port:
- results/10.10.10.5_80.txt
- results/10.10.10.5_8080.txt


## ⚠️ Disclaimer
This tool is intended for educational purposes and authorized security testing only. Do not use this tool on networks you do not have explicit permission to audit.
