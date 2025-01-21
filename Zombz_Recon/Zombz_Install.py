#!/usr/bin/python3
import os 
import subprocess 
GREEN = "\033[1;32m" 
MAGENTA = "\033[95m" 
CYAN = "\033[36m" 
BOLD = "\033[1m" 
NORMAL = "\033[0m"

def print_message(color, message): 
    print(f"{color}{BOLD}{message}{NORMAL}")

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print_message("\033[91m", f"Error: {e}")

def install_tools():
    tools = [
        ("DNS Reconnaissance Tools", "sudo apt install -y massdns && sudo git clone https://github.com/nmmapper/dnsdumpster.git && cd dnsdumpster && sudo pip3 install -r requirements.txt && cd .."),
        ("Trufflehog - Git Repo Pilfer", "sudo apt install -y trufflehog"),
        ("Web Gathering Tools", "sudo apt install -y html2text arjun cmseek hakrawler"),
        ("Nuclei", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("Cloud Enumeration Tools", "sudo apt install -y cloud-enum s3scanner"),
        ("Email Harvester", "sudo apt install -y emailharvester"),
        ("Gau", "go install github.com/lc/gau/v2/cmd/gau@latest && export PATH=$PATH:$(go env GOPATH)/bin"),
        ("Screenshot Tool", "sudo apt install -y imagemagick"),
        ("Cleanup", "sudo apt-get -y autoremove")
    ]

    requirements = [ 
        "dnslib", 
        "dnspython", 
        "ipwhois", 
        "netaddr", 
        "requests",
        "requests_futures",
        "requests-html", 
        "shodan", 
        "selenium", 
        "shcheck",
        "mailspoof",
        "dirsearch"
    ]
    
    print_message(GREEN, "!! Hang onto your Butts !!")
    for tool, command in tools:
        print_message(MAGENTA if "Recon" in tool or "Web" in tool or "Cloud" in tool else CYAN, f"Installing {tool}")
        run_command(command)

    print_message(CYAN, "Installing Python Requirements") 
    run_command("sudo pip3 install --ignore-installed " + " ".join(requirements))

if __name__ == "__main__":
    install_tools()
