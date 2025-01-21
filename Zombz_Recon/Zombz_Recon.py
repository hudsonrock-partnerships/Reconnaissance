#!/usr/bin/python3

import os
import ipaddress
import subprocess
import socket
import sys
import logging
import time
from datetime import datetime

# Constants
INSTALL_DIR = "/opt/tools/Zombz_Recon"
dns_dictionary = "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"

# Create Zombz_Recon directory if it doesn't exist
if not os.path.exists(INSTALL_DIR):
    os.makedirs(INSTALL_DIR)

# Colors
RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, BOLD, NORMAL = ( 
    "\033[31m", "\033[1;32m", "\033[33m", "\033[34m", "\033[95m", "\033[36m", "\033[1m", "\033[0m" 
)

def print_art(color, ascii_art):
    print(f"{color}{BOLD}{ascii_art}{NORMAL}")

def target(target):
    target = target.strip()
    if not target:
        print(f"{RED}[!] No input provided. {NORMAL}")
        return None
    
    # Check if target is a file containing a list of assets
    if os.path.isfile(target):
        with open(target, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
        return targets
    
    # Check if target is a valid IP address
    try:
        ip_obj = ipaddress.ip_address(target)
        print(f"{GREEN}[+] Valid IP Address: {target}{NORMAL}")
        return ip_obj
    except ValueError:
        pass
    
    # Check if target is a valid subnet
    try:
        subnet_obj = ipaddress.ip_network(target, strict=False)
        print(f"{GREEN}[+] Valid Subnet: {target}{NORMAL}")
        return subnet_obj
    except ValueError:
        pass
    
    # Check if target is a valid domain name or URL
    try:
        resolved_ip = socket.gethostbyname(target)
        print(f"{GREEN}[+] Resolved Domain/URL: {target} -> {resolved_ip}{NORMAL}")
        return target
    except socket.gaierror:
        print(f"{RED}[!] Invalid Domain/URL: {target}{NORMAL}")
        return None

# Configure logging
logging.basicConfig(filename='/opt/tools/Zombz_Recon/recon.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command, master_file, shell=False):
    try:
        logging.info(f"Running command: {' '.join(command) if not shell else command}")
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=shell, timeout=300).stdout
        with open(master_file, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n--- {timestamp} ---\n")
            f.write(f"Command: {' '.join(command) if not shell else command}\n")
            f.write(result)
        logging.info(f"Command completed: {' '.join(command) if not shell else command}")
        print(result)
    except subprocess.TimeoutExpired:
        logging.error(f"Command '{' '.join(command) if not shell else command}' timed out.")
        print(f"[!] Command '{' '.join(command) if not shell else command}' timed out.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{' '.join(command) if not shell else command}' failed with error code {e.returncode}. Error message: {e.stderr}")
        print(f"[!] Command '{' '.join(command) if not shell else command}' failed with error code {e.returncode}. Error message: {e.stderr}")

############### PASSIVE RECON ################
def passive_recon(target):
    print(f"{BOLD}{GREEN}[*] STARTING PASSIVE RECON{NORMAL}\n")
    print(f"{BOLD}{GREEN}[*] TARGET:\n {YELLOW} {target} {NORMAL}\n")
    master_file = '/opt/tools/Zombz_Recon/passive_recon_output.txt'

    run_command(['ping', '-c', '1', '-W', '1', target], master_file)
    run_command(['whois', target], master_file)
    run_command(['nslookup', target], master_file)
    run_command(['nslookup', '-type=TXT', target], master_file)
    run_command(['dnsrecon', '-d', target], master_file)
    run_command(['dnsenum', '--enum', target], master_file, timeout=20)
    run_command(['sublist3r', '-d', target], master_file)
    run_command(['cloud_enum', '-k', target], master_file, timeout=20)
    #run_command(['python3', 'dnsdumpster.py', '-d', target], master_file)
    run_command(['mailspoof', '-d', target], master_file)
    run_command(['whatweb', target], master_file)
    run_command(['sslscan', '-t', target], master_file)
    run_command(['shcheck.py', f'https://{target}', '-i', '-x'], master_file)
    run_command(['cmseek.py', '-v', '-u', target, '--follow-redirect'], master_file)
    run_command(['sudo', 'theHarvester', '-d', target, '-b', 'all', '-l', '500'], master_file)
    
############### ACTIVE RECON #################
def active_recon(target):
    print(f"\n{BOLD}{GREEN}[*] STARTING ACTIVE RECON{NORMAL}\n")
    print(f"{BOLD}{GREEN}[*] TARGET:{YELLOW} {target} {NORMAL}\n")
    master_file = '/opt/tools/Zombz_Recon/active_recon_output.txt'

    run_command(['nmap', '-p-', '--open', '-T5', '-v', '-n', target], master_file)
    run_command(['arp-scan', '-l'], master_file)
    run_command(['dnsenum', target], master_file)
    run_command(['dnsrecon', '-d', target, '-t', 'axfr'], master_file)
    run_command(['eyewitness', '-x', '/*.nessus'], master_file)

################ WEB RECON ###################
def web_recon(target):
    print(f"\n{BOLD}{GREEN}[*] STARTING WEB RECON{NORMAL}\n")
    print(f"{BOLD}{GREEN}[*] TARGET:{YELLOW} {target} {NORMAL}\n")
    master_file = '/opt/tools/Zombz_Recon/web_recon_output.txt'
        
    #run_command(['hakrawler'], master_file, shell=True)
    #run_command(['gau', target], master_file)
    run_command(['sudo', 'arjun', '-u', target], master_file)
    run_command(['dirsearch', '-u', target], master_file)
    run_command(['nuclei', '-u', target, '-t', '/usr/share/nuclei-templates/', '-severity', 'low,medium,high,critical', '-silent', '-o'], master_file)

################ FULL RECON ##################
def full_recon(target):
    print(f"\n{BOLD}{GREEN}[*] STARTING FULL RECON{NORMAL}\n")
    passive_recon(target)
    active_recon(target)
    web_recon(target)

############### HELP SECTION #################
def parse_arguments():
    import argparse

    parser = argparse.ArgumentParser(description="Zombz_Recon v2.0 - All-in-One Reconnaissance Tool")
    parser.add_argument('-t', '--target', help="Target domain or IP address")
    parser.add_argument('-l', '--list', help="List of targets")
    parser.add_argument('-p', '--passive', action='store_true', help="Perform passive reconnaissance")
    parser.add_argument('-a', '--active', action='store_true', help="Perform active reconnaissance")
    parser.add_argument('-w', '--web', action='store_true', help="Perform web reconnaissance")
    parser.add_argument('-f', '--full', action='store_true', help="Perform full reconnaissance")

    args = parser.parse_args()

    if not any([args.target, args.list]):
        parser.print_help()
        sys.exit(0)
    return args

def main():
    args = parse_arguments()
    print_art(GREEN, ascii_art= '''
                                                                                                          
@@@@@@@@   @@@@@@   @@@@@@@@@@   @@@@@@@   @@@@@@@@     @@@@@@@   @@@@@@@@   @@@@@@@   @@@@@@   @@@  @@@  
@@@@@@@@  @@@@@@@@  @@@@@@@@@@@  @@@@@@@@  @@@@@@@@     @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@ @@@  
     @@!  @@!  @@@  @@! @@! @@!  @@!  @@@       @@!     @@!  @@@  @@!       !@@       @@!  @@@  @@!@!@@@  
    !@!   !@!  @!@  !@! !@! !@!  !@   @!@      !@!      !@!  @!@  !@!       !@!       !@!  @!@  !@!!@!@!  
   @!!    @!@  !@!  @!! !!@ @!@  @!@!@!@      @!!       @!@!!@!   @!!!:!    !@!       @!@  !@!  @!@ !!@!  
  !!!     !@!  !!!  !@!   ! !@!  !!!@!!!!    !!!        !!@!@!    !!!!!:    !!!       !@!  !!!  !@!  !!!  
 !!:      !!:  !!!  !!:     !!:  !!:  !!!   !!:         !!: :!!   !!:       :!!       !!:  !!!  !!:  !!!  
:!:       :!:  !:!  :!:     :!:  :!:  !:!  :!:          :!:  !:!  :!:       :!:       :!:  !:!  :!:  !:!  
 :: ::::  ::::: ::  :::     ::    :: ::::   :: ::::     ::   :::   :: ::::   ::: :::  ::::: ::   ::   ::  
: :: : :   : :  :    :      :    :: : ::   : :: : :      :   : :  : :: ::    :: :: :   : :  :   ::    :   
                                                                                                          
            ''')

    if args.target:
        target_name = target(args.target)
        if not target_name:
            sys.exit(1)
        if args.passive:
            passive_recon(target_name)
        if args.active:
            active_recon(target_name)
        if args.web:
            web_recon(target_name)
        if args.full:
            full_recon(target_name)
    elif args.list:
        with open(args.list, 'r') as file:
            for target_item in file:
                target_name = target_item.strip()
                if not target_name:
                    continue
                target_name = target(target_name)
                if not target_name:
                    continue
                if args.passive:
                    passive_recon(target_name)
                if args.active:
                    active_recon(target_name)
                if args.web:
                    web_recon(target_name)
                if args.full:
                    full_recon(target_name)

if __name__ == "__main__":
    main()