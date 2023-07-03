import argparse
import requests
import geoip2.database
from colorama import Fore
from tabulate import tabulate
import socket
import sys
import ctypes

def set_console_title(title):
    ctypes.windll.kernel32.SetConsoleTitleW(title)

#title
set_console_title("Cam Scanner CLI")

def main():
    command = input("[+] Enter command: ")

    if command == 'help' or command == '-h':
        print(f"{Fore.RED} use {Fore.RESET} - type help/-h use for more information about the command.")
        print(f"{Fore.RED} vuln {Fore.RESET} - type help/-h vuln for more information about the command.")
        if 'vuln' in sys.argv:
            print("This command function is to scan for the weak spots of the IP camera that you indicate.")
            print(Fore.RED + "--all" + Fore.RESET + " Scan for any possible weak spots on the address.")
        elif 'use' in sys.argv:
            print("use is to change the default of 192.168.1.100/192.168.1.001 to your need of address to scan.")
        else:
            print("Invalid command.")
        return command

    if command == 'vuln':
        if '--all' in sys.argv:
            # Analyze all vulnerabilities
            start_ip = 1
            end_ip = 10
            default_url = 'http://192.168.0.1/'  # Replace with the default address URL
            custom_url = input("[+ Custom] Enter the address and port: ")  # Replace with the custom address URL
            scan_ip_cameras(start_ip, end_ip, default_url, custom_url)
        elif '--cridential' in sys.argv or 'cridential' in sys.argv:
            camera_ip = "192.168.0.1"  # Replace with the camera IP address
            username = "admin"  # Replace with the username
            password = "admin"  # Replace with the password
            check_weak_credentials(camera_ip, username, password)
        elif '--firmware' in sys.argv or 'firmware' in sys.argv:
            camera_ip = "192.168.0.1"  # Replace with the camera IP address
            check_outdated_firmware(camera_ip)
        elif '--secure' in sys.argv or 'encryption' in sys.argv:
            camera_ip = "192.168.0.1"  # Replace with the camera IP address
            check_encryption(camera_ip)
        elif '--rce' in sys.argv or 'remote_access' in sys.argv:
            camera_ip = "192.168.0.1"  # Replace with the camera IP address
            check_remote_access(camera_ip)
        elif 'service' in sys.argv or 'service_cridential' in sys.argv:
            camera_ip = "192.168.0.1"  # Replace with the camera IP address
            start_port = 1  # Replace with the starting port number
            end_port = 100  # Replace with the ending port number
            scan_ports(camera_ip, start_port, end_port)
        else:
            print("Invalid command.")
    elif command == 'use':
        address = input("[+] Enter an address: ")
        port = None
        if '-p' in sys.argv and len(sys.argv) > sys.argv.index('-p') + 1:
            port = int(sys.argv[sys.argv.index('-p') + 1])
        run_custom_scan(address, port)
    elif command == 'default':
        run_default_scan()
    else:
        print("Invalid command.")

def scan_ip_cameras(start_ip, end_ip, default_url, custom_url):
        # Implement the vulnerability scanning logic for IP cameras
    pass

def check_weak_credentials(camera_ip, username, password):
    url = f"http://{camera_ip}/"
    response = requests.get(url, auth=(username, password))
    if response.status_code == 200:
        print("Weak or default credentials detected!")
    else:
        print("Credentials are secure.")

def check_outdated_firmware(camera_ip):
    url = f"http://{camera_ip}/firmware"
    response = requests.get(url)
    current_version = response.text  # Assuming the response contains the firmware version
    vulnerable_versions = ["1.0", "1.1", "1.2"]  # List of known vulnerable versions

    if current_version in vulnerable_versions:
        print("Outdated firmware detected!")
    else:
        print("Firmware is up to date.")

def check_encryption(camera_ip):
    url = f"http://{camera_ip}/"
    response = requests.get(url)
    
    if response.url.startswith("https"):
        print("Communication is encrypted.")
    else:
        print("Unencrypted communication detected!")

def check_remote_access(camera_ip):
    url = f"http://{camera_ip}/settings"
    response = requests.get(url)

    if "telnet_enabled" in response.text or "ftp_enabled" in response.text:
        print("Insecure remote access detected!")
    else:
        print("Remote access is secure.")

def scan_ports(camera_ip, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((camera_ip, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    if open_ports:
        print("Open ports detected:", open_ports)
    else:
        print("No open ports found.")

def run_custom_scan(address, port):
    if 'use vuln' in sys.argv:
        if '--all' in sys.argv:
            # Analyze all vulnerabilities
            start_ip = 1
            end_ip = 10
            default_url = f'http://{address}/'  # Replace with the default address URL
            custom_url = f'{input("[+] Which protocol it uses?: ")}://{input("[+ Custom] Enter the address and port: ")}'  # Replace with the custom address URL
            scan_ip_cameras(start_ip, end_ip, default_url, custom_url)
        elif 'use vuln --cridential' in sys.argv or 'use vuln --custom cridential' in sys.argv:
            camera_ip = address
            username = "admin"  # Replace with the username
            password = "admin"  # Replace with the password
            check_weak_credentials(camera_ip, username, password)
        elif 'use vuln --firmware' in sys.argv or 'use vuln --custom firmware' in sys.argv:
            camera_ip = address
            check_outdated_firmware(camera_ip)
        elif 'use vuln --secure' in sys.argv or 'use vuln --custom encryption' in sys.argv:
            camera_ip = address
            check_encryption(camera_ip)
        elif 'use vuln --rce' in sys.argv or 'use vuln --custom remote_access' in sys.argv:
            camera_ip = address
            check_remote_access(camera_ip)
        elif 'use vuln --service' in sys.argv or 'use vuln --custom service_cridential' in sys.argv:
            camera_ip = address
            start_port = int(input("[+] Minimum port or start port at: "))
            end_port = int(input("[+] Max port or where to stop port scanning: "))  # Replace with the ending port number
            scan_ports(camera_ip, start_port, end_port)
        else:
            print("Invalid command.")
    # Implement custom scanning

def run_default_scan():
    # Implement default scanning logic
    pass

if __name__ == '__main__':
    main()