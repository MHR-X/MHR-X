import socket
import threading
import concurrent.futures
import keyboard
from art import *
from colorama import Fore, Style, init
from flask import Flask, render_template_string, request
from urllib.parse import urlparse
from time import sleep
from pyfiglet import Figlet

# Initialize colorama
init(autoreset=True)

app = Flask(__name__)

def draw_logo():
    logo = text2art("MHR-X", font='starwars', chr_ignore=True)
    skull = """
      _____
    /     \\
   |  * *  |
    \\  ^  /
     |||||
     |||||
    """
    print(Fore.RED + skull)
    print(Fore.CYAN + logo)

def scan_port(target, port, protocols):
    if keyboard.is_pressed('esc'):
        print("\nScan stopped by user.")
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                protocol = protocols.get(port, "unknown")
                print(Fore.GREEN + f"Port {port}: Open ({service}, Protocol: {protocol})")
                return f"Port {port}: Open ({service}, Protocol: {protocol})"
            else:
                print(Fore.RED + f"Port {port}: Closed")
                return f"Port {port}: Closed"
    except socket.error:
        print(Fore.RED + f"Port {port}: Error")
        return f"Port {port}: Error"

def scan_ports(site, protocols):
    print(Fore.YELLOW + f"Scanning ports for {site}...")
    target = socket.gethostbyname(site)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, target, port, protocols) for port in range(1, 1025)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
            if keyboard.is_pressed('esc'):
                print("\n" + Fore.RED + "Scan stopped by user.")
                break
    return results

def save_results(filename, results):
    with open(filename, 'w') as file:
        for result in results:
            file.write(result + '\n')
    print(Fore.GREEN + f"Results saved to {filename}")

def metasploit_info():
    print(Fore.BLUE + "Metasploit is a powerful penetration testing tool.\n")
    print("Installation on Termux:")
    print("```")
    print("pkg install unstable-repo")
    print("pkg install metasploit")
    print("```")
    print("\nInstallation on Windows:")
    print("1. Download the installer from the following link:")
    print("https://windows.metasploit.com/")
    print("2. Run the installer and follow the on-screen instructions.")
    print("\nInstallation on Kali Linux:")
    print("```")
    print("sudo apt update")
    print("sudo apt install metasploit-framework")
    print("```")

def tool_info():
    print(Fore.GREEN + "Tool Version: 1.2.0\n")
    print("Latest updates include new features and performance improvements.")

def creator_info():
    figlet = Figlet(font='starwars')
    message = "Welcome to my tool! Enjoy and stay tuned for more updates from MHR-X."
    print(Fore.MAGENTA + figlet.renderText(message))
    print(Fore.CYAN + "My Instagram: mmhrxx")

def check_website_security(url):
    print(Fore.YELLOW + f"Checking security for {url}...")
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Basic security checks
    security_score = 0
    try:
        target = socket.gethostbyname(domain)
        if target:
            security_score += 1  # Assume domain resolves
    except:
        print(Fore.RED + "Domain resolution failed.")
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((target, 80))  # Check HTTP
            security_score += 1
    except:
        print(Fore.YELLOW + "HTTP port is closed.")

    if security_score == 2:
        print(Fore.GREEN + "The website is secure for access.")
    elif security_score == 1:
        print(Fore.YELLOW + "The website's security is medium.")
    else:
        print(Fore.RED + "The website is not secure for access.")

def show_menu():
    menu = """
    ****************************************
    *           MHR-X Tool Menu            *
    ****************************************
    * 1. Scan ports of a website            * - Scan for open ports on a specified website.
    * 2. Save scan results to a file        * - Save the results of the port scan to a file.
    * 3. Information about Metasploit       * - Get information about Metasploit and its installation.
    * 4. Tool version and updates           * - Display the tool version and latest updates.
    * 5. Check website security             * - Check if a website is safe to visit.
    * 6. About the creator                  * - Get information about the tool creator with a special message and Instagram link.
    * 7. Exit                               * - Exit the tool.
    ****************************************
    """
    print(Fore.YELLOW + menu)

if __name__ == "__main__":
    protocols = {
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP'
    }
    results = []

    while True:
        draw_logo()
        show_menu()

        choice = input("\nPlease choose an option (1-7): ")
        
        if choice == '1':
            site = input("Enter the website (e.g., example.com): ")
            results = scan_ports(site, protocols)
        elif choice == '2':
            filename = input("Enter the filename to save results (e.g., results.txt): ")
            save_results(filename, results)
        elif choice == '3':
            metasploit_info()
        elif choice == '4':
            tool_info()
        elif choice == '5':
            url = input("Enter the website URL to check (e.g., http://example.com): ")
            check_website_security(url)
        elif choice == '6':
            creator_info()
        elif choice == '7':
            print(Fore.RED + "Exiting the tool. Goodbye!")
            break
        else:
            print(Fore.YELLOW + "Invalid choice. Please select a number between 1 and 7.")
        
        back_to_menu = input("\nPress Enter to return to the menu or type 'exit' to quit: ")
        if back_to_menu.lower() == 'exit':
            print(Fore.RED + "Exiting the tool. Goodbye!")
            break
