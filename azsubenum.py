#!/usr/bin/env python3
import dns.resolver
import requests
import argparse
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue
from datetime import datetime
import html
import sys
import logging

class Color:
    green = '\033[92m'
    red = '\033[91m'
    reset = '\033[0m'

class UserInputTimeout:
    def __init__(self, timeout):
        self.timeout = timeout
        self.result = None
        self.input_queue = queue.Queue()

    def _input(self):
        self.result = input()

    def get_input(self):
        input_thread = threading.Thread(target=self._input)
        input_thread.daemon = True
        input_thread.start()
        input_thread.join(timeout=self.timeout)
        if input_thread.is_alive():
            return None  # Timeout occurred
        return self.result

class AzureSubdomainEnumerator:
    def __init__(self, base, verbose=False, num_threads=1, pf=None, bw=None, bt=None):
        self.base = base
        self.verbose = verbose
        self.num_threads = num_threads
        self.pf = pf
        self.bw = bw
        self.bt = bt
        self.sub_lookup = {
            'onmicrosoft.com': 'Microsoft Hosted Domain',
            'scm.azurewebsites.net': 'App Services - Management',
            'azurewebsites.net': 'App Services',
            'p.azurewebsites.net': 'App Services',
            'cloudapp.net': 'App Services',
            'file.core.windows.net': 'Storage Accounts - Files',
            'blob.core.windows.net': 'Storage Accounts - Blobs',
            'queue.core.windows.net': 'Storage Accounts - Queues',
            'table.core.windows.net': 'Storage Accounts - Tables',
            'mail.protection.outlook.com': 'Email',
            'sharepoint.com': 'SharePoint',
            'redis.cache.windows.net': 'Databases-Redis',
            'documents.azure.com': 'Databases-Cosmos DB',
            'database.windows.net': 'Databases-MSSQL',
            'vault.azure.net': 'Key Vaults',
            'azureedge.net': 'CDN',
            'search.windows.net': 'Search Appliance',
            'azure-api.net': 'API Services',
            'azurecr.io': 'Azure Container Registry'
        }
        self.results = set()
        self.results_lock = threading.Lock()
        self.accessible_blob_containers = []
        self.blobs_lock = threading.Lock()
        self.blob_contents = {}  # Dictionary to store blob contents by container URL

    def signal_handler(self, sig, frame):
        print("Ctrl+C detected. Terminating...")
        sys.exit(0)

    def azuresubs_enum(self, subdomain):
        try:
            dns.resolver.resolve(subdomain)
            return True
        except dns.resolver.NoAnswer:
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception as e:
            if self.verbose:
                print(f"{Color.red}DNS resolution error for {subdomain}: {e}{Color.reset}")
            return False

    def generate_permutations(self, base, word, suffix):
        return [
            f"{base}-{word}.{suffix}", f"{word}-{base}.{suffix}",
            f"{word}{base}.{suffix}", f"{base}{word}.{suffix}"
        ]

    def sub_permutations(self, base, word, suffix):
        running_list = []
        combinations = self.generate_permutations(base, word, suffix)
        for lookup in combinations:
            if self.azuresubs_enum(lookup):
                running_list.append((lookup, self.sub_lookup[suffix]))
                if self.verbose:
                    print(f"{Color.green}Subdomain {lookup} found{Color.reset}")
            elif self.verbose:
                print(f"Subdomain {lookup} not found")
        return running_list

    def sub_pfile(self, word):
        for suffix in self.sub_lookup.keys():
            self.results.update(self.sub_permutations(self.base, word, suffix))

    def do_azsubs_enum(self):
        try:
            with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                future_to_lookup = {
                    executor.submit(self.azuresubs_enum, f"{self.base}.{suffix}"): (f"{self.base}.{suffix}", service)
                    for suffix, service in self.sub_lookup.items()
                }
                for future in as_completed(future_to_lookup):
                    try:
                        result = future.result()
                        subdomain, service = future_to_lookup[future]
                        with self.results_lock:
                            if result:
                                self.results.add((subdomain, service))
                                if self.verbose:
                                    print(f"{Color.green}Subdomain {subdomain} found{Color.reset}")
                            elif self.verbose:
                                print(f"Subdomain {subdomain} not found")
                    except Exception as e:
                        if self.verbose:
                            print(f"{Color.red}Error: {e}{Color.reset}")

                if self.pf:
                    self.process_permutation_file(executor)

                print("\nDiscovered Subdomains:")
                self.display_discovered_subdomains()

                if self.bw and self.bt:
                    print("\nChecking for publicly accessible blob containers...")
                    self.brute_force_containers(self.bw, self.bt)

        except KeyboardInterrupt:
            print("\n[!] Script interrupted by user. Exiting...")

    def process_permutation_file(self, executor):
        try:
            with open(self.pf, 'r') as pfl:
                permutation_content = pfl.read().splitlines()
                future_to_word = {
                    executor.submit(self.sub_pfile, word): word
                    for word in permutation_content
                }
                for future in as_completed(future_to_word):
                    word = future_to_word[future]
                    try:
                        future.result()
                    except Exception as e:
                        if self.verbose:
                            print(f"{Color.red}Error processing word '{word}': {e}{Color.reset}")
        except FileNotFoundError:
            print(f"{Color.red}Permutation file '{self.pf}' not found.{Color.reset}")
        except Exception as e:
            print(f"{Color.red}Error reading permutation file: {e}{Color.reset}")

    def check_blob_container(self, base_url, container_name):
        url = f"{base_url}{container_name}?restype=container&comp=list"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                accessible_url = f"{base_url}{container_name}"
                with self.blobs_lock:
                    self.accessible_blob_containers.append(accessible_url)
                    
                print(f"{Color.green}[+] Publicly accessible container found: {url}{Color.reset}")
                print(f"    (To access the Blob Container through the Azure Storage Explorer use the following URL: {accessible_url})")
                
                # Parse the XML content and extract <Name> tags
                self.display_blob_contents(response.content, accessible_url)
                
            else:
                if self.verbose:
                    print(f"{Color.red}[-] Container {container_name} is not accessible or doesn't exist.{Color.reset}")

        except requests.RequestException as e:
            if self.verbose:
                print(f"{Color.red}Request error: {e}{Color.reset}")
            pass  # Ignore non-200 responses and connection errors

    def display_blob_contents(self, xml_content, container_url):
        try:
            from xml.etree import ElementTree as ET
            root = ET.fromstring(xml_content)
            blob_names = []
            print(f"{Color.green}[+] Blob contents:{Color.reset}")
            for blob in root.findall(".//Blob"):
                name = blob.find("Name")
                if name is not None:
                    blob_names.append(name.text)
                    print(f"    - {name.text}")
            
            # Store blob names in the dictionary
            if blob_names:
                with self.blobs_lock:
                    self.blob_contents[container_url] = blob_names

        except ET.ParseError as e:
            print(f"{Color.red}Error parsing XML: {e}{Color.reset}")

    def brute_force_containers(self, wordlist, threads):
        try:
            # Read container names from the wordlist
            with open(wordlist, 'r') as f:
                container_names = [line.strip() for line in f]

            # Prepare a list of tasks for the executor
            tasks = []

            with ThreadPoolExecutor(max_workers=threads) as executor:
                # For each discovered blob subdomain, create tasks for each container name
                for subdomain, _ in self.results:
                    if 'blob.core.windows.net' in subdomain:
                        base_url = f"https://{subdomain}/"
                        for container_name in container_names:
                            tasks.append((base_url, container_name))

                # Use ThreadPoolExecutor to check all blob containers in parallel
                futures = {executor.submit(self.check_blob_container, base_url, container_name): (base_url, container_name)
                           for base_url, container_name in tasks}

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"{Color.red}Error in thread: {e}{Color.reset}")

        except FileNotFoundError:
            print(f"{Color.red}Blob wordlist file '{wordlist}' not found.{Color.reset}")
        except KeyboardInterrupt:
            print("\n[!] Script interrupted by user. Exiting...")
        except Exception as e:
            print(f"{Color.red}Error in brute_force_containers: {e}{Color.reset}")

    def display_discovered_subdomains(self):
        if self.results:
            # Create a dictionary to group subdomains by service
            service_dict = {}
            for subdomain, service in self.results:
                if service not in service_dict:
                    service_dict[service] = []
                service_dict[service].append(subdomain)

            # Display the results by service category
            for service, subdomains in service_dict.items():
                print(f"\n{service}:")
                longest_subdomain = max(len(subdomain) for subdomain in subdomains)
                # Removed the "Subdomain" header
                print("-" * (longest_subdomain + 6))
                for subdomain in subdomains:
                    print(f"{subdomain:<{longest_subdomain + 6}}")
        else:
            print("No subdomains discovered")

    def generate_html_report(self):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Azure Subdomain Enumeration Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #2E4053; }}
                    h2 {{ color: #2874A6; }}
                    table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; }}
                    th {{ background-color: #f2f2f2; text-align: left; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .timestamp {{ font-size: 0.9em; color: #555; }}
                </style>
            </head>
            <body>
                <h1>Azure Subdomain Enumeration Report</h1>
                <p class="timestamp">Generated on: {timestamp}</p>
                <h2>Discovered Subdomains</h2>
            """

            if self.results:
                service_dict = {}
                for subdomain, service in self.results:
                    if service not in service_dict:
                        service_dict[service] = []
                    service_dict[service].append(subdomain)

                for service, subdomains in service_dict.items():
                    html_content += f"<h3>{html.escape(service)}</h3>\n"
                    html_content += """
                    <table>
                        <tr>
                            <th>Subdomain</th>
                        </tr>
                    """
                    for subdomain in subdomains:
                        html_content += f"""
                        <tr>
                            <td>{html.escape(subdomain)}</td>
                        </tr>
                        """
                    html_content += "</table>\n"

            else:
                html_content += "<p>No subdomains discovered.</p>"

            if self.bw and self.bt:
                html_content += "<h2>Accessible Blob Containers</h2>\n"
                if self.accessible_blob_containers:
                    html_content += """
                    <table>
                        <tr>
                            <th>Blob Container URL</th>
                            <th>Contained Blobs</th>
                        </tr>
                    """
                    for container_url in self.accessible_blob_containers:
                        html_content += f"""
                        <tr>
                            <td>{html.escape(container_url)}</td>
                            <td>
                                <ul>
                        """
                        # List the blobs for this container
                        blob_names = self.blob_contents.get(container_url, [])
                        for blob_name in blob_names:
                            html_content += f"<li>{html.escape(blob_name)}</li>"
                        html_content += """
                                </ul>
                            </td>
                        </tr>
                        """
                    html_content += "</table>\n"
                else:
                    html_content += "<p>No publicly accessible blob containers found.</p>"

            html_content += """
            </body>
            </html>
            """

            with open('report.html', 'w') as report_file:
                report_file.write(html_content)

            logging.info("HTML report generated: report.html")

        except Exception as e:
            logging.error(f"Error generating HTML report: {e}")

    def run(self):
        # Set up signal handler for graceful termination
        signal.signal(signal.SIGINT, self.signal_handler)
        # Perform enumeration
        self.do_azsubs_enum()
        # Generate HTML report
        self.generate_html_report()

def main():
    parser = argparse.ArgumentParser(description='Azure Subdomain Enumeration and Blob Container Access Checker')
    parser.add_argument('-b', '--base', required=True, help='Base name to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for concurrent execution')
    parser.add_argument('-p', '--permutations', help='File containing permutations')
    parser.add_argument('--blobsenum', action='store_true', help='Perform blob container enumeration')
    parser.add_argument('-bw', help='Path to a custom wordlist file for blob container enumeration')
    parser.add_argument('-bt', type=int, help='Number of threads to use for blob container enumeration')

    args = parser.parse_args()

    # Default blob wordlist to permutations.txt if not provided
    bw = args.bw if args.bw else 'permutations.txt'

    if args.blobsenum:
        if not bw or not args.bt:
            parser.error("--blobsenum requires a blob wordlist and --blob-threads argument")

    enumerator = AzureSubdomainEnumerator(
        base=args.base,
        verbose=args.verbose,
        num_threads=args.threads,
        pf=args.permutations,
        bw=bw,  # Pass the determined wordlist
        bt=args.bt
    )
    enumerator.run()

if __name__ == "__main__":
    main()
