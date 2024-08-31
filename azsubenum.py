#!/usr/bin/env python3
import dns.resolver
import requests
import argparse
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue

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
    def __init__(self, base, verbose=False, num_threads=1, pf=None, blob_wordlist=None, blob_threads=None):
        self.base = base
        self.verbose = verbose
        self.num_threads = num_threads
        self.pf = pf
        self.blob_wordlist = blob_wordlist
        self.blob_threads = blob_threads
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

    def signal_handler(self, sig, frame):
        print("Ctrl+C detected. Terminating...")
        os._exit(0)

    def azuresubs_enum(self, subdomain):
        try:
            dns.resolver.resolve(subdomain)
            return True
        except dns.resolver.NoAnswer:
            return True
        except:
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
        suffixes = self.sub_lookup.keys()
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
                            print(f"Error: {e}")

                if self.pf:
                    self.process_permutation_file(executor)

                print("\nDiscovered Subdomains:")
                self.display_discovered_subdomains()

                if self.blob_wordlist and self.blob_threads:
                    print("\nChecking for publicly accessible blob containers...")
                    self.brute_force_containers(self.blob_wordlist, self.blob_threads)

        finally:
            executor.shutdown()

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
                            print(f"Error processing word '{word}': {e}")
        except FileNotFoundError:
            print(f"Permutation file '{self.pf}' not found.")
        except Exception as e:
            print(f"Error reading permutation file: {e}")

    def save_blob_subdomains(self):
        try:
            with open('blobs.txt', 'w') as f:
                for subdomain, _ in self.results:
                    if 'blob.core.windows.net' in subdomain:
                        f.write(subdomain + '\n')
            print(f"Blob subdomains saved to blobs.txt")
        except Exception as e:
            print(f"Error saving blob subdomains: {e}")

    def check_blob_container(self, base_url, container_name):
        url = f"{base_url}{container_name}?restype=container&comp=list"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                print(f"[+] Publicly accessible container found: {url}")
                print(f"(To access the Blob Container through the Azure Storage Explorer use the following URL: {base_url}{container_name})")
        except requests.RequestException:
            pass  # Ignore non-200 responses

    def brute_force_containers(self, wordlist, threads):
        try:
            with open(wordlist, 'r') as f:
                container_names = [line.strip() for line in f]

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for subdomain, _ in self.results:
                    if 'blob.core.windows.net' in subdomain:
                        base_url = f"https://{subdomain}/"
                        for container_name in container_names:
                            futures[executor.submit(self.check_blob_container, base_url, container_name)] = container_name

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"Error in thread: {e}")

            # Save discovered blob containers
            self.save_blob_subdomains()

        except KeyboardInterrupt:
            print("\n[!] Script interrupted by user. Exiting...")

    def display_discovered_subdomains(self):
        if self.results:
            longest_subdomain = max(len(result[0]) for result in self.results)
            print(f"{'Subdomain':<{longest_subdomain + 6}}Service")
            print("-" * (longest_subdomain + 25))
            for subdomain, service in self.results:
                print(f"{subdomain:<{longest_subdomain + 6}}{service}")
        else:
            print("No subdomains discovered")

    def run(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        self.do_azsubs_enum()

def main():
    parser = argparse.ArgumentParser(description='Azure Subdomain Enumeration and Blob Container Access Checker')
    parser.add_argument('-b', '--base', required=True, help='Base name to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for concurrent execution')
    parser.add_argument('-p', '--permutations', help='File containing permutations')
    parser.add_argument('--blobsenum', action='store_true', help='Perform blob container enumeration')
    parser.add_argument('--blob-wordlist', help='Path to a custom wordlist file for blob container enumeration')
    parser.add_argument('--blob-threads', type=int, help='Number of threads to use for blob container enumeration')

    args = parser.parse_args()

    if args.blobsenum:
        if not args.blob_wordlist or not args.blob_threads:
            parser.error("--blobsenum requires --blob-wordlist and --blob-threads arguments")
    
    enumerator = AzureSubdomainEnumerator(
        base=args.base,
        verbose=args.verbose,
        num_threads=args.threads,
        pf=args.permutations,
        blob_wordlist=args.blob_wordlist,
        blob_threads=args.blob_threads
    )
    enumerator.run()

if __name__ == "__main__":
    main()
