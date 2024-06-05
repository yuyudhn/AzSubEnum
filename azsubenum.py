#!/usr/bin/env python3
import dns.resolver
import argparse
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class Color:
    green = '\033[92m'
    red = '\033[91m'
    reset = '\033[0m'

class AzureSubdomainEnumerator:
    def __init__(self, base, verbose=False, num_threads=1, pf=None):
        self.base = base
        self.verbose = verbose
        self.num_threads = num_threads
        self.pf = pf
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

    def display_results(self):
        if self.results:
            longest_subdomain = max(len(result[0]) for result in self.results)
            print(f"{'Subdomain':<{longest_subdomain + 6}}Service")
            print("-" * (longest_subdomain + 25))
            for subdomain, service in self.results:
                print(f"{subdomain:<{longest_subdomain + 6}}{service}")
        else:
            print("No results found")

    def run(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        self.do_azsubs_enum()
        self.display_results()

def main():
    parser = argparse.ArgumentParser(description='Azure Subdomain Enumeration')
    parser.add_argument('-b', '--base', required=True, help='Base name to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for concurrent execution')
    parser.add_argument('-p', '--permutations', help='File containing permutations')
    args = parser.parse_args()

    enumerator = AzureSubdomainEnumerator(args.base, verbose=args.verbose, num_threads=args.threads, pf=args.permutations)
    enumerator.run()

if __name__ == "__main__":
    main()
