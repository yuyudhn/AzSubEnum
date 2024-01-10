#! /usr/bin/env python3
import dns.resolver
import argparse
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

# Color definiton
class color:
    green = '\033[92m'
    red = '\033[91m'
    reset = '\033[0m'

# Signal handler
def signal_handler(sig, frame):
    print("Ctrl+C detected. Terminating...")
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)


def azuresubs_enum(subdomain):
    try:
        dns.resolver.resolve(subdomain)
        return True
    except dns.resolver.NoAnswer:
        return True
    except:
        pass

def sub_permutations(base, word, suffix, sub_lookup, verbose=False):
    running_list = []

    combinations = [
        (f"{base}-{word}.{suffix}", f"{word}-{base}.{suffix}"),
        (f"{word}{base}.{suffix}", f"{base}{word}.{suffix}")
    ]

    for combination in combinations:
        for lookup in combination:
            if azuresubs_enum(lookup):
                running_list.append((lookup, sub_lookup[suffix]))
                if verbose:
                    print(f"{color.green}Subdomain {lookup} found{color.reset}")
            else:
                if verbose:
                    print(f"Subdomain {lookup} not found")

    return running_list

def do_azsubs_enum(base, verbose=False, num_threads=1, pf=None):
    sub_lookup = {
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

    results = set()

    suffixes = sub_lookup.keys()

    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            future_to_lookup = {}
            for suffix in suffixes:
                lookup = f"{base}.{suffix}"
                future_to_lookup[executor.submit(azuresubs_enum, lookup)] = (lookup, sub_lookup[suffix])

            for future in as_completed(future_to_lookup):
                try:
                    result = future.result()
                    subdomain, service = future_to_lookup[future]
                    if result:
                        results.add((subdomain, service))
                        if verbose:
                            print(f"{color.green}Subdomain {subdomain} found{color.reset}")
                    else:
                        if verbose:
                            print(f"Subdomain {subdomain} not found")
                except Exception as e:
                    if verbose:
                        print(f"Error: {e}")
            if pf:
                try:
                    with open(pf, 'r') as pfl:
                        permutation_content = pfl.read().splitlines()
                        for word in permutation_content:
                            for suffix in sub_lookup.keys():
                                results.update(sub_permutations(base, word, suffix, sub_lookup, verbose=verbose))
                except FileNotFoundError:
                    print(f"Permutation file '{pf}' not found.")
                except Exception as e:
                    print(f"Error reading permutation file: {e}")
    finally:
        executor.shutdown()

    return results

def main():
    parser = argparse.ArgumentParser(description='Azure Subdomain Enumeration')
    parser.add_argument('-b', '--base', dest='base', required=True, help='Base name to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for concurrent execution')
    parser.add_argument('-p', '--permutations', dest='permutations', help='File containing permutations')
    args = parser.parse_args()

    base_name = args.base
    verbose = args.verbose
    num_threads = args.threads
    pf = args.permutations

    if pf:
        result_set = do_azsubs_enum(base_name, verbose=verbose, num_threads=num_threads, pf=pf)
    else:
        result_set = do_azsubs_enum(base_name, verbose=verbose, num_threads=num_threads)
    
    if result_set:
        longest_subdomain = max(len(result[0]) for result in result_set)
        print(f"{'Subdomain':<{longest_subdomain + 6}}Service")
        print("-" * (longest_subdomain + 25))
        for result in result_set:
            print(f"{result[0]:<{longest_subdomain + 6}}{result[1]}")
    else:
        print("No results found")

if __name__ == "__main__":
    main()
