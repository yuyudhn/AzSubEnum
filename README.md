# AzSubEnum - Azure Service Subdomain Enumeration
AzSubEnum is a specialized subdomain enumeration tool tailored for Azure services. This tool is designed to meticulously search and identify subdomains associated with various Azure services. Through a combination of techniques and queries, AzSubEnum delves into the Azure domain structure, systematically probing and collecting subdomains related to a diverse range of Azure services.

## How it works?
AzSubEnum operates by leveraging DNS resolution techniques and systematic permutation methods to unveil subdomains associated with Azure services such as Azure App Services, Storage Accounts, Azure Databases (including MSSQL, Cosmos DB, and Redis), Key Vaults, CDN, Email, SharePoint, Azure Container Registry, and more. Its functionality extends to comprehensively scanning different Azure service domains to identify associated subdomains.

With this tool, users can conduct thorough subdomain enumeration within Azure environments, aiding security professionals, researchers, and administrators in gaining insights into the expansive landscape of Azure services and their corresponding subdomains.

## Why i create this?
During my learning journey on Azure AD exploitation, I discovered that the Azure subdomain tool, [Invoke-EnumerateAzureSubDomains](https://github.com/NetSPI/MicroBurst/blob/master/Misc/Invoke-EnumerateAzureSubDomains.ps1) from NetSPI, was unable to run on my Debian PowerShell. Consequently, I created a crude implementation of that tool in Python.

## Added functionality
1. Discovered subdomains are now displayed by **Service** category.
2. AzSubEnum has now the option to perform enumeration for Blob Containers that allow Anonymous access and discover Blobs inside them. This can be done using the `--blobsenum` optional argument. The default wordlist used is `permutations.txt` that is already caonteined in the repository. Users can define their own custom wordlist using the `-bw` option, as well as use threaded fuzzing with the `-bt` option to speed up the enumeration.
3. AzSubEnum will also generate a simple HTML report with the findings.

## Usage
```
PS C:\AzureTools\AzSubEnum> python.exe .\azsubenum.py --help
usage: azsubenum.py [-h] -b BASE [-v] [-t THREADS] [-p PERMUTATIONS] [--blobsenum] [-bw BW] [-bt BT]

Azure Subdomain Enumeration and Blob Container Access Checker

options:
  -h, --help            show this help message and exit
  -b BASE, --base BASE  Base name to use
  -v, --verbose         Show verbose output
  -t THREADS, --threads THREADS
                        Number of threads for concurrent execution
  -p PERMUTATIONS, --permutations PERMUTATIONS
                        File containing permutations
  --blobsenum           Perform blob container enumeration
  -bw BW                Path to a custom wordlist file for blob container enumeration
  -bt BT                Number of threads to use for blob container enumeration
```

Basic enumeration:
```
python3 azsubenum.py -b retailcorp --thread 10
```

Using permutation wordlists:
```
python3 azsubenum.py -b retailcorp --thread 10 --permutation permutations.txt
```

With verbose output:
```
python3 azsubenum.py -b retailcorp --thread 10 --permutation permutations.txt --verbose
```

Basic enumeration with Blob Containers enumeration using the default Blob Container wordlist:
```
python3 azsubenum.py -b retailcorp --thread 10 --permutation permutations.txt --blobsenum -bt 10
```

Basic enumeration with Blob Containers enumeration using a custom Blob Container wordlist
```
python3 azsubenum.py -b retailcorp --thread 10 --permutation permutations.txt --blobsenum -bw yourcustomwordlist.txt -bt 10

```

## Screenshot

![AzSubEnum](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjJfr0FoT-2mq0Bsyvt2qb7tDp5lOUA8dmcFw_2GArFGOgCywOZEmkYYdpenBQnIOX_r1X6xUdJdFMHFxwDCr18nTtbIwb_gKpPenLj214AiiLCNF_dEa0MUe1PLUJ8sOcnfcWYnySDzJC8XzBeiHCgc3fXgYotSPmARmnzlnQFAxXFMd-sjoOkvEbeQ-X1/s900)

## Let's contribute!
Do you have any ideas on how to enhance this tool? Let's contribute!

## Disclaimer
Any actions and or activities related to the material contained within this tool is solely your responsibility. The misuse of the information in this tool can result in criminal charges brought against the persons in question.
