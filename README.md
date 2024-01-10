# AzSubEnum - Azure Service Subdomain Enumeration
During my learning journey on Azure AD exploitation, I discovered that the Azure subdomain tool, [Invoke-EnumerateAzureSubDomains](https://github.com/NetSPI/MicroBurst/blob/master/Misc/Invoke-EnumerateAzureSubDomains.ps1) from NetSPI, was unable to run on my Debian PowerShell. Consequently, I created a crude implementation of that tool in Python.

## Usage
```
➜  AzSubEnum git:(main) ✗ python3 azsubenum.py --help
usage: azsubenum.py [-h] -b BASE [-v] [-t THREADS] [-p PERMUTATIONS]

Azure Subdomain Enumeration

options:
  -h, --help            show this help message and exit
  -b BASE, --base BASE  Base name to use
  -v, --verbose         Show verbose output
  -t THREADS, --threads THREADS
                        Number of threads for concurrent execution
  -p PERMUTATIONS, --permutations PERMUTATIONS
                        File containing permutations
```

```
python3 azsubenum.py -b retailcorp --thread 10
```

## Screenshot

![AzSubEnum](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjJfr0FoT-2mq0Bsyvt2qb7tDp5lOUA8dmcFw_2GArFGOgCywOZEmkYYdpenBQnIOX_r1X6xUdJdFMHFxwDCr18nTtbIwb_gKpPenLj214AiiLCNF_dEa0MUe1PLUJ8sOcnfcWYnySDzJC8XzBeiHCgc3fXgYotSPmARmnzlnQFAxXFMd-sjoOkvEbeQ-X1/s900)

## Disclaimer
Any actions and or activities related to the material contained within this tool is solely your responsibility.The misuse of the information in this tool can result in criminal charges brought against the persons in question.