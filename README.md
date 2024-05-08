# TFG

## How to isntall
U need to have python 3.12 installed 

```pip install -r requirements.txt```
## Usage
```usage: script2_tabulat.py [-h] [-i IP] [-d DOMAIN] [-lI LIST_IP] [-lD LIST_DOMAIN] [-r] [-v] [-a] [-c] [--threads THREADS]

Recon & Scan automated script tool

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        Target IP to scan
  -d DOMAIN, --domain DOMAIN
                        Target domain to scan
  -lI LIST_IP, --list_Ip LIST_IP
                        List of IPs to scan
  -lD LIST_DOMAIN, --list_Domain LIST_DOMAIN
                        List of domains to scan
  -r, --recon           Perform only reconnaissance
  -v, --vuln_scan       Perform only vulnerability scanning
  -a, --aggressive      Run scans in aggressive mode
  -c, --cautious        Run scans in cautious mode
  --threads THREADS     Number of concurrent threads (default: 4)
```
## Running 
### Single domain
``python3 script -d domini.com``
### Single IP
``python3 script -i 0.0.0.0``
### Multiple domain
``python3 script -lD domini_list.txtn``
### Multiple IPs
``python3 script -lI IPs_list.txt``
