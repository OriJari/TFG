# TFG - KUDO
KUDO has been developed as a final grade's project. 

Kudo is a script that automates the recognition and scanning of services, technologies and vulnerabilities.

Is a Script that collects different information gathering tools in the phase of recognizing and scanning a pentest. Generate an xlsx file with all the information found.

(only tested for kali linux)

## How to isntall
You must have installed Python 3 (recomended 3.12)
then execute the following comands:

(recomended to update apt)

```sudo apt update```

```sudo ./installation_tools.sh ```

It is recomendable to create a venv, at the directory of the project:

```python -m virtualenv venv```

``venv/bin/activate``
or
``source venv/bin/activate``

```pip install -r requirements.txt```
### Recomendation
It is recomendet to try each tool that don't cause any issue, and to update them.

## Usage
```
usage: kudo.py [-h] [-i IP] [-d DOMAIN] [-lI LIST_IP] [-lD LIST_DOMAIN] [-r] [-v] [-a] [-c] 

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
```

## Running 
### Single domain
``python3 kudo.py -d domini.com``
### Single IP
``python3 kudo.py -i 0.0.0.0``
### Multiple domain
``python3 kudo.py -lD domini_list.txtn``
### Multiple IPs
``python3 kudo.py -lI IPs_list.txt``

## APIs 
You can vinculate diferents APIs to the tools, theHarvester or wpscan. 

### theHarvester
For the theHarvester you can find more info here, at their repo and following the configuration they sey, it will work for the tool.
https://github.com/laramies/theHarvester

### wpscan
For the wpscan, at file config.py as a constant there is the line 

```API_WPSCAN = "YOUR_API_TOKEN" #add your api token, it's free, only with register at https://wpscan.com/```

Register to the web of wpscan https://wpscan.com/, and with a free account you get acces to the API.

