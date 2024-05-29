import os
import subprocess
import argparse
import logging
import re
import openpyxl
import datetime
import ipaddress
import validators
import json
from config import CommandEnumDef, CommandEnumAgg, CommandEnumCau
from concurrent.futures import ProcessPoolExecutor, as_completed

# logging.basicConfig(level=logging.INFO, filename="logs.log", filemode="w", format='%(asctime)s - %(levelname)s - %(message)s')
# auditoria per servidor (sistema de logs)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# globals
logger = logging.getLogger()
SAVES = "results/temp/"


def filter_ips(text):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, text)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain):
    try:
        validators.domain(domain)
        return True
    except ValueError:
        return False

def filter_domains(text):
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    return re.findall(domain_pattern, text)

def expand_ip_range(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def treat_json(filename, data):
    with open(filename, 'w') as f:
        for item in data:
            if not item == "127.0.0.1":
                f.write("%s\n" % item)

def save_info(source, output, target):
    if source == "harvester":
        for section, content in output.items():
            if isinstance(content, list):
                treat_json(f'{SAVES}{target}_harvester_{section}.txt', content)

def merge_unique_ips(file1, file2, output_file):
    ips_set = set()
    with open(file1, 'r') as f1:
        for line in f1:
            ip = line.strip()
            if ip:
                ips_set.add(ip)

    with open(file2, 'r') as f2:
        for line in f2:
            ip = line.strip()
            if ip:
                ips_set.add(ip)

    with open(output_file, 'w') as output:
        for ip in sorted(ips_set):
            output.write(f"{ip}\n")

def merge_unique_subdomain(file_subfinder, file_gobuster, output_file):
    with open(file_subfinder, 'r') as f:
        subfinder_lines = f.read().splitlines()

    with open(file_gobuster, 'r') as f:
        gobuster_lines = [line.replace('Found: ', '').strip() for line in f]

    combined_lines = list(set(subfinder_lines + gobuster_lines))

    with open(output_file, 'w') as f:
        for line in sorted(combined_lines):
            f.write(line + '\n')

def execute_order_66(command):
    return os.popen(command).read()

def exec_dmitry(target):
    print(f"[·] Dmitry for {target} started.")
    result_dmirty = execute_order_66(CommandEnumDef.DMIRTY.format(target,target))
    logger.info(result_dmirty)
    print(f"[·] Dmitry for {target} ended.")

def exec_harvester(target):
    print(f"[·] theHarvester for {target} started.")
    result_harvester = execute_order_66(CommandEnumDef.HARVESTER.format(target, target))
    logger.info(result_harvester)
    with open(f'{SAVES}harvester_{target}.json', 'r') as file:
        output = json.load(file)
    save_info("harvester", output, target)
    print(f"[·] theHarvester for {target} ended.")

def exec_subfinder(target,flags):
    print(f"[·] subfinder for {target} started.")
    if flags.cautious:
        result_subfinder = execute_order_66(CommandEnumCau.SUBFINDER.format(target, target))
    else:
        result_subfinder = execute_order_66(CommandEnumDef.SUBFINDER.format(target, target))
    logger.info(result_subfinder)
    print(f"[·] subfinder for {target} ended.")

def exec_dnsx(target,flags):
    print(f"[·] DNSX for {target} started.")
    if flags.aggresive:
        result_dnsx = execute_order_66(CommandEnumAgg.DNSX.format(f"{SAVES}total_subdomains{target}.txt", target))
        execute_order_66(CommandEnumAgg.DNSX2.format(f"{SAVES}total_subdomains{target}.txt", target))
    elif flags.cautious:
        result_dnsx = execute_order_66(CommandEnumCau.DNSX.format(f"{SAVES}total_subdomains{target}.txt", target))
        execute_order_66(CommandEnumCau.DNSX2.format(f"{SAVES}total_subdomains{target}.txt", target))
    else:
        result_dnsx = execute_order_66(CommandEnumDef.DNSX.format(f"{SAVES}total_subdomains{target}.txt", target))
        execute_order_66(CommandEnumDef.DNSX2.format(f"{SAVES}total_subdomains{target}.txt", target))
    logger.info(result_dnsx)
    print(f"[·] DNSX for {target} ended.")

def exec_nmap(target, flags):
    print(f"[·] NMAP for {target} started.")
    if flags.aggressive:
        execute_order_66(CommandEnumAgg.NMAPLIST.format(f"{SAVES}total_ips_{target}.txt",target))
    elif flags.cautious:
        execute_order_66(CommandEnumCau.NMAPLIST.format(f"{SAVES}total_ips_{target}.txt",target))
    else:
        execute_order_66(CommandEnumDef.NMAPLIST.format(f"{SAVES}total_ips_{target}.txt",target))

    with open(f"results/temp/nmap_{target}.txt", 'r') as file:
        content = file.read()
    logger.info(content)
    print(f"[·] NMAP for {target} ended.")

def exec_ferox(target,flags):
    logger.info(f"[·] Feroxbuster for {target} started.")
    result_ferox = execute_order_66(CommandEnumDef.FEROXBUSTER.format(target,target))
    logger.info(result_ferox)
    logger.info(f"[·] Feroxbuster for {target} ended.")

def exec_gobuster(target):
    logger.info(f"[·] Gobuster DNS for {target} starterd.")
    result_gobuster_dns = execute_order_66(CommandEnumDef.GOBUSTERDNS.format(target,target))
    logger.info(result_gobuster_dns)
    logger.info(f"[·] Gobuster DNS for {target} ended.")

def exec_waf(target):
    logger.info(f"[·] Waffw00f for {target} started.")
    result_waf = execute_order_66(CommandEnumDef.WAF.format(target,target))
    logger.info(result_waf)
    logger.info(f"[·] Waffw00f for {target} started.")
def exec_wpscan(target, flags):
    logger.info(f"[·] WPscan for {target} started.")
    if flags.aggressive:
        execute_order_66(CommandEnumAgg.WPSACN.format(target,target))
        execute_order_66(CommandEnumAgg.WPSACNPRINT.format(target, target))
    elif flags.cautious:
        execute_order_66(CommandEnumCau.WPSACN.format(target,target))
        execute_order_66(CommandEnumCau.WPSACNPRINT.format(target, target))
    else:
        execute_order_66(CommandEnumDef.WPSACN.format(target,target))
        execute_order_66(CommandEnumDef.WPSACNPRINT.format(target, target))

    with open(f"results/temp/wpscan_{target}.txt", 'r') as file:
        content = file.read()
    logger.info(content)
    logger.info(f"[·] WPscan for {target} ended.")

def work_domini(targets, flags):
    for target in targets:
        if validate_domain(target):

            print(f"[+] OSINT and Recon for {target} started.")
            exec_dmitry(target)
            exec_harvester(target)
            exec_subfinder(target,flags)
            exec_gobuster(target)

            merge_unique_subdomain(f"{SAVES}{target}_subfinder_subdomain.txt",f"{SAVES}{target}_gobuster_dns.txt", f'{SAVES}{target}_total_subdomains.txt')
            dnsx_break = False
            try:
                 exec_dnsx(target,flags)
            except:
                logger.error("[-] DNSX failed")
                dnsx_break = True

            if not dnsx_break:
                merge_unique_ips(f'{SAVES}{target}_harvester_ips.txt', f'{SAVES}{target}_dnsx2_subdomains.txt',f'{SAVES}{target}_total_ips.txt')
            else:
                os.system(f"cp {SAVES}{target}_harvester_ips.txt {SAVES}{target}_total_ips.txt")

            exec_nmap(target, flags)
            exec_ferox(target,flags)
            exec_waf(target)
            exec_wpscan(target,flags)

            logger.info(f"[+] OSINT and Recon for {target} completed.")
        else:
            logger.error(f"[-] Domain {target} not valid or not reachable")

def scan_recon_ip(target, flags):
    exec_dmitry(target)
    exec_harvester(target)
    exec_subfinder(target, flags)
    exec_gobuster(target)

    merge_unique_subdomain(f"{SAVES}subfinder_subdomain_{target}.txt", f"{SAVES}gobuster_dns_{target}.txt",
                           f'{SAVES}total_subdomains{target}.txt')
    dnsx_break = False
    try:
        exec_dnsx(target, flags)
    except:
        logger.error("[-] DNSX failed")
        dnsx_break = True

    if not dnsx_break:
        merge_unique_ips(f'{SAVES}harvester_{target}_ips.txt', f'{SAVES}dnsx2_subdomains_{target}.txt',
                         f'{SAVES}total_ips_{target}.txt')
    else:
        os.system(f"cp {SAVES}harvester_{target}_ips.txt {SAVES}total_ips_{target}.txt")

    exec_nmap(target, flags)
    exec_ferox(target, flags)
    exec_waf(target)
    exec_wpscan(target, flags)

def work_ips(targets, flags):
    for target in targets:
        if '/' in target:
            ip_range = expand_ip_range(target)
            for ip in ip_range:
                if validate_ip(ip):
                    print(f"[+] OSINT and Recon for {ip} started.")
                    scan_recon_ip(ip, flags)
                    print(f"[+] OSINT and Recon for {ip} completed.")

                else:
                    logger.error(f"[-] IP {ip} not valid or not reachable")
        else:
            if validate_ip(target):
                print(f"[+] OSINT and Recon for {target} started.")
                scan_recon_ip(target, flags)
                print(f"[+] OSINT and Recon for {target} completed.")

            else:
                logger.error(f"[-] IP {target} not valid or not reachable")

def make_excel(flags):
    results_workbook = openpyxl.Workbook()

    ws_single_model = results_workbook.create_sheet(title="Dummy result")
    ws_single_model.append(['DNS', 'IPS', 'mails', 'domains', 'subdomains'])

    set_columns_width(ws_single_model)

    output_file = f"results/{datetime.datetime.now()}_OSINT_tool_info_{flags.domain}.xlsx"
    results_workbook.save(output_file)

def recon(flags):
    if flags.domain:
        targets = [flags.domain]
        work_domini(targets, flags)
    elif flags.list_Domain:
        try:
            with open(flags.list_Domain, 'r') as file:
                targets = [line.strip() for line in file.readlines() if line.strip()]
                work_domini(targets, flags)
        except FileNotFoundError:
            logger.error(f"[-] File not found: {flags.list_Ip or flags.list_Domain}")
            return
    elif flags.ip:
        targets = [flags.ip]
        work_ips(targets, flags)
    elif flags.list_Ip:
        try:
            with open(flags.list_Ip, 'r') as file:
                targets = [line.strip() for line in file.readlines() if line.strip()]
                work_ips(targets, flags)
        except FileNotFoundError:
            logger.error(f"[-] File not found: {flags.list_Ip or flags.list_Domain}")
            return
    else:
        logger.error("[-] No target specified. Use -i , -d , -lI or -lD to specify the IP(s) or the Domain(s).")
        return

def main(flags):
    os.popen("rm -rf results/temp/*")

    if not flags.vuln_scan and not flags.recon: # no flags, default
        recon(flags)
    elif not flags.recon: # -vuln_scan, only
        print("vuln scan")
    elif not flags.vuln_scan: # -recon, only
        recon(flags)
    else: # -recon i -vuln_scan, default
        recon(flags)



    #os.popen("rm -rf results/temp/*")

def set_columns_width(ws):
    for col in ws.columns:
        max_length = 0
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        adjusted_width = (max_length + 2) * 1.2
        ws.column_dimensions[col[0].column_letter].width = adjusted_width


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon & Scan Vulns automated script tool")
    parser.add_argument("-i", "--ip", type=str, help="Target IP to scan")
    parser.add_argument("-d", "--domain", type=str, help="Target domain to scan")
    parser.add_argument("-lI", "--list_Ip", type=str, help="List of IPs to scan")
    parser.add_argument("-lD", "--list_Domain", type=str, help="List of domains to scan")
    parser.add_argument("-r", "--recon", action="store_true", help="Perform only reconnaissance")
    parser.add_argument("-v", "--vuln_scan", action="store_true", help="Perform only vulnerability scanning")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Run scans in aggressive mode")
    parser.add_argument("-c", "--cautious", action="store_true", help="Run scans in cautious mode")

    args = parser.parse_args()
    print(args)
    main(args)
