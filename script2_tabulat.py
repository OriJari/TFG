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


def is_real_target(target):  # questionable
    try:
        subprocess.check_output(["ping", "-c", "1", target], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


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


def treat_json(filename, data):
    with open(filename, 'w') as f:
        for item in data:
            f.write("%s\n" % item)


def save_info(source, output, target):
    if source == "harvester":
        treat_json(f'{SAVES}{target}_asns.txt', output.get('asns', []))
        treat_json(f'{SAVES}{target}_emails.txt', output.get('emails', []))
        treat_json(f'{SAVES}{target}_hosts.txt', output.get('hosts', []))
        treat_json(f'{SAVES}{target}_urls.txt', output.get('interesting_urls', []))
        treat_json(f'{SAVES}{target}_ips.txt', output.get('ips', []))
        treat_json(f'{SAVES}{target}_shodan.txt', output.get('shodan', []))

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


def execute_order_66(command):
    return os.popen(command).read()


def work_domini(targets, flags):
    for target in targets:
        if validate_domain(target) and is_real_target(target):
            if not flags.vuln_scan:
                print(f"[+] OSINT and Recon for {target} started.")

                print(f"[·] Dmitry for {target} started.")
                result_dmirty = execute_order_66(CommandEnumDef.DMIRTY.format(target))
                logger.info(result_dmirty)
                print(f"[·] Dmitry for {target} ended.")

                print(f"[·] theHarvester for {target} started.")
                result_harvester = execute_order_66(CommandEnumDef.HARVESTER.format(target, target))
                logger.info(result_harvester)
                with open(f'{SAVES}harvester_{target}', 'r') as file:
                    output = json.load(file)
                save_info("harvester", output, target)
                print(f"[·] theHarvester for {target} ended.")

                print(f"[·] subfinder for {target} started.")
                result_subfinder = execute_order_66(CommandEnumDef.SUBFINDER.format(target, target))
                logger.info(result_subfinder)
                print(f"[·] subfinder for {target} ended.")

                print(f"[·] DNSX for {target} started.")
                result_dnsx = execute_order_66(CommandEnumDef.DNSX.format(f"{SAVES}subfinder_subdomain_{target}.txt", target))
                execute_order_66(CommandEnumDef.DNSX2.format(f"{SAVES}subfinder_subdomain_{target}.txt", target))
                logger.info(result_dnsx)
                print(f"[·] DNSX for {target} ended.")

                merge_unique_ips(f'{SAVES}{target}_ips.txt', f'{SAVES}dnsx2_subdomains_{target}.txt', f'{SAVES}total_ips{target}.txt')

                print(f"[·] NMAP for {target} started.")
                if flags.aggressive:
                    result_nmap = execute_order_66(CommandEnumAgg.NMAPLIST.format(f"{SAVES}total_ips{target}.txt"))
                elif flags.cautious:
                    result_nmap = execute_order_66(CommandEnumCau.NMAPLIST.format(f"{SAVES}total_ips{target}.txt"))
                else:
                    result_nmap = execute_order_66(CommandEnumDef.NMAPLIST.format(f"{SAVES}total_ips{target}.txt"))
                logger.info(result_nmap)
                print(f"[·] NMAP for {target} ended.")

                logger.info(f"[+] OSINT and Recon for {target} completed.")
        else:
            logger.error(f"[-] Domain {target} not valid or not reachable")


def work_ips(targets, flags):
    # per llista de ips mirar rang
    with ProcessPoolExecutor(max_workers=flags.threads) as executor:
        for target in targets:
            if validate_ip(target) and is_real_target(target):

                result_nmap = os.popen("nmap -Pn -sV -T4 {}".format(target)).read()
                result_dmitry = os.popen("dmitry -i -w -n -s -e {}".format(target)).read()
                logger.info(result_nmap)
                logger.info(result_dmitry)
            else:
                logger.error(f"[-] IP {target} not valid or not reachable")

            print(f"[+] OSINT and Recon for {target} completed.")


def main(flags):
    os.popen("rm -rf results/temp/*")

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

    results_workbook = openpyxl.Workbook()

    ws_single_model = results_workbook.create_sheet(title="Dummy result")
    ws_single_model.append(['DNS', 'IPS', 'mails', 'domains', 'subdomains'])

    set_columns_width(ws_single_model)

    output_file = f"results/{datetime.datetime.now()}_OSINT_tool_info_{flags.domain}.xlsx"
    results_workbook.save(output_file)

    os.popen("rm -rf results/temp/*")


def set_columns_width(ws):
    for col in ws.columns:
        max_length = 0
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        adjusted_width = (max_length + 2) * 1.2
        ws.column_dimensions[col[0].column_letter].width = adjusted_width


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon & Scan automated script tool")
    parser.add_argument("-i", "--ip", type=str, help="Target IP to scan")
    parser.add_argument("-d", "--domain", type=str, help="Target domain to scan")
    parser.add_argument("-lI", "--list_Ip", type=str, help="List of IPs to scan")
    parser.add_argument("-lD", "--list_Domain", type=str, help="List of domains to scan")
    parser.add_argument("-r", "--recon", action="store_true", help="Perform only reconnaissance")
    parser.add_argument("-v", "--vuln_scan", action="store_true", help="Perform only vulnerability scanning")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Run scans in aggressive mode")
    parser.add_argument("-c", "--cautious", action="store_true", help="Run scans in cautious mode")

    args = parser.parse_args()
    print (args)
    main(args)
