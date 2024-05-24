import os
import subprocess
import argparse
import logging
import re
import openpyxl
import datetime
import ipaddress
import validators
from config import CommandEnumDef
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


def execute_order_66(command):
    return os.popen(command).read()


def work_domini(targets, flags):
    for target in targets:
        if validate_domain(target) and is_real_target(target):
            print(f"[+] OSINT and Recon for {target} started.")
            print(f"[·] Dmitry for {target} started.")
            result_dmirty = execute_order_66(CommandEnumDef.DMIRTY.format(target))
            print(f"[·] Dmitry for {target} ended.")
            print(f"[·] subfinder for {target} started.")
            result_subfinder = execute_order_66(CommandEnumDef.SUBFINDER.format(target))
            print(f"[·] subfinder for {target} ended.")
            print(f"[·] DNSX for {target} started.")
            result_dnsx = execute_order_66(CommandEnumDef.DNSX.format(f"{SAVES}subfinder_subdomain_{target}.txt)"))
            execute_order_66(CommandEnumDef.DNSX2.format(f"{SAVES}subfinder_subdomain_{target}.txt)"))
            print(f"[·] DNSX for {target} ended.")
            print(f"[·] NMAP for {target} started.")
            result_nmap = execute_order_66(CommandEnumDef.NMAP.format(f"{SAVES}dnsx2_subdomains_{{}}.txt"))
            print(f"[·] NMAP for {target} ended.")

            logger.info(result_dmirty)
            logger.info(result_subfinder)
            logger.info(result_dnsx)
            logger.info(result_nmap)
            logger.info(f"[+] OSINT and Recon for {target} completed.")
        else:
            logger.error(f"[-] Domain {target} not valid or not reachable")

        print(f"[+] OSINT and Recon for {target} completed.")


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

    output_file = f"{datetime.datetime.now()}_OSINT_tool_info_{flags.domain}.xlsx"
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
    main(args)
