import os
import subprocess
import argparse
import logging
import re
import openpyxl
import datetime
from concurrent.futures import ThreadPoolExecutor

# logging.basicConfig(level=logging.INFO, filename="logs.log", filemode="w", format='%(asctime)s - %(levelname)s - %(message)s') #auditoria per servidor (sistema de logs)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_real_target(target):  #questionable
    try:
        subprocess.check_output(["ping", "-c", "1", target], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


# función para correr las herramientas de manera concurrente
def run_tool(command):
    output = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return output.stdout.decode()

def filter_ips(text):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # IPv4 pattern
    ipv6_pattern = r'(?:(?:(?:[0-9a-fA-F]){1,4}:){7}(?:[0-9a-fA-F]){1,4}|(?:(?:[0-9a-fA-F]){1,4}:){6}(?::[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|(?:(?:[0-9a-fA-F]){1,4}:){5}(?:(?::[0-9a-fA-F]{1,4}){1,2}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|(?:(?:[0-9a-fA-F]){1,4}:){4}(?:(?::[0-9a-fA-F]{1,4}){1,3}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|(?:(?:[0-9a-fA-F]){1,4}:){3}(?:(?::[0-9a-fA-F]{1,4}){1,4}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|(?:(?:[0-9a-fA-F]){1,4}:){2}(?:(?::[0-9a-fA-F]{1,4}){1,5}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|(?:(?:[0-9a-fA-F]){1,4}:)(?:(?::[0-9a-fA-F]{1,4}){1,6}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}):(?:[0-9a-fA-F]{1,4}:){1,7}|(?:[0-9a-fA-F]{1,4}:){6}(?::[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|::(?:[0-9a-fA-F]{1,4}:){5}(?::[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})|:)|::(?:[0-9a-fA-F]{1,4}:){4}(?::[0-9a-fA-F]{1,4}){0,2}|(?:::)?(?:[0-9a-fA-F]{1,4}:){3}(?::[0-9a-fA-F]{1,4}){0,3}|(?:::)?(?:[0-9a-fA-F]{1,4}:){2}(?::[0-9a-fA-F]{1,4}){0,4}|(?:::)?[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){0,5}|(?:::)?:(?::[0-9a-fA-F]{1,4}){0,6}|(?:::)?)'
    combined_pattern = f'(?:{ip_pattern})|(?:{ipv6_pattern})'  # Combined pattern
    return re.findall(combined_pattern, text)

def filter_domains(text):
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    return re.findall(domain_pattern, text)

# función principal que llama a las herramientas de OSINT y recon
def main(flags):
    logger = logging.getLogger()
    if flags.domain:
        targets = [flags.domain]
    elif flags.list_Domain:
        try:
            with open(flags.list_Domain, 'r') as file:
                targets = [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError:
            logger.error(f"[-] File not found: {flags.list_Ip or flags.list_Domain}")
            return
    else:
        logger.error("[-] No target specified. Use -i , -d , -lI or -lD to specify the IP(s) or the Domain(s).")
        return

    with ThreadPoolExecutor(max_workers=flags.threads) as executor:
        for target in targets:
            tools = []

            result_nmap = os.popen("nmap -Pn -sV -T4 {}".format(target)).read()
            result_dmitry = os.popen("dmitry -i -w -n -s -e {}".format(target)).read()
            logger.info(result_nmap)
            logger.info(result_dmitry)


           '''  if flags.recon or not flags.vuln_scan:
                    tools.extend([
                        f"theHarvester -d {target} -b all",
                        f"nmap {'-T5' if flags.aggressive else '-T2'} -Pn -sV {target}",
                        f"feroxbuster -u {target}{' -x js,php' if flags.aggressive else ''}",
                        f"subfinder -d {target} | dnsx -a -resp",
                        f"dmitry -i -w -n -s -e {target}",
                        f"nslookup {target}",
                    ])

                if flags.vuln_scan:
                    tools.extend([
                        f"wafw00f -v -a {target}",
                        f"nuclei -u{target}",
                        f"wpscan --url {target}{' --stealthy' if flags.cautious else ''}"
                    ])

                results = list(executor.map(run_tool, tools))
                for result in results:
                    print(result)
'''
        print(f"[+] OSINT and Recon for {target} completed.")


    results_workbook = openpyxl.Workbook()


    ws_single_model = results_workbook.create_sheet(title="Dummy result")
    ws_single_model.append(['DNS',
                            'IPS',
                            'mails',
                            'domains',
                            'subdomains'
                            ])


    set_columns_width(ws_single_model)

    output_file = f"{datetime.datetime.now()}_OSINT_tool_info_{flags.Domain}.xlsx"
    results_workbook.save(output_file)


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
    parser.add_argument("--threads", type=int, default=4, help="Number of concurrent threads (default: 4)")

    args = parser.parse_args()
    print(args)
    main(args)
