import os
import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor



def is_real_target(target):
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


# función principal que llama a las herramientas de OSINT y recon
def main(flags):
    if flags.ip or flags.d:
        targets = [flags.ip or flags.d]
    elif flags.list_Ip or flags.list_Domain:
        try:
            with open(flags.list_Ip or flags.list_Domain, 'r') as file:
                targets = [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"[-] File not found: {flags.list_Ip or flags.list_Domain}")
            return
    else:
        print("[-] No target specified. Use -i , -d , -lI or -lD to specify the IP(s) or the Domain(s).")
        return

    with ThreadPoolExecutor(max_workers=flags.threads) as executor:
        for target in targets:

                tools = []

                if flags.recon or not flags.vuln_scan:
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

                print(f"[+] OSINT and Recon for {target} completed.")



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
    main(args)
