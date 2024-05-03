import os
import subprocess
import argparse



target_domain = "celageltru.com"	

def is_real_target(target): #questionable
	try: 
		subprocess.check_output(["ping","-c","1",target])
		return True
	except subprocess.CalledProcessError:
		return False


def run_tools(target):

	os.system("theHarvester -d {} -b all".format(target))
	os.system("nmap -Pn -sV -T4 {}".format(target))
	os.system("feroxbuster -u {}".format(target))
	os.system("subfinder -d {} | dnsx -a -resp".format(target))
	os.system("dmitry -i -w -n -s -e {}".format(target))
	os.system("nslookup {}".format(target))
	os.system("wafw00f -v -a {}".format(target))
	os.system("nuclei -u{}".format(target))
	os.system("wpscan --url {}".format(target))
	os.system("prips {} | go run hakip2host.go").format(target))

def main():



	if is_real_target(target_domain):
		print(f"[+] Target domain {target_domain} is reachable. Starting OSINT and Recon...")

		print("[*]Running theHarvester")
		print("[*]Running Nmap")

		run_tools(target_domain)

		print("[+] OSINT and Recon completed.")

	else: 
		print(f"[-] Target domain {target_domain} is not reachable. Aborting.")


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Recon & Scan automated script tool')

	parser.add_argument('-t', '--target', help='Target domain name', required=True)
	args = parser.parse_args()

	main(args.domain)