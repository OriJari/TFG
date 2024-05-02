import os
import subprocess



target_domain = "celageltru.com"	

def is_real_target(target):
	try: 
		subprocess.check_output(["ping","-c","1",target])
		return True
	except subprocess.CalledProcessError:
		return False


def run_tools(target):

	os.system("theHarvester -d {} -b all".format(target))
	os.system("nmap -Pn -sV -T4 {}".format(target))


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
	main()