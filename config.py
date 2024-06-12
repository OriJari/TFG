from strenum import StrEnum

# All comands can be modified to your liking.
# Every class will be the comands that are called by default, so if you want to customize them, go ahead.
# Further down, in comments sections, include a copy so as not to lose them once you have customized them.

#set your diferents wordlists here
WORDLIST_SUBDOMAINS = "lists/amass/subdomains-top1mil-5000.txt"
WORDLIST_VHOST = "lists/dirb/common.txt"


#set your api tokens here
API_WPSCAN = "YOUR API CODE" #add your api token, it's free, only with register at https://wpscan.com/

#path to temporal files are saved
SAVES = "results/temp/"

#IMPORTANT!! If you customize the commands to your liking, which you are free to do,
# be careful not to modify the save files, their names, and their paths,
# otherwise the script will not be able to execute correctly.

class CommandEnumDef(StrEnum):  #default call
    #recon
    NMAPLIST = f"nmap -T4 -iL {{}} -oN {SAVES}{{}}_nmap.txt" #nmap list for -domain input
    NMAP = f"nmap -T4 {{}} -oN {SAVES}{{}}_nmap.txt" #nmap unique for -ip input
    DMIRTY = f"dmitry -i -w -n -s -e -o {SAVES}{{}}_dmitry.txt {{}}"
    SUBFINDER = f"subfinder -all -recursive -d {{}} -t 100  -o {SAVES}{{}}_subfinder_subdomain.txt"
    DNSX = f"dnsx -l {{}} -a -re -o {SAVES}{{}}_dnsx_subdomains.txt" #subdomain with ips, for output and proccessing data
    DNSX2 = f"dnsx -l {{}} -a -ro -o {SAVES}{{}}_dnsx2_subdomains.txt" #response only
    GOBUSTERDNS = f"gobuster dns -d {{}} -w {WORDLIST_SUBDOMAINS} -t 200 -o {SAVES}{{}}_gobuster_dns.txt"
    HARVESTER = f"theHarvester -d {{}} -b all -n -r -f {SAVES}{{}}_harvester.com"
    WAF = f"wafw00f https://{{}} -a -o {SAVES}{{}}_wafw00f.txt"
    WPSACN = f"wpscan --url https://{{}} --random-user-agent --enumerate t,p,u,m -t 100 -o {SAVES}{{}}_wpscan.txt -f cli" #with --enumerate at,ap searchs for all themes and all pluggins, more slow

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt -f cli"
    NUCLEI = f"nuclei -u {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -o {SAVES}{{}}_nuclei.txt"

class CommandEnumAgg(StrEnum):  #aggresive comands
    #recon
    NMAPLIST = f"nmap -T5 -iL {{}} -oN {SAVES}{{}}_nmap.txt"
    NMAP = f"nmap -T5 {{}} -oN {SAVES}{{}}_nmap.txt"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate p,t,u,m --detection-mode aggressive --plugins-detection aggressive --themes-detection aggressive --user-detection aggresive -o {SAVES}{{}}_wpscan.txt -f cli"
    DNSX = f"dnsx -l {{}} -a -re-retry 3 -o {SAVES}{{}}_dnsx_subdomains.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -retry 3 -o {SAVES}{{}}_dnsx2_subdomains.txt"

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode aggressive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt -f cli"

class CommandEnumCau(StrEnum):  #caution comands
    #recon
    NMAPLIST = f"nmap -T2 -iL {{}} -oN {SAVES}{{}}_nmap.txt"
    NMAP = f"nmap -T2 {{}} -oN {SAVES}{{}}_nmap.txt"
    SUBFINDER = f"subfinder -silent -recursive -d {{}} -t 10 -o {SAVES}{{}}_subfinder_subdomain.txt"
    DNSX = f"dnsx -l {{}} -a -re -rate-limit 5 -o {SAVES}{{}}_dnsx_subdomains.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -rate-limit 5 -o {SAVES}{{}}_dnsx2_subdomains.txt"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode passive --plugins-detection passive --themes-detection passive --user-detection passive -o {SAVES}{{}}_wpscan.txt -f cli"

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode passive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt -f cli"


#basic calls, they are here as a backup if you make any modification to the calls
'''

class CommandEnumDef(StrEnum):  #default call
    #recon
    NMAPLIST = f"nmap -T4 -iL {{}} -oN {SAVES}{{}}_nmap.txt" #nmap list for -domain input
    NMAP = f"nmap -T4 {{}} -oN {SAVES}{{}}_nmap.txt" #nmap unique for -ip input
    DMIRTY = f"dmitry -i -w -n -s -e -o {SAVES}{{}}_dmitry.txt {{}}"
    SUBFINDER = f"subfinder -all -recursive -d {{}} -t 100  -o {SAVES}{{}}_subfinder_subdomain.txt"
    DNSX = f"dnsx -l {{}} -a -re -o {SAVES}{{}}_dnsx_subdomains.txt" #subdomain with ips, for output and proccessing data
    DNSX2 = f"dnsx -l {{}} -a -ro -o {SAVES}{{}}_dnsx2_subdomains.txt" #response only
    GOBUSTERDNS = f"gobuster dns -d {{}} -w {WORDLIST_SUBDOMAINS} -t 200 -o {SAVES}{{}}_gobuster_dns.txt"
    HARVESTER = f"theHarvester -d {{}} -b all -n -r -f {SAVES}{{}}_harvester.com"
    WAF = f"wafw00f https://{{}} -a -o {SAVES}{{}}_wafw00f.txt"
    WPSACN = f"wpscan --url https://{{}} --random-user-agent --enumerate t,p,u,m -t 100 -o {SAVES}{{}}_wpscan.txt -f cli" #with --enumerate at,ap searchs for all themes and all pluggins, more slow

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt -f cli"
    NUCLEI = f"nuclei -u {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -o {SAVES}{{}}_nuclei.txt"

class CommandEnumAgg(StrEnum):  #aggresive comands
    #recon
    NMAPLIST = f"nmap -T5 -iL {{}} -oN {SAVES}{{}}_nmap.txt"
    NMAP = f"nmap -T5 {{}} -oN {SAVES}{{}}_nmap.txt"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate p,t,u,m --detection-mode aggressive --plugins-detection aggressive --themes-detection aggressive --user-detection aggresive -o {SAVES}{{}}_wpscan.txt -f cli"
    DNSX = f"dnsx -l {{}} -a -re-retry 3 -o {SAVES}{{}}_dnsx_subdomains.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -retry 3 -o {SAVES}{{}}_dnsx2_subdomains.txt"

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode aggressive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt -f cli"

class CommandEnumCau(StrEnum):  #caution comands
    #recon
    NMAPLIST = f"nmap -T2 -iL {{}} -oN {SAVES}{{}}_nmap.txt"
    NMAP = f"nmap -T2 {{}} -oN {SAVES}{{}}_nmap.txt"
    SUBFINDER = f"subfinder -silent -recursive -d {{}} -t 10 -o {SAVES}{{}}_subfinder_subdomain.txt"
    DNSX = f"dnsx -l {{}} -a -re -rate-limit 5 -o {SAVES}{{}}_dnsx_subdomains.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -rate-limit 5 -o {SAVES}{{}}_dnsx2_subdomains.txt"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode passive --plugins-detection passive --themes-detection passive --user-detection passive -o {SAVES}{{}}_wpscan.txt -f cli"

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode passive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt -f cli"

'''


