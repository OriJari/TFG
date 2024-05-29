from strenum import StrEnum

# All comands can be modified to your liking.
# Every class will be the comands that are called by default, so if you want to customize them, go ahead.
# Further down, comments include a copy so as not to lose them once you have customized them.

#set your diferents wordlists here
WORDLIST_SUBDOMAINS = "lists/amass/subdomains-top1mil-5000.txt"
WORDLIST_VHOST = "lists/dirb/common.txt"


#set your api tokens here
API_WPSCAN = "sIxe5FoNOPimo8LN3sbKErvzBr7Q7X29JDqVnYIcxVs" #add your api token, it's free, only with register at https://wpscan.com/

#path to temporal files are saved
SAVES = "results/temp/"

#IMPORTANT!! If you customize the commands to your liking, which you are free to do,
# be careful not to modify the save files, their names, and their paths,
# otherwise the script will not be able to execute correctly.

class CommandEnumDef(StrEnum):  #default call
    #recon
    NMAPLIST = f"nmap -T4 -iL {{}} >> {SAVES}{{}}_nmap.txt" #nmap list for -domain input
    NMAP = f"nmap -T4 {{}} >> {SAVES}{{}}_nmap.txt" #nmap unique for -ip input
    DMIRTY = f"dmitry -i -w -n -s -e -o {SAVES}{{}}_dmitry.txt {{}}"
    SUBFINDER = f"subfinder -all -recursive -d {{}} -t 100  -o {SAVES}{{}}_subfinder_subdomain.txt"
    DNSX = f"dnsx -l {{}} -a -re -o {SAVES}{{}}_dnsx_subdomains.txt" #subdomain with ips, for output and proccessing data
    DNSX2 = f"dnsx -l {{}} -a -ro -o {SAVES}{{}}_dnsx2_subdomains.txt" #response only
    FEROXBUSTER = f"feroxbuster -u {{}} -t 100 -d 2 --insecure --random-agent --thorough --force-recursion --json -o {SAVES}{{}}_feroxbuster.json -C 404,403,500 --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old"
    GOBUSTERDNS = f"gobuster dns -d {{}} -w {WORDLIST_SUBDOMAINS} -t 200 -o {SAVES}{{}}_gobuster_dns.txt"
    HARVESTER = f"theHarvester -d {{}} -b all -n -r -f {SAVES}{{}}_harvester.com"
    WAF = f"wafw00f https://{{}} -a -o {SAVES}{{}}_wafw00f.json -f json"
    WPSACN = f"wpscan --url https://{{}} --random-user-agent --enumerate t,p,u,m -t 100 -o {SAVES}{{}}_wpscan.json -f json" #with --enumerate at,ap searchs for all themes and all pluggins, more slow
    WPSACNPRINT = f"wpscan --url https://{{}} --random-user-agent --enumerate p,t,u,m -t 100 -o {SAVES}{{}}_wpscan.txt" #just for print

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.json -f json"
    WPSCANVULNPRINT = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt" #just for print
    NUCLEI = f"nuclei -u {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -jsonl -o {SAVES}{{}}_nuclei.json"
    NUCLEIUNIC = f"nuclei -u {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -jsonl -o {SAVES}{{}}_nucleiunique.json"

class CommandEnumAgg(StrEnum):  #aggresive comands
    #recon
    NMAPLIST = f"nmap -T5 -iL {{}} >> {SAVES}{{}}_nmap.txt"
    NMAP = f"nmap -T5 {{}} >> {SAVES}{{}}_nmap.txt"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate p,t,u,m --detection-mode aggressive --plugins-detection aggressive --themes-detection aggressive --user-detection aggresive -o {SAVES}{{}}_wpscan.json -f json"
    WPSACNPRINT = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate p,t,u,m --detection-mode aggressive --plugins-detection aggressive --themes-detection aggressive --user-detection aggresive -o {SAVES}{{}}_wpscan.txt"
    DNSX = f"dnsx -l {{}} -a -re-retry 3 -o {SAVES}{{}}_dnsx_subdomains.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -retry 3 -o {SAVES}{{}}_dnsx2_subdomains.txt"

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode aggressive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.json -f json"
    WPSCANVULNPRINT = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode aggressive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt"


class CommandEnumCau(StrEnum):  #caution comands
    #recon
    NMAPLIST = f"nmap -T2 -iL {{}} >> {SAVES}{{}}_nmap.txt"
    NMAP = f"nmap -T2 {{}} >> {SAVES}{{}}_nmap.txt"
    SUBFINDER = f"subfinder -silent -recursive -d {{}} -t 10 -o {SAVES}{{}}_subfinder_subdomain.txt"
    DNSX = f"dnsx -l {{}} -a -re -rate-limit 5 -o {SAVES}{{}}_dnsx_subdomains.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -rate-limit 5 -o {SAVES}{{}}_dnsx2_subdomains.txt"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode passive --plugins-detection passive --themes-detection passive --user-detection passive -o {SAVES}{{}}_wpscan.json -f json"
    WPSACNPRINT = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode passive --plugins-detection passive --themes-detection passive --user-detection passive -o {SAVES}{{}}_wpscan.txt"

    #vulns
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode passive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.json -f json"
    WPSCANVULNPRINT = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode passive  --api-token {API_WPSCAN} -t 100 -o {SAVES}{{}}_wpscanvuln.txt"


#basic calls, they are here as a backup if you make any modification to the calls
'''

class CommandEnumDef(StrEnum):  #default call
    NMAPLIST = f"nmap -T4 -iL {{}} >> {SAVES}_nmap_{{}}.txt"
    NMAP = f"nmap -T4 {{}} >> {SAVES}_nmap_{{}}.txt"
    DMIRTY = f"dmitry -i -w -n -s -e -o {SAVES}dmitry.txt {{}}"
    SUBFINDER = f"subfinder -all -recursive -d {{}} -t 100  -o {SAVES}subfinder_subdomain_{{}}.txt"
    DNSX = f'dnsx -l {{}} -a -re -o {SAVES}dnsx_subdomains_{{}}.txt'
    DNSX2 = f'dnsx -l {{}} -a -ro -o {SAVES}dnsx2_subdomains_{{}}.txt'
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --insecure --thorough --force-recursion --json -o {SAVES}feroxbuster_{{}}.json -C 404,403,500 --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old"
    GOBUSTERDNS = f"gobuster dns -d {{}} -w {WORDLIST_SUBDOMAINS} -t 200 -o {SAVES}gobuster_dns_{{}}.txt"
    HARVESTER = f"theHarvester -d {{}} -b all -n -r -f {SAVES}harvester_{{}}.com"
    WAF = f"wafw00f https://{{}} -a -o {SAVES}wafw00f_{{}} -f json"
    WPSACN = f"wpscan --url https://{{}} --random-user-agent --enumerate ap,at,u,m -t 100 -o {SAVES}wpscan_{{}} -f json"
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --api-token {API_WPSCAN} -t 100 -o {SAVES}wpscanvuln_{{}} -f json"
    NUCLEI = f"nuclei -l {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -jsonl -o {SAVES}nuclei_{{}}.json"
    NUCLEIUNIC = f"nuclei -u {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -jsonl -o {SAVES}nucleiunique_{{}}.json"

class CommandEnumAgg(StrEnum):  #aggresive comands
    NMAPLIST = f"nmap -T5 -iL {{}} >> {SAVES}_nmap_{{}}.txt"
    NMAP = f"nmap -T5 {{}} >> {SAVES}_nmap_{{}}.txt"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode aggressive --plugins-detection aggressive --themes-detection aggressive --user-detection aggresive -o {SAVES}wpscan_{{}} -f json"
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode aggressive  --api-token {API_WPSCAN} -t 100 -o {SAVES}wpscanvuln_{{}} -f json"
    DNSX = f"dnsx -l {{}} -a -re-retry 3 -o {SAVES}dnsx_subdomains_{{}}.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -retry 3 -o {SAVES}dnsx_subdomains_{{}}.txt"


class CommandEnumCau(StrEnum):  #caution comands
    NMAPLIST = "nmap -T2 -iL {}"
    NMAP = "nmap -T2 {}"
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --thorough --insecure --force-recursion --json -o {SAVES}feroxbuster_{{}}.json -C 404,403,500 --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old --random-agent"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode passive --plugins-detection passive --themes-detection passive --user-detection passive -o {SAVES}wpscan_{{}} -f json"
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode passive  --api-token {API_WPSCAN} -t 100 -o {SAVES}wpscanvuln_{{}} -f json"
    SUBFINDER = f"subfinder -silent -recursive -d {{}} -t 10 -o {SAVES}subfinder_subdomain_{{}}.txt"
    DNSX = f'dnsx -l {{}} -a -re -rate-limit 5 -o {SAVES}dnsx_subdomains_{{}}.txt'
    DNSX2 = f'dnsx -l {{}} -a -ro -rate-limit 5 -o {SAVES}dnsx_subdomains_{{}}.txt'

'''


