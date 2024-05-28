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

class CommandEnumDef(StrEnum):  #default call
    NMAPLIST = f"nmap -T4 -iL {{}} >> {SAVES}_nmap_{{}}.txt"
    NMAP = f"nmap -T4 {{}} >> {SAVES}_nmap_{{}}.txt"
    DMIRTY = f"dmitry -i -w -n -s -e -o {SAVES}dmitry.txt {{}}"
    SUBFINDER = f"subfinder -all -recursive -d {{}} -t 100  -o {SAVES}subfinder_subdomain_{{}}.txt"
    DNSX = f'dnsx -l {{}} -a -re -o {SAVES}dnsx_subdomains_{{}}.txt'
    DNSX2 = f'dnsx -l {{}} -a -ro -o {SAVES}dnsx2_subdomains_{{}}.txt'
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --insecure --thorough --force-recursion -o {SAVES}feroxbuster_{{}}.txt --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old"
    GOBUSTERDNS = f"gobuster dns -d {{}} -w {WORDLIST_SUBDOMAINS} -t 200 -o {SAVES}gobuster_dns_{{}}.txt"
    GOBUSTERVHOST = f"gobuster vhost dir -u {{}} -w {WORDLIST_VHOST} -t 50 -o {SAVES}obuster_vhost_{{}}.txt"
    HARVESTER = f"theHarvester -d {{}} -b all -n -r -f {SAVES}harvester_{{}}.com"
    WAF = f"wafw00f https://{{}} -a -o {SAVES}wafw00f_{{}}.txt -f txt"
    WPSACN = f"wpscan --url https://{{}} --random-user-agent --enumerate ap,at,u,m -t 100"
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --api-token {API_WPSCAN}"
    NUCLEI = f"nuclei -l {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -jsonl -o {SAVES}nuclei_{{}}.json"
    NUCLEIUNIC = f"nuclei -u {{}}  -tags cve,security,misconfiguration -severity high,medium,critical -rate-limit 100 -timeout 5 -jsonl -o {SAVES}nucleiunique_{{}}.json"

class CommandEnumAgg(StrEnum):  #aggresive comands
    NMAPLIST = "nmap -T5 -iL {}"
    NMAP = "nmap -T5 {}"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode aggressive --plugins-detection aggressive --themes-detection aggressive --user-detection aggresive "
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode aggressive  --api-token {API_WPSCAN}"
    DNSX = f"dnsx -l {{}} -a -re-retry 3 -o {SAVES}dnsx_subdomains_{{}}.txt"
    DNSX2 = f"dnsx -l {{}} -a -ro -retry 3 -o {SAVES}dnsx_subdomains_{{}}.txt"


class CommandEnumCau(StrEnum):  #caution comands
    NMAPLIST = "nmap -T2 -iL {}"
    NMAP = "nmap -T2 {}"
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --thorough --insecure --force-recursion -o {SAVES}feroxbuster_{{}}.txt --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old --random-agent"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode passive --plugins-detection passive --themes-detection passive --user-detection passive "
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode passive  --api-token {API_WPSCAN}"
    SUBFINDER = f"subfinder -silent -recursive -d {{}} -t 10 -o {SAVES}subfinder_subdomain_{{}}.txt"
    DNSX = f'dnsx -l {{}} -a -re -rate-limit 5 -o {SAVES}dnsx_subdomains_{{}}.txt'
    DNSX2 = f'dnsx -l {{}} -a -ro -rate-limit 5 -o {SAVES}dnsx_subdomains_{{}}.txt'


#basic calls, they are here as a backup if you make any modification to the calls
'''

class CommandEnumDef(StrEnum):  #default call
    NMAP = "nmap -Pn -p- -sV -A -T4 {}"
    DMIRTY = "dmitry -i -w -n -s -e {}"
    SUBFINDER = f"subfinder -all -d -t 100 {{}} -o {SAVES}subfinder_subdomain_{{}}.txt"
    SUBFINDERECURSIVE = f'subfinder -all -recursive -d -t 100 {{}} -o {SAVES}subfinderecursive_subdomain_{{}}.txt'
    DNSX = f'dnsx -l {{}} -a -resp -o {SAVES}dnsx_subdomains_{{}}.txt'
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --insecure --thorough --force-recursion -o {SAVES}feroxbuster_{{}}.txt --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old"
    GOBUSTERDNS = f"gobuster dns -d {{}} -w {WORDLIST_DNS} -t 100 -o {SAVES}gobuster_dns_{{}}.txt"
    HARVESTER = f"theHarvester -d {{}} -b all -n -r >> {SAVES}harvester_{{}}.txt"
    WAF = f"wafw00f https://{{}} -a -o {SAVES}wafw00f_{{}}.txt -f txt"
    WPSACN = f"wpscan --url https://{{}} --random-user-agent --enumerate ap,at,u,m -t 100"
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --api-token {API_WPSCAN}"
    ALTDNS = f"altdns {{}} -w {WORDLIST_SUBDOMAINS} -r -n -e -d 8.8.8.8 -o {SAVES}altdns_alterated_{{}} -s {SAVES}altdns_resolved_{{}}.txt -t 50" #target ha de ser llista de subdominis cal?



class CommandEnumAgg(StrEnum):  #aggresive comands
    NMAP = "nmap -Pn -sV -T5 {}"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode aggressive --plugins-detection aggressive --themes-detection aggressive --user-detection aggresive "
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode aggressive  --api-token {API_WPSCAN}"

class CommandEnumCau(StrEnum):  #caution comands
    NMAP = "nmap -Pn -sV -T2 {}"
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --thorough --insecure --force-recursion -o {SAVES}feroxbuster_{{}}.txt --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old --random-agent"
    WPSACN = f"wpscan --url https://{{}} -t 100 --random-user-agent --enumerate ap,at,u,m --detection-mode passive --plugins-detection passive --themes-detection passive --user-detection passive "
    WPSCANVULN = f"wpscan --url https://{{}} --random-user-agent --enumerate vp,vt --detection-mode passive  --api-token {API_WPSCAN}"


'''


