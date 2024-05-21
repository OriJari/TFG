from strenum import StrEnum

# All comands can be modified to your liking.
# Every class will be the comands that are called by default, so if you want to customize them, go ahead.
# Further down, comments include a copy so as not to lose them once you have customized them.

WORDLIST_DNS = "lists/amass/all.txt"
WORDLIST_SUBDOMAINS = "lists/amass/subdomains-top1mil-110000.txt"
WORDLIST_DIR = "lists/dirbuster/directory-list-2.3-medium.txt"

SAVES = "results/temp/"

class CommandEnumDef(StrEnum):  #default call
    NMAP = "nmap -Pn -p- -sV -A -T4 {}"
    DMIRTY = "dmitry -i -w -n -s -e {}"
    SUBFINDER = f"subfinder -all -d -t 100 {{}} -o {SAVES}subfinder_subdomain_{{}}.txt"
    SUBFINDERECURSIVE = f'subfinder -all -recursive -d -t 100 {{}} -o {SAVES}subfinderecursive_subdomain_{{}}.txt'
    DNSX = f'dnsx -l {{}} -a -resp -o {SAVES}dnsx_subdomains_{{}}.txt'
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --insecure --thorough --force-recursion -o {SAVES}feroxbuster_{{}}.txt --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old"
    GOBUSTERDNS = f"gobuster dns -d {{}} -w {WORDLIST_DNS} -t 100 -o {SAVES}gobuster_dns_{{}}.txt"
    GOBUSTERDIR = f"gobuster dir -u https://{{}} -w {WORDLIST_DIR} -x html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old -t 100 -o {SAVES}gobuster_dir_{{}}.txt"
    NSLOOKUP = "nslookup {}"
    HARVESTER = f"theHarvester -d {{}} -b all -n -r >> {SAVES}harvester_{{}}.txt"
    WAF = f"wafw00f https://{{}} -a -o {SAVES}wafw00f_{{}}.txt -f txt"





class CommandEnumAgg(StrEnum):  #aggresive comands
    NMAP = "nmap -Pn -sV -T5 {}"


class CommandEnumCau(StrEnum):  #caution comands
    NMAP = "nmap -Pn -sV -T2 {}"
    FEROXBUSTER = f"feroxbuster -u {{}} -t 200 -d 0 --thorough --insecure --force-recursion -o {SAVES}feroxbuster_{{}}.txt --extensions html,php,asp,aspx,jsp,js,css,png,jpg,gif,pdf,xml,txt,log,bak,old --random-agent"


'''

'''


