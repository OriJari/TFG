from strenum import StrEnum

# All comands can be modified to your liking.
# Every class will be the comands that are called by default, so if you want to customize them, go ahead.
# Further down, comments include a copy so as not to lose them once you have customized them.
class CommandEnumDef(StrEnum):  #default comands
    NMAP = "nmap -Pn -p- -sV -A -T4 {}"
    DMIRTY = "dmitry -i -w -n -s -e {}"
    SUBFINDER = "subfinder -all -d -t 100 {} -o temp/subfinder_subdomain_{}.txt"
    SUBFINDERECURSIVE = "subfinder -all -recursive -d -t 100 {} -o temp/subfinderecursive_subdomain_{}.txt"
    DNSX = "dnsx -l {} -a -resp -o temp/dnsx_subdomains_{}.txt"



class CommandEnumAgg(StrEnum):  #aggresive comands
    NMAP = "nmap -Pn -sV -T5 {}"


class CommandEnumCau(StrEnum):  #caution comands
    NMAP = "nmap -Pn -sV -T2 {}"


'''

'''


