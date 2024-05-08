from strenum import StrEnum

# All comands can be modified to your liking.
# Every class will be the comands that are called by default, so if you want to customize them, go ahead.
# Further down, comments include a copy so as not to lose them once you have customized them.
class CommandEnumDef(StrEnum):  #default comands
    NMAP = "nmap -Pn -sV -T4 {}"
    DMIRTY = "dmitry -i -w -n -s -e {}"


class CommandEnumAgg(StrEnum):  #aggresive comands
    NMAP = "nmap -Pn -sV -T5 {}"


class CommandEnumCau(StrEnum):  #caution comands
    NMAP = "nmap -Pn -sV -T2 {}"


'''

'''


