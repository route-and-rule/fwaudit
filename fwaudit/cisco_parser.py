import ipaddress
from fwaudit.models import Rule, ANY_NET

def parse_address(words, i):
    """Read a cisco address starting at words[i].
    Returns (network, position of the next word)."""

    if words[i] == "any":
        return ANY_NET,i+1
    
    if words[i] == "host":
        return ipaddress.ip_network(words[i+1]), i+2 

    
    network = ipaddress.ip_network(f"{words[i]}/{words[i+1]}")
    return network, i+2

# ---- NEW ----

PORT_NAMES = {"www": 80, "http": 80, "https": 443, "ssh": 22,
              "telnet": 23, "ftp": 21, "domain": 53, "smtp": 25}

def port_number(word):
    """'https' --> 443, '3389' --> 3389"""
    if word in PORT_NAMES:
        return PORT_NAMES[word]
    return int(word)

def parse_acl_line(text, line_number):
    words = text.split()

    chain = words[1]

    if words[3] == "permit":
        action = "ACCEPT"
    else:
        action = "DROP"

    proto = words[4]
    if proto == "ip":
        proto = "any"


    src, i = parse_address(words, 5)
    dst, i = parse_address(words, i)

    rule = Rule(line=line_number, chain=chain, action=action,
                proto=proto, src=src, dst=dst)

    if i < len(words) and words[i] == "eq":
        port = port_number(words[i+1])
        rule.dport = (port,port)

    return rule

def parse_cisco_file(path):
    rules = []
    policies = {}

    with open(path) as f:
        lines = f.readlines()

    for number, line in enumerate(lines, 1):
        line = line.strip()

        if line.startswith("access-list") == False:
            continue
        words = line.split()

        if words[2] != "extended":
            continue

        rule = parse_acl_line(line,number)

        rules.append(rule)

        policies[rule.chain] = "DROP"

    return rules, policies