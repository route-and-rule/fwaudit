import ipaddress
from fwaudit.models import Rule

def parse_line(text, line_number):
    words = text.split()

    chain = None
    action = None
    proto = "any"
    src = None
    dst = None
    dport = None
    in_if = None
    out_if = None
    state = None

    i = 0
    while i < len(words):
        word = words[i]

        if word == "-A":
            chain = words[i+1]
            i=i+2
        elif word == "-p":
            proto = words[i+1]
            i=i+2
        elif word == "-j":
            action = words[i+1]
            i=i+2
        elif word == "-s":
            src = ipaddress.ip_network(words[i+1])
            i=i+2
        elif word == "-d":
            dst = ipaddress.ip_network(words[i+1])
            i=i+2
        elif word == "--dport":
            port = int(words[i+1])
            dport = (port,port)
            i+=2
        elif word == "-i":
            in_if = words[i+1]
            i+=2
        elif word == "-o":
            out_if = words[i+1]
            i += 2
        elif word == "--ctstate" or word == "--state":
            state = words[i+1]
            i+=2
        else:
            i+=1

    rule = Rule(line=line_number, chain=chain, action=action, proto=proto)
    if src is not None:
        rule.src = src
    if dport is not None:
        rule.dport = dport
    if dst is not None:
        rule.dst = dst
    if in_if is not None:
        rule.in_if = in_if
    if out_if is not None:
        rule.out_if = out_if
    if state is not None:                          
        rule.state = state
    return rule

def parse_file(path):
    rules = []
    policies = {}

    with open(path) as f:
        lines = f.readlines()

    for number, line in enumerate(lines, 1):
        line = line.strip()

        if line == "" or line.startswith("#"):
            continue
        if line.startswith("*") or line == "COMMIT":
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            chain = parts[0]
            policy = parts[1]
            policies[chain] = policy

        if line.startswith("-A"):
            rules.append(parse_line(line, number))

    return rules, policies
            


