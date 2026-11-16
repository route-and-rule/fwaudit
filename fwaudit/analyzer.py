def covers(a, b):
    """True if rule a matches every packet that rule b matches"""

    if not (a.proto == "any" or a.proto == b.proto):
        return False

    if not b.src.subnet_of(a.src):
        return False

    if not b.src.subnet_of(a.src):
        return False

    if not (a.dport[0] <= b.dport[0] and b.dport[1] <= a.dport[1]):
        return False

    if not (a.in_if is None or a.in_if == b.in_if):
        return False

    if not (a.out_if is None or a.out_if == b.out_if):
        return False

    if not (a.state is None or a.state == b.state):
        return False

    return True


def find_order_problems(rules):
    findings = []

    for j in range(len(rules)):
        later = rules[j]

        for i in range(j):
            earlier = rules[i]

            if covers(earlier,later):
                if earlier.action != later.action:
                    msg = f"[HIGH] Line {later.line} is SHADOWED: line {earlier.line} already does {earlier.action} for this traffic, so {later.action} never happens."
                
                else:
                    msg = f"[LOW] Line {later.line} is a DUPLICATE: line {earlier.line} already does {earlier.action} for this traffic. Delete it"
                findings.append(msg)
                break

    return findings
        
DANGEROUS_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 3306: "MySQL", 5900: "VNC"}

def find_risky_rules(rules, policies):
    findings = []

    if policies.get("INPUT") == "ACCEPT":
        findings.append("[HIGH] Chain INPUT has default policy ACCEPT: anything not blocked is allowed.")

    for rule in rules:
        if rule.action != "ACCEPT":
            continue
        if rule.in_if == "lo":
            continue
        if rule.state is not None and "NEW" not in rule.state:
            continue
        src_any = rule.src.prefixlen == 0 
        dst_any = rule.dst.prefixlen == 0
        low,high = rule.dport

        if rule.proto == "any" and src_any and dst_any and (low, high) == (0,65535):
            findings.append(f"[CRITICAL] Line {rule.line}: allows ALL traffic from anywhere to anywhere. This disables the firewall.")
            continue

        for port, name in DANGEROUS_PORTS.items():
            if src_any and low <= port <= high:
                findings.append(f"[HIGH] Line {rule.line}: {name} (port {port}) is open to ANY source. Restrict it to an admin network or VPN.")

    return findings
