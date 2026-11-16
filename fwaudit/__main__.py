import sys
from fwaudit.parser import parse_file
from fwaudit.analyzer import find_order_problems, find_risky_rules
from fwaudit.cisco_parser import parse_cisco_file

# Order of importance: worst first
SEVERITY_ORDER = ["[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]"]


def severity_rank(finding):
    """Give each finding a number so the worst ones come first.
    [CRITICAL] -> 0, [HIGH] -> 1, [MEDIUM] -> 2, [LOW] -> 3"""
    for rank, tag in enumerate(SEVERITY_ORDER):
        if finding.startswith(tag):
            return rank
    return len(SEVERITY_ORDER)          # unknown tags go last

def detect_type(path):
    """Look inside the file and decide: cisco or linux"""

    with open(path) as f:
        text = f.read()

    if "access-list" in text:
        return "cisco"
    else:
        return "linux"
    
def main():
    # 1. Did the user give a file name?
    #    sys.argv = the words typed:  ['...fwaudit', 'samples/risky.rules']
    if len(sys.argv) < 2:
        print("Usage: python -m fwaudit <rules-file>")
        sys.exit(1)

    path = sys.argv[1]

    # 2. Read the file and run all the checks
    kind = detect_type(path)
    if kind == "cisco":
        rules, policies = parse_cisco_file(path)
    else:
        rules, policies = parse_file(path)

    findings = find_order_problems(rules) + find_risky_rules(rules, policies)
    findings.sort(key=severity_rank)    # worst problems first

    # 3. Count each severity
    critical = 0
    high = 0
    low = 0
    for f in findings:
        if f.startswith("[CRITICAL]"):
            critical += 1
        elif f.startswith("[HIGH]"):
            high += 1
        elif f.startswith("[LOW]"):
            low += 1

    # 4. Print the report
    print("=" * 50)
    print(f" fwaudit report: {path} ({kind})")
    print(f" Rules checked: {len(rules)}")
    print(f" Findings: {critical} critical | {high} high | {low} low")
    print("=" * 50)

    if not findings:
        print("No problems found.")
    for f in findings:
        print(f)

    # 5. Exit code: 0 = all good, 2 = serious problems found
    #    (lets other programs/pipelines know if the firewall is safe)
    if critical > 0 or high > 0:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()