<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=44&duration=3000&pause=100000&color=00D4FF&center=true&vCenter=true&repeat=false&width=600&height=70&lines=fwaudit" alt="fwaudit" />

### 🔥 Firewall Policy Analyzer for Linux iptables & Cisco ASA

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&pause=1000&color=8AB4F8&center=true&vCenter=true&width=650&lines=Finds+shadowed+rules+that+never+take+effect;Catches+SSH%2C+RDP+%26+Telnet+open+to+the+internet;Flags+rules+that+allow+everything;One+command.+Worst+problems+first." alt="Typing animation" />

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-iptables-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Cisco](https://img.shields.io/badge/Cisco-ASA%20ACLs-1BA0D7?style=for-the-badge&logo=cisco&logoColor=white)
![No dependencies](https://img.shields.io/badge/dependencies-none-2E8B57?style=for-the-badge)

**[📄 View a sample audit report](docs/REPORT.md)**

</div>

---

## 🧐 The problem

Firewalls read rules **top to bottom, and the first match wins**. Over the years, rule lists grow
to hundreds of lines written by different people, and mistakes slip in:

- 🚫 A **block rule that never works**, because an earlier rule already allows the same traffic
- ♻️ **Duplicate rules** that clutter the config and hide real problems
- 🌍 **Admin services open to the whole internet**: SSH, RDP, Telnet, databases
- 💥 A forgotten **`permit ip any any`** that silently turns the firewall off

Finding these by reading configs by hand is slow and error-prone.
**fwaudit finds them in under a second.**

---

## ✨ What it detects

| Severity | Check | What it means |
|:---:|---|---|
| 🔴 **CRITICAL** | **Allow everything** | A rule that accepts any protocol, from anywhere, to anywhere |
| 🟠 **HIGH** | **Shadowed rule** | An earlier rule matches all of this rule's traffic with the *opposite* action, so this rule never takes effect |
| 🟠 **HIGH** | **Dangerous service exposed** | SSH (22), Telnet (23), SMB (445), MySQL (3306), RDP (3389) or VNC (5900) allowed from **any** source |
| 🟠 **HIGH** | **Default-allow policy** | The `INPUT` chain falls through to `ACCEPT`, so anything not blocked gets in |
| 🟡 **LOW** | **Duplicate rule** | An earlier rule already makes the same decision, so this one is dead weight |

### 🧠 Smart enough to avoid false alarms
- ✅ **Loopback rules** (`-i lo`) are recognised as safe
- ✅ **Stateful rules** (`ESTABLISHED,RELATED`) are understood: they only allow replies, so they are never flagged as "allow everything"
- ✅ **Least privilege is rewarded**: SSH restricted to an admin subnet is *not* flagged
- ✅ **Public services** like HTTPS (443) open to everyone are treated as normal

---

## 🚀 Quick start

No installation needed, just Python 3.8+.

```bash
git clone https://github.com/route-and-rule/fwaudit.git
cd fwaudit

python -m fwaudit samples/asa.cfg        # Cisco ASA example
python -m fwaudit samples/risky.rules    # Linux iptables example
python -m fwaudit samples/good.rules     # a clean, well-built firewall
```

The file type (**Linux** or **Cisco**) is **detected automatically**.

### Audit your own firewall
```bash
# Linux: export your live rules
sudo iptables-save > my-rules.txt
python -m fwaudit my-rules.txt

# Cisco ASA: save "show running-config" to a file
python -m fwaudit edge-firewall.cfg
```

---

## 📟 Example output

```text
==================================================
 fwaudit report: samples/asa.cfg (cisco)
 Rules checked: 6
 Findings: 1 critical | 2 high | 1 low
==================================================
[CRITICAL] Line 9: allows ALL traffic from anywhere to anywhere. This disables the firewall.
[HIGH] Line 6 is SHADOWED: line 4 already does ACCEPT for this traffic, so DROP never happens.
[HIGH] Line 7: RDP (port 3389) is open to ANY source. Restrict it to an admin network or VPN.
[LOW] Line 5 is a DUPLICATE: line 4 already does ACCEPT for this traffic. Delete it.
```

Findings are **sorted worst-first**, so the most urgent problem is always at the top.

---

## 🚦 Exit codes: use it as a safety gate

| Code | Meaning |
|:---:|---|
| `0` | ✅ No critical or high findings |
| `1` | ⚠️ Usage error (no file given) |
| `2` | ❌ Critical or high findings: **this firewall needs attention** |

Because of this, fwaudit can run **automatically before a firewall change goes live**
and block risky changes until they are fixed.

---

## ⚙️ How it works

```text
  Linux rules ──► parser.py ───────┐
                                   ├──► Rule objects ──► analyzer.py ──► sorted report
  Cisco config ─► cisco_parser.py ─┘          ▲
                                       same format for both
```

1. **Auto-detect**: the tool looks for `access-list` to decide between Cisco and Linux
2. **Parse**: each vendor's syntax is translated into the same vendor-neutral `Rule` object
   (protocol, source, destination, port, interfaces, connection state, action)
3. **Analyze**: the core function `covers(a, b)` answers *"does rule A match every packet rule B matches?"*
   by comparing subnets, port ranges, protocols, interfaces and state
4. **Report**: findings are counted, sorted by severity, and printed with a clear fix

> 💡 **Design highlight:** adding Cisco support required **zero changes** to the analyzer.
> A new vendor only needs a new parser.

---

## 🗂️ Project structure

```text
fwaudit/
├── fwaudit/
│   ├── __main__.py       # command-line entry point, auto-detect, report
│   ├── models.py         # the vendor-neutral Rule object
│   ├── parser.py         # Linux iptables parser
│   ├── cisco_parser.py   # Cisco ASA ACL parser
│   └── analyzer.py       # covers(), shadow/duplicate & risk checks
├── samples/
│   ├── test.rules        # iptables with order mistakes
│   ├── risky.rules       # iptables with dangerous rules
│   ├── good.rules        # a clean, well-designed firewall
│   └── asa.cfg           # Cisco ASA config with planted problems
└── docs/
    └── REPORT.md         # sample audit report
```

---

## 📌 Supported syntax

| | Linux iptables | Cisco ASA |
|---|---|---|
| **Rules** | `-A CHAIN ... -j ACCEPT/DROP` | `access-list NAME extended permit/deny ...` |
| **Protocol** | `-p tcp/udp/icmp` | `tcp`, `udp`, `icmp`, `ip` (= any) |
| **Addresses** | `-s`, `-d` (IP or CIDR) | `any`, `host x.x.x.x`, `network mask` |
| **Ports** | `--dport 22` | `eq 22`, `eq https`, `eq www`... |
| **Interfaces** | `-i`, `-o` | — |
| **Connection state** | `--ctstate` / `--state` | — |
| **Default policy** | `:INPUT DROP` | implicit deny at the end of every ACL |

### Current limitations
- Single destination ports only (no ranges like `8000:9000` or `multiport` lists yet)
- IPv4 only
- Cisco `object-group` references are not expanded

---

## 🎓 What I learned building this

- How firewalls **really** evaluate rules: first match wins, and why **rule order matters**
- **Stateful filtering**: the difference between `NEW`, `ESTABLISHED` and `RELATED` connections
- How **subnets contain other subnets**, and how to compare port ranges
- Reading **Cisco ASA ACLs** and translating them to the same model as iptables
- Why **false positives** matter: a security tool that cries wolf gets ignored

---

<div align="center">

**Built by Urvisha Bhoi** · part of **[Route & Rule](https://github.com/route-and-rule)** 🌐

*"Every network is only as strong as its weakest rule."*

</div>