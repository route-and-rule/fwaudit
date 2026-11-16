<div align="center">

# 🛡️ Firewall Audit Report

**Generated with fwaudit** · Route & Rule

![CRITICAL](https://img.shields.io/badge/CRITICAL-2-8B0000?style=for-the-badge)
![HIGH](https://img.shields.io/badge/HIGH-5-E67E22?style=for-the-badge)
![LOW](https://img.shields.io/badge/LOW-1-F1C40F?style=for-the-badge)
![CLEAN](https://img.shields.io/badge/CLEAN%20CONFIGS-1-2E8B57?style=for-the-badge)

</div>

---

## 📋 Executive summary

Three firewall configurations were audited: one **Cisco ASA** edge firewall and two
**Linux iptables** hosts, plus one well-built reference configuration.

| Config | Type | Rules | 🔴 Critical | 🟠 High | 🟡 Low | Verdict |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `asa.cfg` | Cisco ASA | 6 | 1 | 2 | 1 | ❌ **Fail** |
| `risky.rules` | Linux iptables | 5 | 1 | 3 | 0 | ❌ **Fail** |
| `good.rules` | Linux iptables | 4 | 0 | 0 | 0 | ✅ **Pass** |

> ⚠️ **Key risk:** both failing firewalls contain an **allow-everything rule**.
> Until it is removed, every other rule in those configs is effectively irrelevant.

---

## 🔴 Config 1: `asa.cfg` (Cisco ASA edge firewall)

```text
 fwaudit report: samples/asa.cfg (cisco)
 Rules checked: 6
 Findings: 1 critical | 2 high | 1 low
```

### 1. 🔴 CRITICAL: Line 9, allow everything
**Rule:** `access-list OUTSIDE_IN extended permit ip any any`

**Risk:** Any protocol, from any source on the internet, to any internal destination is permitted.
The firewall is effectively switched off for all traffic reaching this line.

**Fix:** Delete this rule. If it was added for troubleshooting, replace it with a narrow,
temporary rule for the exact host and port, and remove it afterwards.

### 2. 🟠 HIGH: Line 6, shadowed block rule
**Rule:** `access-list OUTSIDE_IN extended deny tcp host 198.51.100.66 host 203.0.113.10 eq 443`

**Risk:** This rule was added to block an abusive client, but **line 4 already permits HTTPS from any source**
to the same server. Because the first match wins, the deny is **never reached**: the client is *not* blocked.

**Fix:** Move the deny rule **above** line 4. Block-lists belong at the top.

### 3. 🟠 HIGH: Line 7, RDP exposed to the internet
**Rule:** `access-list OUTSIDE_IN extended permit tcp any host 203.0.113.20 eq 3389`

**Risk:** Remote Desktop is one of the most common ransomware entry points.
Exposing it to any source invites brute-force and exploit attempts.

**Fix:** Restrict the source to a VPN range or management subnet, or require VPN access for RDP.

### 4. 🟡 LOW: Line 5, duplicate rule
**Rule:** `access-list OUTSIDE_IN extended permit tcp any host 203.0.113.10 eq 443`

**Risk:** No security impact on its own, but duplicate rules clutter the config and make real problems harder to spot.

**Fix:** Delete it.

---

## 🔴 Config 2: `risky.rules` (Linux iptables host)

```text
 fwaudit report: samples/risky.rules (linux)
 Rules checked: 5
 Findings: 1 critical | 3 high | 0 low
```

### 1. 🔴 CRITICAL: Line 7, allow everything
**Rule:** `-A INPUT -j ACCEPT`

**Risk:** Every incoming connection is accepted, regardless of source or port.

**Fix:** Remove the rule and allow only the services this host actually provides.

### 2. 🟠 HIGH: Default policy is ACCEPT
**Rule:** `:INPUT ACCEPT`

**Risk:** Anything not explicitly blocked is allowed. Every forgotten service becomes reachable.

**Fix:** Switch to default-deny (`iptables -P INPUT DROP`), after first allowing established
traffic and your own admin access, so you don't lock yourself out.

### 3. 🟠 HIGH: Line 3, RDP exposed to any source
**Rule:** `-A INPUT -p tcp --dport 3389 -j ACCEPT`

**Fix:** Add `-s <admin-subnet>` to restrict who can connect.

### 4. 🟠 HIGH: Line 5, Telnet exposed to any source
**Rule:** `-A INPUT -p tcp --dport 23 -j ACCEPT`

**Risk:** Telnet sends usernames and passwords in **plain text**. Anyone on the path can read them.

**Fix:** Disable Telnet entirely and use SSH, restricted to an admin subnet.

---

## ✅ Config 3: `good.rules` (reference configuration)

```text
 fwaudit report: samples/good.rules (linux)
 Rules checked: 4
 Findings: 0 critical | 0 high | 0 low
 No problems found.
```

This configuration follows best practice and is included as a **reference**:

| Practice | Rule |
|---|---|
| 🔒 Default-deny policy | `:INPUT DROP` |
| 🔁 Loopback allowed | `-A INPUT -i lo -j ACCEPT` |
| 🔄 Replies to outbound connections allowed (stateful) | `-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` |
| 🎯 SSH only from the admin network (least privilege) | `-s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT` |
| 🌐 Public HTTPS service | `-p tcp --dport 443 -j ACCEPT` |

---

## 🧭 General recommendations

1. **Default-deny everywhere.** Allow only what is needed; let everything else fall through to DROP.
2. **Put block-lists at the top.** A deny rule below a broader allow never takes effect.
3. **Never expose admin services to the internet.** Use a VPN or jump host for SSH, RDP and databases.
4. **Remove "temporary" rules.** Troubleshooting rules like `permit ip any any` are often forgotten.
5. **Audit after every change.** Run fwaudit before a change goes live, and let its exit code block risky changes.

---

<div align="center">

*Report produced with* **[fwaudit](../README.md)** · Route & Rule 🌐

</div>