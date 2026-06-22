# DETECT.md - Detection Analysis

How a SOC/WAF/EDR would detect Mercure's traffic, how the tool behaves, and what residual signals remain.

## 1. Baseline - Raw DNS Query Behavior

Without any evasion, Mercure generates a recognizable DNS query pattern:

| Behavior | Detection Signal | Severity |
|---|---|---|
| Burst of TXT queries (`_dmarc.`, `v=spf1`, `selector._domainkey.`) | Unusual volume of TXT queries from a single source in a short window | Medium |
| Sequential checks across 12 record types (A, AAAA, MX, NS, CAA, DS, DNSKEY, TLSA, SRV, TXT, PTR) + SMTP probe | Full DNS reconnaissance fingerprint -- very few legitimate clients query all types | High |
| SMTP connection to `*.mail.protection.outlook.com:25` (Ghost Sender check) | Direct SMTP probe to EXO endpoint is unusual from non-mail infrastructure. EHLO hostname `mercure.audit.local` is identifiable | High |
| DKIM selector bruteforce (100-2000+ TXT queries to `*._domainkey.domain`) | Massive volume of NXDOMAIN responses for non-existent selectors | High |
| Aggressive mode year/month patterns (`dkim-2024-q1._domainkey.`, etc.) | Sequential enumeration pattern in subdomain queries | High |
| Concurrent DNS queries via ThreadPoolExecutor | Parallel resolution from same source IP | Low |

**Baseline detection score: ~70%** for a DNS-aware monitoring system.

## 2. Feature Inventory

| Feature | Evasion Type | Status | Detection Impact |
|---|---|---|---|
| Standard DNS resolution via system resolver | Passive | Active | Blends with normal DNS traffic |
| Configurable DNS timeout | Timing | Active | Prevents timeout-based fingerprinting |
| Configurable thread count | Rate control | Active | Allows throttling to avoid burst detection |
| No HTTP/TLS traffic (except Ghost SMTP) | Protocol absence | Active | No web fingerprinting possible |
| Ghost Sender SMTP probe | Active recon | Active | SMTP handshake to EXO port 25 with identifiable EHLO |
| Log-to-disk only | No exfiltration | Active | No outbound data channel to detect |

## 3. Deep Dives

### 3.1 DNS Query Pattern

**Defender's view**: A DNS monitoring system (Passive DNS, DNS firewall, or SIEM with DNS logs) will see:

1. A burst of queries to the target domain across multiple record types
2. A high NXDOMAIN ratio from DKIM selector bruteforce
3. Sequential queries to `_domainkey.` subdomains with common selector names

**Mercure's behavior**: Queries are made through the system's configured DNS resolver (typically ISP or corporate resolver). No direct queries to authoritative nameservers.

**Residual signal**: The query pattern is distinctive. A defender who logs DNS queries at the recursive resolver level can reconstruct the full check sequence and identify it as a security audit tool.

### 3.2 DKIM Selector Bruteforce

**Defender's view**: 100+ (default) or 2000+ (aggressive) TXT queries to `*._domainkey.target.com` in rapid succession. The NXDOMAIN ratio will be very high (typically 95%+).

**Detection rules**:
```
# Sigma-style rule
title: DKIM Selector Enumeration
detection:
  selection:
    query_type: TXT
    query_name|endswith: '._domainkey.'
  condition: selection | count(query_name) > 50 within 5m from same source
```

**Mercure's behavior**: No randomization of query order. No delays between queries. Thread pool fires as fast as the resolver allows.

**Residual signal**: Even with threading reduced to 1, the sequential pattern of `default._domainkey`, `selector1._domainkey`, `google._domainkey` etc. is recognizable.

### 3.3 Ghost Sender SMTP Probe

**Defender's view**: An SMTP connection to `<dashed-domain>.mail.protection.outlook.com:25` from an external, non-mail-server IP. The EHLO hostname `mercure.audit.local` is a clear tool signature. The SMTP session performs `MAIL FROM` + `RCPT TO` without sending `DATA` -- a classic SMTP enumeration pattern.

**Detection rules**:
```
# Sigma-style rule
title: Ghost Sender SMTP Probe
detection:
  selection:
    dst_port: 25
    dst_hostname|endswith: '.mail.protection.outlook.com'
    smtp_ehlo|contains: 'mercure'
  condition: selection
```

**Mercure's behavior**: Single SMTP connection per domain. EHLO with `mercure.audit.local`, MAIL FROM with `probe@mercure.audit.local`, RCPT TO with `postmaster@target`. No DATA command, no actual email delivery. Connection closed with RSET+QUIT.

**Residual signal**: The SMTP session is logged by Exchange Online. Microsoft's internal telemetry captures the source IP, EHLO hostname, and MAIL FROM. The `mercure.audit.local` EHLO is a unique signature. The defender can also see the probe in Exchange Online message trace (even failed sessions are logged).

**Key difference from DNS checks**: This is an **active probe** that touches the target's mail infrastructure directly. It leaves a trail in Exchange Online logs, unlike passive DNS queries that only touch the recursive resolver.

### 3.4 Multi-Domain Batch Mode

**Defender's view**: When Mercure processes a file of domains, the same query pattern repeats for each domain. This creates a periodic, machine-like cadence.

**Residual signal**: Identical check ordering across multiple domains is a strong indicator of automated tooling.

## 4. Limitation Inventory

| Residual Signal | Mode | Severity | Mitigation |
|---|---|---|---|
| High NXDOMAIN ratio from DKIM bruteforce | All modes | High | Use `--no-bruteforce` to skip selector enumeration |
| Full 12-type DNS reconnaissance | Default | High | Use `--checks` to limit to specific checks |
| SMTP probe to EXO endpoint on port 25 | Ghost check | High | Exclude ghost check: `--checks spf,dkim,dmarc,...` |
| `mercure.audit.local` EHLO signature | Ghost check | High | Identifiable in Exchange Online logs |
| Query volume spike | Batch mode | Medium | Reduce `--threads` to 1-2, add delays (not implemented) |
| Sequential query pattern | All modes | Medium | Query order is fixed; no randomization |
| Recursive resolver logs | All modes | Low | Use a dedicated resolver or DNS-over-HTTPS (external) |

## 5. Risk Matrix

| Mode | Basic DNS Monitoring | Corporate DNS Firewall | Enterprise SIEM + DNS |
|---|---|---|---|
| Single domain, no bruteforce | Low (10%) | Low (15%) | Medium (30%) |
| Single domain, default | Medium (30%) | Medium (45%) | High (65%) |
| Single domain, aggressive | High (50%) | High (70%) | High (85%) |
| Batch mode, default | High (60%) | High (75%) | Very High (90%) |
| Batch mode, aggressive | Very High (80%) | Very High (90%) | Very High (95%) |

## 6. Recommendations

| Target Profile | Recommended Config | Rationale |
|---|---|---|
| No monitoring | `python mercure.py -d target.com --aggressive` | Full coverage, speed doesn't matter |
| Basic DNS logs | `python mercure.py -d target.com --threads 2` | Reduce burst, keep bruteforce |
| Corporate DNS firewall | `python mercure.py -d target.com --no-bruteforce` | Avoid DKIM enumeration spike |
| Enterprise SIEM | `python mercure.py -d target.com --checks spf,dmarc,caa --no-bruteforce` | Minimal footprint, high-value checks only |
| Stealth recon | Manual `dig` queries for SPF/DMARC/CAA only | Mercure's pattern is too recognizable for stealth |

## 7. Behavioral Analysis

### Statistical Detection

A DNS monitoring system with behavioral baselines can detect Mercure via:

1. **Query type diversity**: 11 different record types to a single domain within seconds is abnormal for any legitimate client
2. **NXDOMAIN ratio**: DKIM bruteforce generates 95%+ NXDOMAIN, far above normal baselines
3. **Query cadence**: Machine-generated queries have sub-second intervals with no human think time
4. **Subdomain enumeration**: `*._domainkey` queries follow a dictionary pattern

### ML-Based Detection

Supervised models trained on DNS logs would flag Mercure based on:
- Feature vector: (query_type_count=11, nxdomain_ratio=0.95, queries_per_minute=500, unique_subdomains=100)
- This vector is far outside the cluster of normal browsing/email behavior

### Bypass Limitations

Mercure does NOT implement:
- Query order randomization
- Inter-query delays or jitter
- DNS-over-HTTPS/TLS (resolver selection is external)
- Split queries across multiple resolvers
- Time-spread scanning (all checks run immediately)

These are intentional: Mercure is an auditing tool, not a stealth scanner. Defenders should assume that a determined attacker would implement these techniques independently.
