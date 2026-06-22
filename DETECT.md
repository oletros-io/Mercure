# DETECT.md - Detection Analysis

How a SOC/WAF/EDR would detect Mercure's traffic, how the tool behaves, and what residual signals remain.

## 1. Baseline - Raw DNS Query Behavior

Without any evasion, Mercure generates a recognizable DNS query pattern:

| Behavior | Detection Signal | Severity |
|---|---|---|
| Burst of TXT queries (`_dmarc.`, `v=spf1`, `selector._domainkey.`) | Unusual volume of TXT queries from a single source in a short window | Medium |
| Sequential checks across 12 record types (A, AAAA, MX, NS, CAA, DS, DNSKEY, TLSA, SRV, TXT, PTR) + SMTP probe | Full DNS reconnaissance fingerprint -- very few legitimate clients query all types | High |
| SMTP connection to `*.mail.protection.outlook.com:25` (Ghost Sender check) | Direct SMTP probe to EXO endpoint is unusual from non-mail infrastructure. EHLO mimics `mail.<domain>` but source IP doesn't match SPF | Medium |
| DKIM selector bruteforce (100-2000+ TXT queries to `*._domainkey.domain`) | Massive volume of NXDOMAIN responses for non-existent selectors | High |
| Aggressive mode year/month patterns (`dkim-2024-q1._domainkey.`, etc.) | Sequential enumeration pattern in subdomain queries | High |
| Concurrent DNS queries via ThreadPoolExecutor | Parallel resolution from same source IP | Low |

| SMTP connections to recipient MX on port 25 (Spoof mode, direct) | Direct SMTP delivery of spoofed emails -- full email content in mail server logs. Source IP recorded | Critical |
| SMTP connections via authenticated relay (Spoof mode, relay) | Email delivered through relay provider. Relay logs authenticated user, recipient sees relay IP (not attacker IP). SPF passes for relay domain but DMARC alignment fails for spoofed domain | High |
| Multiple SMTP sessions to same MX within seconds (Spoof mode, 12 methods) | Repeated connections with different senders/envelopes is a spoofing test pattern | High |
| Multi-recipient RCPT TO to dead addresses in single session (bs_amp) | 5 RCPT TO to nonexistent addresses in one SMTP session — classic amplification probe | High |
| Emails to functional mailboxes from spoofed return-path (bs_oob) | Messages to info@/contact@/support@ with return-path set to external victim — auto-reply harvesting | Medium |

**Baseline detection score: ~70%** for a DNS-aware monitoring system. **~95%** when spoof mode is used (actual email delivery attempts).

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

**Defender's view**: An SMTP connection to `<dashed-domain>.mail.protection.outlook.com:25` from an external, non-mail-server IP. The SMTP session performs `MAIL FROM` + `RCPT TO` without sending `DATA` -- a classic SMTP enumeration pattern.

**Detection rules**:
```
# Sigma-style rule
title: Ghost Sender SMTP Probe
detection:
  selection:
    dst_port: 25
    dst_hostname|endswith: '.mail.protection.outlook.com'
  filter_legitimate:
    src_ip|cidr: <known_seg_ranges>
  condition: selection and not filter_legitimate
```

**Mercure's behavior**: Single SMTP connection per domain. EHLO with `mail.<target-domain>` (mimics legitimate MTA), MAIL FROM with `postmaster@<target-domain>`, RCPT TO with `postmaster@target`. No DATA command, no actual email delivery. Connection closed with RSET+QUIT. No unique tool signature in SMTP handshake.

**Residual signal**: The SMTP session is logged by Exchange Online. Microsoft's internal telemetry captures the source IP, EHLO hostname, and MAIL FROM. The EHLO and MAIL FROM look legitimate but the source IP won't match the domain's SPF-authorized servers. The defender can see the probe in Exchange Online message trace (even failed sessions are logged).

**Key difference from DNS checks**: This is an **active probe** that touches the target's mail infrastructure directly. It leaves a trail in Exchange Online logs, unlike passive DNS queries that only touch the recursive resolver.

### 3.4 Spoof Mode - SMTP Email Delivery

**Defender's view**: Multiple SMTP connections to the recipient's MX on port 25 within seconds. Each connection attempts a full SMTP transaction (EHLO → MAIL FROM → RCPT TO → DATA) with a spoofed sender. The only non-standard header is `X-Oletros-Tool`.

**Detection rules**:
```
# Sigma-style rule
title: Mercure Spoof Test Detection
detection:
  selection_header:
    email_header|contains: 'X-Oletros-Tool'
  selection_subject:
    smtp_subject|startswith: 'Security Test - '
  selection_pattern:
    smtp_mail_from|startswith: 'mercure@'
  condition: selection_header or (selection_subject and selection_pattern)
```

**Mercure's behavior**: 4 sequential SMTP connections per target domain:
1. Direct delivery via recipient MX with spoofed sender
2. Ghost delivery to EXO direct endpoint (if applicable)
3. Null envelope sender with spoofed From header
4. Subdomain sender (`nonexistent.<domain>`)

Each connection uses EHLO `mail.<sender-domain>` (mimics legitimate MTA), attempts STARTTLS if offered. Message-ID format: `<uuid>@<sender-domain>`. Subject includes method: `Security Test - direct`, `Security Test - ghost`, etc.

**Residual signals**:
- `X-Oletros-Tool` header (intentional attribution — only identifiable signature)
- Source IP in SMTP connection logs (not SPF-authorized for the spoofed domain)
- `mercure@` sender local-part pattern
- Subject contains "Security Test - <method>"
- Nine connections to the same MX in rapid succession (or mix of relay + direct)
- Exchange Online message trace records all delivery attempts (even failed)
- Lorem ipsum body content

### 3.5 Relay Mode Detection Profile

**Defender's view**: When relay is configured, 5 of 9 methods route through the authenticated SMTP relay (e.g. `ssl0.ovh.net:465`). The recipient MX sees the relay's IP, not the attacker's.

**Detection differences vs direct**:
- SPF: passes for relay domain (e.g. `ovh.net`), but DMARC alignment fails because From domain differs
- Source IP: relay provider's IP — no direct attribution to attacker's IP in recipient logs
- `Received:` headers: contain relay hostname and relay's internal routing — identifiable as OVH/provider infrastructure
- `Authentication-Results:` header: SPF pass on relay domain, DKIM depends on relay's signing policy

**Relay-side detection**: The relay provider logs the authenticated session — username, source IP, recipients, timestamps. This is the primary attribution trail when using relay.

**Residual signals specific to relay mode**:
- Relay server name visible in `Received:` headers
- Authenticated user's email domain may differ from spoofed From domain
- Some relays add `X-Authenticated-Sender` or similar headers
- Relay provider may rate-limit or block after repeated sends with mismatched From domains

**Risk level**: **HIGH** (reduced from CRITICAL vs direct). The attacker's IP is hidden behind the relay, but the relay provider has full attribution.

**Risk level**: **CRITICAL**. Unlike score mode (passive DNS queries), spoof mode actively attempts to deliver emails. This leaves evidence in:
- Recipient mail server logs
- Exchange Online message trace
- SEG logs (Proofpoint, Mimecast, etc.)
- DMARC aggregate reports (rua)
- DMARC forensic reports (ruf)
- SPF authentication results in received headers

### 3.5 Multi-Domain Batch Mode

**Defender's view**: When Mercure processes a file of domains, the same query pattern repeats for each domain. This creates a periodic, machine-like cadence.

**Residual signal**: Identical check ordering across multiple domains is a strong indicator of automated tooling.

## 4. Limitation Inventory

| Residual Signal | Mode | Severity | Mitigation |
|---|---|---|---|
| High NXDOMAIN ratio from DKIM bruteforce | All modes | High | Use `--no-bruteforce` to skip selector enumeration |
| Full 12-type DNS reconnaissance | Default | High | Use `--checks` to limit to specific checks |
| SMTP probe to EXO endpoint on port 25 | Ghost check | High | Exclude ghost check: `--checks spf,dkim,dmarc,...` |
| Source IP not in SPF for EHLO domain | Ghost + Spoof (direct) | Medium | EHLO mimics `mail.<domain>` but source IP won't match SPF |
| Authenticated relay user mismatch | Spoof (relay) | Medium | Relay authenticates as one user but sends as another domain |
| `X-Oletros-Tool` header in delivered emails | Spoof mode | High | Intentional attribution header (only tool-specific signature) |
| `mercure@` sender + `Security Test - <method>` subject | Spoof mode | Medium | Identifiable spoofing test pattern |
| Source IP in recipient SMTP logs | Spoof mode | Critical | Direct attribution to testing origin |
| DMARC failure reports to `rua`/`ruf` endpoints | Spoof mode | High | SPF/DKIM failures generate reports to domain owner |
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
| Spoof mode (direct) | Very High (85%) | Very High (95%) | Critical (99%) |
| Spoof mode (relay) | High (60%) | High (75%) | Very High (90%) |

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
