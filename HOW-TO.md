# HOW-TO.md - Operational Playbook

## 1. Quick Start

```bash
pip install -r requirements.txt

# Score mode - audit domain security posture (49 checks: 31 passive, 8 external, 10 intrusive)
python mercure.py score -d example.com

# Intrusive mode - SMTP recon, user enum, port scan, zone walking, vuln scanning
python mercure.py score -d target.com --intrusive

# Spoof mode - test if spoofed emails actually get delivered (12 methods)
python mercure.py spoof -d target.com -r recipient@example.com
```

Score mode outputs a dual scoring table:
- **Security**: 10/10 = hardened, 0/10 = exposed (weighted security posture)
- **Exploitability**: 10/10 = trivially exploitable, 0/10 = impractical (weighted by attack ease - like CVSS vs KEV)

Results are auto-saved to `results/YYYYMMDD_XXXXX.txt` as JSON with full per-check details.

Spoof mode: Rich table showing which of 12 spoofing methods succeed or fail against the domain.

## 2. Target Profiles

### No WAF / No Monitoring

Full scan with aggressive DKIM bruteforce and all intrusive checks:

```bash
python mercure.py -d target.com --intrusive --aggressive --selector-threads 32
```

If nuclei, katana, and subfinder are installed, they run automatically.

### Corporate Target (Basic DNS Monitoring)

Reduce thread count to avoid burst detection:

```bash
python mercure.py -d target.com --threads 2 --selector-threads 4
```

### Enterprise Target (SIEM + DNS Firewall)

Skip DKIM bruteforce, run high-value checks only:

```bash
python mercure.py -d target.com --checks spf,dmarc,caa,dnssec --no-bruteforce
```

### Intrusive Mode (Full SMTP Recon)

Enable all intrusive checks - SMTP reconnaissance, user enumeration, TLS stripping, bounce analysis, port scanning, NSEC zone walking, subdomain bruteforce:

```bash
python mercure.py score -d target.com --intrusive
```

This adds 10 checks on top of the 31 passive + 8 external checks. Nuclei and katana run automatically if their binaries are in PATH.

### SMTP-Focused Audit

Target email infrastructure specifically:

```bash
python mercure.py score -d target.com --intrusive --checks smtp_sec,smtp_recon,smtp_enum,smtp_tls_strip,ghost,bounce,spf,dkim,dmarc
```

Covers: SMTP banner/version, EHLO analysis, AUTH enumeration, NTLM info leak, RCPT TO user enum, TLS enforcement, Ghost Sender, bounce/backscatter, and email authentication.

### Air-Gapped / Offline (No External APIs)

Skip checks that call crt.sh, Shodan, RDAP, Cloudflare RPKI:

```bash
python mercure.py score -d target.com --skip-external
```

Only DNS queries and direct connections. No internet API calls.

### Bulk Domain Audit

Batch process from a file. Results auto-saved to `results/`:

```bash
python mercure.py -f domains.txt --format json --output results.json --threads 16
```

### Ghost Sender Check Only

Test Exchange Online direct endpoint vulnerability:

```bash
python mercure.py -d target.com --checks ghost
```

### Ghost Sender + Email Auth (Full Spoofing Audit)

Complete email spoofing assessment:

```bash
python mercure.py score -d target.com --checks spf,dkim,dmarc,ghost
```

### Spoof Mode - Direct (No Relay)

Test spoofing via direct MX delivery (no relay configured):

```bash
python mercure.py spoof -d target.com -r victim@example.com
```

### Spoof Mode - With SMTP Relay

Configure an authenticated relay in `.env` for higher deliverability:

```
SMTP_RELAY_HOST=ssl0.ovh.net
SMTP_RELAY_PORT=465
SMTP_RELAY_USER=mercure@yourdomain.com
SMTP_RELAY_PASS=your_password
```

Then run spoof mode normally - eligible methods auto-route through the relay:

```bash
python mercure.py spoof -d target.com -r victim@example.com
```

The console shows `relay configured: ssl0.ovh.net:465 (mercure@yourdomain.com)` on startup. Methods `ghost`, `relay`, `internal`, `backscatter` still connect directly.

### Full Audit Workflow

Score first (passive + intrusive), then spoof to validate findings:

```bash
# 1. Full audit with all checks
python mercure.py score -d target.com --intrusive

# 2. Validate email spoofing if Security score is low
python mercure.py spoof -d target.com -r test@yourlab.com

# 3. Review auto-saved results in results/ directory
ls -la results/
```

### Email Infrastructure Only

Focus on the email authentication triad:

```bash
python mercure.py -d target.com --checks spf,dkim,dmarc
```

### DNS Infrastructure Only

Check nameserver resilience, DNSSEC, zone transfers:

```bash
python mercure.py -d target.com --checks ns,dnssec,caa,mx,soa,axfr,wildcard,zone_consistency
```

### External Tool Integration

Mercure auto-detects ProjectDiscovery tools when available in PATH:

```bash
# Install external tools (optional)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Verify installation
which subfinder nuclei katana

# Run with intrusive mode (nuclei + katana auto-detected)
python mercure.py score -d target.com --intrusive
```

- **subfinder**: merges with crt.sh for subdomain enumeration (passive, always runs if available)
- **nuclei**: vulnerability scanning with severity classification (intrusive, requires `--intrusive`)
- **katana**: web surface crawling with sensitive path detection (intrusive, requires `--intrusive`)

If a tool is not installed, the check scores 7/10 (`tool_not_installed`) and does not penalize the domain.

## 3. Proxy Setup

Mercure uses DNS resolution, not HTTP. Proxy configuration depends on your DNS resolver:

### System Resolver (Default)

Mercure uses whatever DNS resolver your system is configured with. To change:

```bash
# /etc/resolv.conf or systemd-resolved
nameserver 1.1.1.1
nameserver 8.8.8.8
```

### DNS-over-HTTPS (External)

Use `dnscrypt-proxy` or `cloudflared` as a local resolver:

```bash
# Install cloudflared
cloudflared proxy-dns --port 5053

# Point system resolver to localhost:5053
```

### VPN / SOCKS

DNS queries typically follow the system route. If you're using a VPN, DNS will go through the VPN tunnel. Verify with:

```bash
dig +short whoami.akamai.net
```

### External Tools (subfinder, nuclei, katana)

External tools make their own HTTP connections. They respect standard proxy environment variables:

```bash
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080

# Or per-tool config (nuclei example)
nuclei -proxy http://proxy:8080
```

Subfinder, nuclei, and katana each have their own proxy configuration options. Refer to their documentation for advanced proxy setups (SOCKS5, rotating proxies, etc.).

## 4. OPSEC Checklist

### Before a Run

- [ ] Verify your DNS resolver: `dig +short whoami.akamai.net`
- [ ] Check your source IP: `curl -s ifconfig.me`
- [ ] Review the check list: do you need all 49, or can you limit with `--checks`?
- [ ] Decide on DKIM bruteforce: is the selector enumeration worth the query volume?
- [ ] Ghost Sender check: the SMTP probe to port 25 is logged by EXO - accept the risk or exclude with `--checks`
- [ ] **Intrusive mode**: SMTP connections to each MX will be logged. RCPT TO enumeration (30 addresses) is noisy. Port scanning (18 ports TCP connect) is detectable by IDS/IPS
- [ ] **NSEC walk**: generates unusual DNS query patterns (NSEC chain following). Logged by DNSSEC-aware monitoring
- [ ] **Subdomain brute**: 200+ A record queries for common prefixes. Visible in DNS logs as dictionary enumeration
- [ ] **External tools**: check if nuclei/katana/subfinder are installed (`which nuclei katana subfinder`). Nuclei sends HTTP requests with identifiable User-Agent. Katana crawls the web surface
- [ ] **Spoof mode**: you are sending actual emails. Ensure you have authorization and the recipient is a controlled test mailbox
- [ ] **SMTP relay**: if configured, verify credentials work (`openssl s_client -connect ssl0.ovh.net:465` for SSL test)
- [ ] **SMTP relay OPSEC**: relay logs your authenticated user - the relay provider sees sender, recipient, and content
- [ ] Set appropriate thread count for the target's monitoring level

### During a Run

- [ ] Monitor DNS query volume: `tcpdump -i any port 53 -c 100`
- [ ] Watch for rate limiting: check log output for DNS timeout errors
- [ ] Monitor SMTP connections: intrusive checks connect to each MX on ports 25/587/465
- [ ] Watch for nuclei/katana output in log files (can be verbose)
- [ ] Verify results are being written if using `--output`

### After a Run

- [ ] Results auto-saved to `results/YYYYMMDD_XXXXX.txt` - check JSON for full per-check details
- [ ] Review dual scores: Security (hardening posture) vs Exploitability (how easy to attack)
- [ ] Review `log/` directory for the session log
- [ ] Check for domains with low Security score or high Exploitability score
- [ ] Export results for reporting: `--format json` or `--format csv`
- [ ] Clean up logs if needed: log files are auto-pruned after 30 days (configurable)

## 5. Escalation

When a check returns a low score, here's what to investigate further:

### SPF 0/10 (no_spf or allow_all)

1. Check if the domain sends email at all (`dig MX target.com`)
2. If MX exists but no SPF: the domain is fully spoofable
3. If `+all`: equivalent to no SPF, any IP can send as this domain
4. Escalate: attempt to send a spoofed email through a test relay

### DKIM 0/10 (no_dkim)

1. Run with `--aggressive` to try more selectors
2. Try a custom wordlist: `--dkim-wordlist custom.txt`
3. Check if the domain uses a known provider (Google, Microsoft, etc.) and try their standard selectors
4. If truly no DKIM: emails can't be cryptographically verified

### DMARC 0/10 (no_dmarc)

1. Check if `_dmarc.target.com` returns any TXT record at all
2. If the parent domain has DMARC with `sp=`, the subdomain inherits
3. No DMARC + no SPF = fully spoofable with no policy enforcement

### DNSSEC 0/10 (no_dnssec)

1. The domain is vulnerable to DNS cache poisoning
2. Check the registrar: some registrars don't support DNSSEC
3. Check the TLD: not all TLDs have full DNSSEC support

### GHOST 0/10 (ghost_sender_vulnerable)

The domain is vulnerable to the Ghost Sender attack. This bypasses SPF/DKIM/DMARC entirely.

1. Confirm: the EXO endpoint `<dashed-domain>.mail.protection.outlook.com:25` accepts RCPT TO with a spoofed MAIL FROM
2. The root cause: MX routes through a third-party SEG but no **partner connector** is configured in Exchange Online to restrict which IPs can deliver mail to the direct EXO endpoint
3. Immediate mitigation: configure a partner connector in Exchange Online that restricts inbound mail to the SEG's IP range or certificate
4. Alternative: create a transport rule that quarantines mail missing the `X-MS-Exchange-Organization-AuthAs: Internal` header from unexpected IPs
5. Verify: re-run `python mercure.py -d target.com --checks ghost` - should now return `partner_connector_configured` (10/10)

### GHOST 7/10 (exo_unreachable)

The EXO endpoint exists and MX routes through a third-party, but the SMTP probe couldn't connect.

1. This may mean port 25 is blocked from your source IP, or the EXO endpoint has network-level restrictions
2. Re-test from a different network (VPS, residential IP, VPN) to confirm reachability
3. If still unreachable: the risk is lower but not zero - the endpoint may be reachable from other networks

### AXFR 0/10 (zone_transfer_allowed)

At least one nameserver allows full zone transfer. This is a critical exposure.

1. Identify which NS allows AXFR from the check details
2. Verify manually: `dig AXFR target.com @ns1.target.com`
3. The zone dump reveals all DNS records - subdomains, internal hostnames, mail servers, SPF includes
4. Immediate mitigation: restrict AXFR to authorized secondary nameservers only (ACLs on the authoritative NS)
5. Check all NS servers - one misconfigured NS is enough

### SMTP-RECON (intrusive)

NTLM info leak or weak authentication methods discovered:

1. If NTLM info leaked: the check extracted NetBIOS domain name, computer name, DNS domain/tree, and potentially OS version from the SMTP server
2. This information enables targeted attacks: AD domain structure, internal naming conventions, OS version for exploit selection
3. Mitigation: disable NTLM authentication on externally-facing SMTP servers. Use modern auth (OAuth2) instead
4. If AUTH PLAIN/LOGIN offered without TLS: credentials can be intercepted in transit
5. If HELP command reveals server software/version: disable HELP response or restrict to authenticated sessions

### SMTP-ENUM (intrusive)

RCPT TO user enumeration succeeded:

1. Check the details for which addresses were confirmed (postmaster, admin, ceo, ciso, etc.)
2. If no catch-all: the server reveals valid vs invalid addresses through differential responses (250 vs 550)
3. Attackers use this for targeted spear-phishing (confirm exec names before sending)
4. Mitigation: enable catch-all or configure the MX to accept all RCPT TO during SMTP and reject later (accept-then-bounce). Tradeoff: catch-all increases spam surface
5. If catch-all detected: lower risk, but the server accepts mail for any address

### SMTP-STRIP (intrusive)

SMTP TLS can be downgraded or is misconfigured:

1. If plaintext delivery accepted: the MX accepted email without STARTTLS. An on-path attacker can strip TLS and read emails in transit
2. If deprecated TLS (1.0/1.1) accepted: vulnerable to BEAST, POODLE, and other protocol-level attacks
3. If certificate hostname mismatch: the MX cert doesn't match the MX hostname - enables MITM with a rogue cert
4. Mitigation: enforce STARTTLS with MTA-STS (`enforce` mode), disable TLS 1.0/1.1, fix certificate to match MX hostname
5. Deploy DANE/TLSA for cryptographic binding of the certificate to DNS

### NSEC-WALK (intrusive)

DNSSEC zone is walkable:

1. If NSEC (not NSEC3): the zone can be fully enumerated by following the NSEC chain. All hostnames are exposed
2. If NSEC3 with weak parameters: low iteration count or short/empty salt makes offline cracking feasible
3. Check the details for discovered hostnames, NSEC3 algorithm, iterations, and salt length
4. Mitigation: switch from NSEC to NSEC3 with opt-out if zone walking is a concern
5. For NSEC3: use SHA-1 (algorithm 1), 100+ iterations, and a random salt of 8+ bytes

### DANGLING 0/10 (dangling_cnames_found)

Subdomain takeover is possible via dangling CNAME records:

1. Check the details for which subdomains have dangling CNAMEs and which services they pointed to
2. Common targets: AWS S3 buckets, Azure services, GitHub Pages, Heroku, Netlify, Vercel, Shopify
3. An attacker can register the abandoned service and serve content on your subdomain (including valid TLS via the service's cert)
4. Immediate mitigation: remove the CNAME record or re-provision the service
5. Risk: cookie theft (parent domain cookies), OAuth token theft, phishing from a trusted subdomain

### OPEN PORTS (intrusive)

Dangerous services exposed to the internet:

1. Check the details for which ports are open and what services are running
2. Critical findings: FTP (21), Telnet (23), SMB (445), RDP (3389), databases (3306/5432/27017)
3. FTP/Telnet: plaintext credentials, no encryption
4. SMB exposed: EternalBlue, credential relay, share enumeration
5. RDP exposed: brute-force target, BlueKeep/DejaBlue if unpatched
6. Database ports: direct access enables SQL injection equivalent without the web layer
7. Mitigation: firewall all non-essential ports, use VPN for admin access

### NUCLEI (intrusive)

Vulnerability scanner found issues:

1. **Critical/High severity**: address immediately. These are known, often exploitable vulnerabilities with public exploits
2. **Medium severity**: prioritize based on context. Information disclosure, misconfigurations, weak crypto
3. **Low/Info severity**: housekeeping. Version disclosures, default pages, deprecated features
4. Check the details for template IDs, matched URLs, and severity classification
5. Cross-reference with CVE databases for exploitability and patch availability
6. If nuclei not installed: score is 7/10 (`tool_not_installed`). Install with `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

### MTA-STS (mta_sts)

MTA-STS is missing or in testing mode:

1. If no MTA-STS: SMTP connections have no policy-based TLS enforcement. STARTTLS can be stripped by on-path attackers
2. If `mode: testing`: MTA-STS exists but sending servers only report failures, they don't enforce TLS
3. Mitigation: publish a `_mta-sts.domain` TXT record and serve the policy at `https://mta-sts.domain/.well-known/mta-sts.txt` with `mode: enforce`
4. Complement with DANE/TLSA for belt-and-suspenders TLS enforcement

### Spoof Mode - DELIVERED Results

If any method shows DELIVERED:

1. **direct DELIVERED**: the domain's SPF/DKIM/DMARC is not enforced by the recipient MX. This is the most common finding for domains with `p=none` or missing DMARC
2. **ghost DELIVERED**: Ghost Sender attack succeeded. The recipient's EXO tenant has no partner connector. This bypasses all email authentication
3. **null_from DELIVERED**: null envelope sender accepted. Bounce-style spoofing works - the From header shows the spoofed domain but SPF checks pass on the empty envelope
4. **subdomain DELIVERED**: DMARC subdomain policy (`sp=`) is missing or set to `none`. Attackers can spoof from any subdomain

5. **relay DELIVERED**: relay delivered the email through the authenticated SMTP server. The relay accepted the spoofed envelope-from - some providers rewrite it, others accept it as-is
6. **mismatch DELIVERED**: envelope/header domain mismatch not caught by DMARC alignment check
7. **display_name DELIVERED**: display name spoofing passed through recipient filters - BEC-style attack works
8. **internal DELIVERED**: target's MX accepts intra-domain mail from external sources without SPF check
9. **backscatter DELIVERED**: target's MX generates NDR to spoofed bounce address - backscatter attack works
10. **bs_inject DELIVERED**: NDR content injection succeeded. The bounce message carries the attacker's phishing content to the victim, delivered from the target's trusted MTA
11. **bs_amp DELIVERED**: amplification attack works. N dead recipients generated N separate NDRs, all delivered to victim. Check the `accepted_count` in results for amplification factor
12. **bs_oob DELIVERED**: auto-reply abuse works. Functional mailbox (info@, contact@, etc.) accepted the message and auto-reply/OOO goes to victim without sender validation

### Spoof Mode - All REJECTED

All 12 methods blocked means the domain has robust defenses:
- SPF with `-all`
- DKIM with strong keys
- DMARC with `p=reject` and `sp=reject`
- Partner connector configured (for EXO tenants)

### Dual Score Interpretation

**Security Score < 4/10** - the domain has critical security gaps. Prioritize:
1. Ghost Sender - if 0/10, this is the most critical finding (full SPF/DKIM/DMARC bypass)
2. Email auth (SPF + DKIM + DMARC) - prevents phishing
3. DNSSEC - prevents DNS hijacking
4. CAA - prevents unauthorized certificate issuance

**Exploitability Score > 7/10** - the domain is trivially exploitable. Focus on:
1. Checks with highest exploit weight first: Ghost (5.0), SMTP-SEC (5.0), Nuclei (5.0), DMARC (4.5), Dangling (4.5)
2. These represent the easiest paths for an attacker with the highest impact
3. A domain can have moderate Security (6/10) but high Exploitability (8/10) if the missing controls are the ones attackers actually target

**Exploitability Score < 3/10** - exploitation is impractical even if some controls are missing. The absent controls require specific conditions (network position, timing, resource investment) that limit real-world risk.

## 6. Troubleshooting

### DNS Timeout Errors

```
dns query TXT target.com failed: The DNS operation timed out
```

Increase the timeout in `.env`:

```
DNS_TIMEOUT=10.0
```

Or reduce thread count to avoid overwhelming the resolver:

```bash
python mercure.py -d target.com --selector-threads 4
```

### No DKIM Selectors Found

DKIM selectors are unpredictable. If default bruteforce finds nothing:

1. Try aggressive mode: `--aggressive`
2. Use a custom wordlist with target-specific selectors
3. Check email headers from the target for `DKIM-Signature: ... s=selector_name`
4. Some domains use very long, random selectors that bruteforce won't find

### Import Errors

```
ModuleNotFoundError: No module named 'dns'
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Permission Errors on Log Directory

```
PermissionError: [Errno 13] Permission denied: 'log/2026-06-22.log'
```

Set a writable log directory in `.env`:

```
LOG_DIR=/tmp/mercure-logs
```

### Empty Results in CSV/JSON

Ensure the domain or file argument is provided:

```bash
python mercure.py -d example.com --format csv --output results.csv
```

Without `-d` or `-f`, Mercure shows help and exits.

### External Tools Not Found

```
nuclei not found in PATH, skipping
```

External tools (nuclei, katana, subfinder) are optional. When not installed:
- Nuclei and katana checks score 7/10 (`tool_not_installed`) - the domain is not penalized
- Subfinder results are omitted; crt.sh is still used for subdomain enumeration

Install ProjectDiscovery tools:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

### SMTP Connection Refused (Port 25 Blocked)

```
smtp connection to mail.target.com:25 failed: Connection refused
```

Many ISPs and cloud providers block outbound port 25 to prevent spam. Options:

1. Run Mercure from a VPS with port 25 open (dedicated server, not shared hosting)
2. Use a VPN that doesn't block port 25
3. Accept that SMTP-related intrusive checks will fail and rely on passive DNS checks
4. For spoof mode: configure an SMTP relay in `.env` (uses port 465/587 instead)

### Intrusive Checks Timeout

```
smtp_recon check failed: timed out
```

SMTP operations are slower than DNS. Increase timeout in `.env`:

```
SMTP_TIMEOUT=30.0
```

Some MX servers are slow to respond, especially during NTLM auth negotiation or TLS handshakes. Individual check timeouts don't affect the overall scan - other checks continue.

### NSEC Walk Stuck (Large Zone)

The NSEC walk follows up to 50 NSEC records in the chain. For very large zones, this can be slow.

The walk is capped at 50 steps to prevent excessive DNS queries. If the zone has thousands of records, the walk will capture the first 50 names and report NSEC parameters. This is sufficient to confirm the zone is walkable.

### Nuclei/Katana Slow Execution

Nuclei and katana run as subprocesses with a 120-second timeout. For targets with many endpoints:

1. Nuclei timeout: runs with default templates. Large targets may hit the timeout - the results captured before timeout are still reported
2. Katana crawl depth: limited to prevent excessive crawling. Sensitive paths found within the crawl window are reported
3. To speed up: run nuclei/katana manually with custom flags for fine-grained control, then use Mercure for the DNS/email checks only
