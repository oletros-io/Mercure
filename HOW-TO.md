# HOW-TO.md - Operational Playbook

## 1. Quick Start

```bash
pip install -r requirements.txt
python mercure.py -d example.com
```

Output: Rich table with per-check scores (/10) and global score. 10/10 = maximum security.

## 2. Target Profiles

### No WAF / No Monitoring

Full scan with aggressive DKIM bruteforce:

```bash
python mercure.py -d target.com --aggressive --selector-threads 32
```

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

### Bulk Domain Audit

Batch process from a file with JSON export:

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
python mercure.py -d target.com --checks spf,dkim,dmarc,ghost
```

### Email Infrastructure Only

Focus on the email authentication triad:

```bash
python mercure.py -d target.com --checks spf,dkim,dmarc
```

### DNS Infrastructure Only

Check nameserver resilience and DNSSEC:

```bash
python mercure.py -d target.com --checks ns,dnssec,caa,mx
```

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

## 4. OPSEC Checklist

### Before a Run

- [ ] Verify your DNS resolver: `dig +short whoami.akamai.net`
- [ ] Check your source IP: `curl -s ifconfig.me`
- [ ] Review the check list: do you need all 12, or can you limit with `--checks`?
- [ ] Decide on DKIM bruteforce: is the selector enumeration worth the query volume?
- [ ] Ghost Sender check: the SMTP probe to port 25 is logged by EXO -- accept the risk or exclude with `--checks`
- [ ] Set appropriate thread count for the target's monitoring level

### During a Run

- [ ] Monitor DNS query volume: `tcpdump -i any port 53 -c 100`
- [ ] Watch for rate limiting: check log output for DNS timeout errors
- [ ] Verify results are being written if using `--output`

### After a Run

- [ ] Review `log/` directory for the session log
- [ ] Check for domains with 0/10 global score -- these are the most vulnerable targets
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
5. Verify: re-run `python mercure.py -d target.com --checks ghost` -- should now return `partner_connector_configured` (10/10)

### GHOST 7/10 (exo_unreachable)

The EXO endpoint exists and MX routes through a third-party, but the SMTP probe couldn't connect.

1. This may mean port 25 is blocked from your source IP, or the EXO endpoint has network-level restrictions
2. Re-test from a different network (VPS, residential IP, VPN) to confirm reachability
3. If still unreachable: the risk is lower but not zero -- the endpoint may be reachable from other networks

### Global Score < 4/10

The domain has critical security gaps. Prioritize:
1. Ghost Sender -- if 0/10, this is the most critical finding (full SPF/DKIM/DMARC bypass)
2. Email auth (SPF + DKIM + DMARC) -- prevents phishing
3. DNSSEC -- prevents DNS hijacking
4. CAA -- prevents unauthorized certificate issuance

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
