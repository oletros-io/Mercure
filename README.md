# Mercure - Domain Security Auditor

Mercure is a blackbox domain security auditor. From a single domain name, it runs 49 security checks across DNS, email authentication, TLS/certificates, web headers, subdomain takeover, email gateway bypass, SMTP reconnaissance, and infrastructure mapping. Passive by default, intrusive on demand. Integrates with ProjectDiscovery tools (subfinder, nuclei, katana) when available.

## Scoring

**Dual scoring system:**
- **Security**: 10/10 = maximum security, 0/10 = no security (weighted security posture)
- **Exploitability**: 10/10 = trivially exploitable, 0/10 = impractical to exploit (weighted by attack ease - like CVSS vs KEV)

Results auto-saved to `results/YYYYMMDD_XXXXX.txt` as JSON with full per-check details.

## Checks (49)

### Email Authentication & Policy

| Check | Weight | What it does |
|---|---|---|
| **GHOST** | 4.0 | Ghost Sender: probes EXO direct endpoint bypass when MX routes through third-party SEG |
| **DMARC** | 3.5 | DMARC policy (reject/quarantine/none), pct, subdomain policy, reporting |
| **SPF** | 3.0 | SPF record validation and `all` mechanism (-all, ~all, ?all, +all) |
| **DKIM** | 2.5 | DKIM selector bruteforce, key strength (RSA bits), risky tags (l=, t=y) |
| **MTA-STS** | 1.5 | MTA-STS TXT record + HTTPS policy (enforce/testing/none), MX patterns, max_age |
| **SEG** | 1.5 | Email gateway fingerprinting (Proofpoint, Mimecast, Barracuda, IronPort, MS Defender, Google, 15+ providers) |
| **DMARC-EXT** | 1.0 | DMARC external report authorization (RFC 7489 s7.1) - validates rua/ruf cross-domain auth |
| **TLS-RPT** | 0.5 | SMTP TLS Reporting (RFC 8460) - rua presence |
| **SPF-DEPTH** | 0.5 | SPF include chain recursion - DNS lookup count vs RFC 7208 10-lookup limit |
| **SPF-RECON** | 0.5 | SPF infrastructure mapping - recursive include tree walking, ESP identification (25+ providers), broad IP range detection |
| **BIMI** | 0.25 | BIMI brand indicator (v=BIMI1) - logo URL, VMC certificate |

### DNS Infrastructure

| Check | Weight | What it does |
|---|---|---|
| **AXFR** | 2.0 | Zone transfer test against each NS - full zone dump = critical exposure |
| **DNSSEC** | 1.5 | DS + DNSKEY chain of trust validation |
| **CAA** | 1.5 | Certificate Authority Authorization - issue/issuewild tags |
| **NS** | 1.0 | Nameserver count and provider diversity |
| **MX** | 1.0 | Mail exchangers, null MX, IP-literal detection |
| **DNSBL** | 1.0 | IP reputation on 4 major blacklists (Spamhaus, SpamCop, Barracuda, SORBS) |
| **SOA** | 0.5 | SOA record analysis - timers, admin contact, serial |
| **WILDCARD** | 0.5 | Wildcard DNS detection (random subdomain resolution) |
| **NSEC-WALK** | 1.5 | DNSSEC zone walking: NSEC chain enumeration, NSEC3 parameter analysis (algorithm, iterations, salt) |
| **DNS-REBIND** | 1.0 | Private/reserved IP resolution detection (RFC 1918, loopback, link-local, CGNAT) - SSRF/rebinding risk |
| **ZONE** | 0.5 | NS answer consistency - same query to all NS, compare answers |
| **TLSA** | 0.5 | DANE/TLSA for SMTP (port 25) |
| **PTR** | 0.5 | Reverse DNS match |
| **CNAME** | 0.25 | CNAME on apex (RFC violation), chain length, CNAME+MX coexistence |
| **SRV** | 0.25 | Mail SRV records (submission, imaps, pop3s) |
| **IPv6** | 0.25 | AAAA record presence |

### TLS / Certificates / Web

| Check | Weight | What it does |
|---|---|---|
| **TLS** | 2.0 | Web TLS (port 443) + MX STARTTLS: cert chain, cipher, protocol version, deprecated TLS |
| **CT** | 1.0 | Certificate Transparency via crt.sh - unexpected certs, wildcard abuse |
| **HSTS** | 1.0 | HSTS header (max-age, includeSubDomains, preload) |
| **HEADERS** | 1.0 | HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP) |
| **REDIRECT** | 0.5 | HTTP -> HTTPS redirect analysis |
| **COOKIE** | 0.5 | Set-Cookie flags (Secure, HttpOnly, SameSite) |
| **SEC.TXT** | 0.25 | security.txt (RFC 9116) - Contact, Expires fields |

### Recon / Attack Surface

| Check | Weight | What it does |
|---|---|---|
| **DANGLING** | 3.0 | Subdomain takeover: dangling CNAMEs to deprovisioned services (31 fingerprints: AWS S3/EB/CF, Azure, GitHub, Heroku, Netlify, Vercel, Shopify...) |
| **SUBDOMAINS** | 1.5 | crt.sh CT log enumeration, sensitive subdomain detection (dev, staging, admin, vpn) |
| **M365** | 1.0 | Microsoft 365 tenant detection (OpenID config, autodiscover CNAME, SIP federation SRV) |
| **AUTODISCOVER** | 1.0 | Autodiscover/autoconfig endpoint security (4 HTTP endpoints + SRV + CNAME), info leak detection |
| **OPEN PORTS** | 1.0 | TCP scan on 18 ports, dangerous port flagging (FTP, telnet, SMB, RDP, DB), Shodan enrichment |
| **SUB-BRUTE** | 1.0 | Dictionary subdomain enumeration (200+ prefixes), wildcard filtering, sensitive subdomain detection |
| **WHOIS** | 0.5 | RDAP: domain expiry, registrar lock, transfer protection |
| **RPKI** | 0.5 | Route Origin Authorization via Cloudflare RPKI API |

### Intrusive (`--intrusive`)

| Check | Weight | What it does |
|---|---|---|
| **SMTP-RECON** | 2.0 | SMTP reconnaissance: EHLO hostname analysis, AUTH method enumeration, NTLM info leak (AD domain, internal hostname, OS version), HELP probing |
| **SMTP-SEC** | 2.0 | Per-MX: banner/version, STARTTLS enforcement, VRFY/EXPN user enum, open relay, SMTP smuggling (bare-LF injection) |
| **BOUNCE** | 2.0 | Send to nonexistent recipient, detect accept-then-bounce (backscatter) vs reject-before-accept |
| **SMTP-ENUM** | 1.5 | RCPT TO user enumeration against 30 common addresses, catch-all detection, differential response analysis |
| **SMTP-STRIP** | 1.5 | SMTP TLS enforcement: plaintext delivery test, deprecated TLS (1.0/1.1) probing, STARTTLS cert hostname mismatch |
| **NSEC-WALK** | 1.5 | DNSSEC zone walking via NSEC chain, NSEC3 parameter strength analysis |
| **SUB-BRUTE** | 1.0 | Dictionary subdomain brute-force (200+ prefixes), wildcard detection, sensitive service exposure |
| **NUCLEI** | 2.0 | Vulnerability scanning via ProjectDiscovery nuclei (auto-detected, critical/high/medium severity) |
| **KATANA** | 0.5 | Web surface discovery via ProjectDiscovery katana (sensitive paths, forms, JS files) |

## Weight Rationale

Weights reflect **attacker exploitability** - how much damage results from exploiting the absence of each control:

- **Critical (3.0-4.0)**: Ghost Sender (full auth bypass), Dangling CNAME (subdomain takeover = full control)
- **High (2.0-3.5)**: DMARC, SPF, DKIM, AXFR (zone dump), TLS (MITM), SMTP-SEC (relay/smuggling), SMTP-RECON (NTLM info leak/AD recon), Nuclei (vuln scanner), Bounce (backscatter)
- **Significant (1.0-1.5)**: DNSSEC, CAA, MTA-STS, SEG, Subdomains, M365, Autodiscover, SMTP-ENUM (user enumeration), SMTP-STRIP (TLS downgrade), NSEC-WALK (zone walking), CT, HSTS, Headers, DNSBL, Open Ports, DNS-REBIND, Sub-Brute, NS, MX
- **Low (0.5)**: SOA, Wildcard, Zone consistency, TLS-RPT, WHOIS, Redirect, Cookie, SPF-Depth, SPF-Recon, RPKI, TLSA, PTR, Katana
- **Minimal (0.25)**: CNAME, BIMI, Security.txt, SRV, IPv6

## Modes

Mercure has two modes:

### Score Mode (default)

Run security checks and compute a per-check + global score.

```bash
python mercure.py score -d example.com
python mercure.py -d example.com                  # implicit score mode
python mercure.py score -f domains.txt --format json --output results.json
```

### Spoof Mode

Attempt multiple email spoofing methods against a domain. Tests whether the domain's defenses (SPF, DKIM, DMARC, partner connectors) actually block spoofed emails in practice.

```bash
python mercure.py spoof -d target.com -r victim@example.com
```

Sender is always `mercure@<domain>`, subject is "Security Test", body is lorem ipsum. When an SMTP relay is configured (see Configuration), eligible methods route through it for higher deliverability.

**Methods (12):**

| Method | Description | What it tests |
|---|---|---|
| `direct` | Deliver spoofed email via the recipient's MX | SPF/DKIM/DMARC enforcement |
| `ghost` | Bypass SEG, deliver directly to EXO endpoint | Partner connector absence (Ghost Sender) |
| `null_from` | Empty envelope sender with spoofed From header | Bounce-style spoofing, header-from DMARC only |
| `subdomain` | Spoof from `nonexistent.<domain>` | DMARC subdomain policy (`sp=`) |
| `relay` | Route through target's own MX to external recipient | Open relay misconfiguration |
| `mismatch` | Envelope domain ≠ header From domain | DMARC alignment enforcement |
| `display_name` | Neutral sender, display name shows target identity | BEC-style display name deception |
| `internal` | Both sender and recipient @target, via target's MX | Internal mail filtering (requires recipient @domain) |
| `backscatter` | Send to nonexistent@target, bounce goes to victim | Recipient validation before accept (NDR abuse) |
| `bs_inject` | Phishing body to dead@target, NDR delivers content to victim | NDR body inclusion policy (RET=FULL content injection) |
| `bs_amp` | 5 dead recipients in 1 SMTP session, each generates NDR | Per-recipient NDR generation, amplification factor |
| `bs_oob` | Send to functional addresses (info@, contact@), return-path=victim | Auto-reply/OOO sender validation (RFC 3834 compliance) |

**Status codes:**

| Status | Meaning | Color |
|---|---|---|
| DELIVERED | Email accepted by server | Red (vulnerable) |
| REJECTED | Server refused the email | Green (protected) |
| SKIP | Method not applicable | Grey |
| ERROR | Connection/network failure | Yellow |

## Project Structure

```
mercure_-_domain_security/
   mercure.py                     # Launcher script
   requirements.txt
   .env                           # Configuration (SMTP relay creds, timeouts, paths)
   resources/
      dkim_selectors.txt          # DKIM selector wordlist (5300+ selectors)
   mercure/
      __init__.py
      cli.py                      # CLI argument parsing and mode dispatch
      config.py                   # Lazy-loaded configuration (.env support)
      logger.py                   # Rich console logging with file persistence
      dns_utils.py                # DNS queries with cache, typed errors, AXFR, DNSBL
      http_utils.py               # HTTP fetch, TLS cert analysis, SMTP STARTTLS probe
      recon.py                    # External sources (crt.sh, Shodan InternetDB, RDAP)
      scoring.py                  # CheckResult dataclass, scoring logic, 39 weights
      runner.py                   # Orchestration (domain analysis, file batch, spoof)
      output.py                   # Rendering (banner, tables, JSON/CSV export)
      smtp.py                     # Generic SMTP delivery (direct, relay, amplification)
      spoof.py                    # Email spoofing engine (12 methods, parallel execution)
      checks/
         __init__.py              # Auto-discovery check registry
         base.py                  # BaseCheck abstract class
         spf.py                   # SPF validation
         dkim.py                  # DKIM key strength and selector discovery
         dmarc.py                 # DMARC policy enforcement
         caa.py                   # Certificate Authority Authorization
         mx.py                    # Mail exchanger validation
         ns.py                    # Nameserver diversity
         dnssec.py                # DNSSEC chain of trust
         ipv6.py                  # IPv6 support
         ptr.py                   # Reverse DNS validation
         srv.py                   # Mail SRV records
         tlsa.py                  # DANE/TLSA for SMTP
         ghost.py                 # Ghost Sender (EXO direct endpoint spoofing)
         smtp_recon.py            # SMTP recon (NTLM info leak, AUTH enum, EHLO analysis)
         smtp_enum.py             # RCPT TO user enumeration
         smtp_tls_strip.py        # SMTP TLS enforcement and downgrade testing
         nsec_walk.py             # DNSSEC NSEC/NSEC3 zone walking
         dns_rebind.py            # Private IP resolution detection
         subdomain_brute.py       # Dictionary subdomain enumeration
         autodiscover.py          # Autodiscover/autoconfig endpoint security
         spf_recon.py             # SPF infrastructure mapping
         nuclei_scan.py           # Nuclei vulnerability scanner integration
         katana_scan.py           # Katana web crawler integration
      dkim_selectors/
         __init__.py
         builder.py               # DKIM selector generation and expansion
   tests/
      conftest.py                 # Shared fixtures (config reset, DNS mocks, SMTP mocks)
      test_config.py              # Config and lazy proxy tests
      test_dns_utils.py           # DNS cache, resolve, DnsResult tests
      test_scoring.py             # Score mapping, weighted scoring, style tests
      test_spf.py                 # SPF detection and evaluation tests
      test_dkim.py                # DKIM key parsing, selector bruteforce tests
      test_dmarc.py               # DMARC parsing and policy evaluation tests
      test_ghost.py               # Ghost Sender detection tests
      test_ptr.py                 # PTR matching and check tests
      test_ns.py                  # Nameserver diversity check tests
      test_smtp.py                # SMTP delivery (direct, relay, amplification) tests
      test_spoof.py               # Spoof engine method and parallel execution tests
```

## Installation

```
pip install -r requirements.txt
```

## Usage

```bash
python mercure.py score -d example.com
python mercure.py spoof -d target.com -r victim@example.com
python mercure.py -h
```

## Score Arguments

| Argument | Description |
|---|---|
| `-d, --domain` | Domain to analyze |
| `-f, --file` | File with domains (one per line) |
| `--checks NAMES` | Comma-separated checks to run (default: all). Available: spf,dkim,dmarc,caa,mx,ns,dnssec,ipv6,srv,ptr,tlsa,ghost |
| `--dkim-wordlist PATH` | Custom DKIM selector wordlist (default: `resources/dkim_selectors.txt`, 5300+ selectors) |
| `--no-bruteforce` | Disable DKIM selector bruteforce |
| `--aggressive` | Enable aggressive DKIM selector bruteforce |
| `--intrusive` | Enable intrusive checks (SMTP probing, bounce analysis, port scan) |
| `--skip-external` | Skip checks that call external APIs (crt.sh, Shodan, RDAP) |
| `--threads N` | Worker threads for file mode (default 16) |
| `--selector-threads N` | Threads for DKIM selector bruteforce (default 16) |
| `--format FMT` | Output format: text, json, csv (default text) |
| `--output PATH` | Output file path |

## Spoof Arguments

| Argument | Description |
|---|---|
| `-d, --domain` | Domain to spoof as (sender = mercure@domain) |
| `-r, --recipient` | Recipient email address |
| `--no-parallel` | Run spoofing methods sequentially (default: parallel with 6 workers) |
| `--format FMT` | Output format: text, json (default text) |
| `--output PATH` | Output file path |

## Common Arguments

| Argument | Description |
|---|---|
| `--log-level LEVEL` | debug, info, warning, error, success (default info) |
| `-h, --help` | Show help |

## Configuration

Create a `.env` file in the working directory:

```
LOG_RETENTION_DAYS=30
DNS_TIMEOUT=5.0
DEFAULT_THREADS=16
SELECTOR_THREADS=16
DKIM_WORDLIST_PATH=resources/dkim_selectors.txt
SMTP_TIMEOUT=10.0
LOG_DIR=log

# SMTP Relay (authenticated relay for spoof mode)
SMTP_RELAY_HOST=ssl0.ovh.net
SMTP_RELAY_PORT=465
SMTP_RELAY_USER=mercure@yourdomain.com
SMTP_RELAY_PASS=your_password
```

All values have sensible defaults and are optional.

### SMTP Relay

When `SMTP_RELAY_HOST`, `SMTP_RELAY_USER`, and `SMTP_RELAY_PASS` are all set, spoof mode routes eligible methods through the authenticated relay instead of connecting directly to the recipient's MX.

| Delivery | Methods | Rationale |
|---|---|---|
| **Via relay** | `direct`, `null_from`, `subdomain`, `mismatch`, `display_name` | Benefit from authenticated delivery (higher deliverability, real-world BEC simulation) |
| **Always direct** | `ghost`, `relay`, `internal`, `backscatter` | Must connect to target's own MX or EXO endpoint (relay would defeat the test) |

Supports SSL (port 465) and STARTTLS (port 587). Falls back to direct MX delivery if relay is not configured.

## Examples

### Score Mode

Analyze a single domain:

```bash
python mercure.py score -d example.com
```

Run only email authentication checks:

```bash
python mercure.py score -d example.com --checks spf,dkim,dmarc
```

Aggressive DKIM bruteforce with custom wordlist:

```bash
python mercure.py score -d example.com --aggressive --dkim-wordlist selectors.txt --selector-threads 32
```

Analyze multiple domains from a file, export as JSON:

```bash
python mercure.py score -f domains.txt --format json --output results.json --threads 32
```

Export as CSV:

```bash
python mercure.py score -f domains.txt --format csv --output results.csv
```

Ghost Sender check only:

```bash
python mercure.py score -d target.com --checks ghost
```

### Spoof Mode

Test all spoofing methods against a domain:

```bash
python mercure.py spoof -d target.com -r victim@example.com
```

Export spoof results as JSON:

```bash
python mercure.py spoof -d target.com -r victim@example.com --format json --output spoof.json
```

Debug-level logging for troubleshooting:

```bash
python mercure.py spoof -d target.com -r victim@example.com --log-level debug
```
