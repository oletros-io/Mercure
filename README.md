# Mercure - Domain Security Auditor

Mercure is a unified CLI tool for auditing the security posture of a domain. It checks email authentication (SPF, DKIM, DMARC), DNS infrastructure (NS, MX, DNSSEC, CAA), additional records (PTR, TLSA, SRV, IPv6), and active SMTP vulnerabilities (Ghost Sender).

## Scoring

**10/10 = maximum security. 0/10 = no security.**

Each check returns a score from 0 (no security) to 10 (maximum security). A weighted global score out of 10 is computed from all checks.

## Checks

| Check | Weight | Score mapping | What it does | Why it matters |
|---|---|---|---|---|
| **GHOST** | 4.0 | 0: vulnerable / 3: inconclusive / 7: EXO unreachable or rejected / 10: not EXO or mitigated | Ghost Sender attack: probes whether the Exchange Online direct endpoint accepts spoofed mail when MX routes through a third-party SEG | When MX is routed via a SEG (Proofpoint, Mimecast, etc.) but EXO's direct endpoint (`<domain>.mail.protection.outlook.com`) has no partner connector, attackers can bypass SPF/DKIM/DMARC entirely by delivering directly to EXO on port 25. |
| **DMARC** | 3.5 | 0: missing / 3: none policy / 7: quarantine / 10: reject pct=100 | Checks DMARC policy (`reject`/`quarantine`/`none`), percentage sampling (`pct`), subdomain policy (`sp`), and reporting endpoints (`rua`/`ruf`) | Without `p=reject` at `pct=100`, receivers may still deliver spoofed emails. `p=none` only monitors -- it does not protect. Missing DMARC means no policy enforcement at all. |
| **SPF** | 3.0 | 0: missing or +all / 3: neutral or unknown / 7: soft fail / 10: hard fail | Validates the Sender Policy Framework record and its `all` mechanism (`-all`, `~all`, `?all`, `+all`) | A missing or permissive SPF (`+all`, `~all`) lets attackers send emails on behalf of the domain. Hard fail (`-all`) is the only policy that tells receiving servers to reject unauthorized senders. |
| **DKIM** | 2.5 | 0: missing / 3: weak key or l= tag / 7: test mode or guessable / 10: strong | Bruteforces DKIM selectors, checks key strength (RSA bits), detects guessable selectors and risky tags (`l=`, `t=y`) | Weak DKIM keys (<2048 bits) can be factored, allowing an attacker to sign forged emails. The `l=` tag lets attackers append content to signed messages. Test mode (`t=y`) means receivers may not enforce failures. |
| **DNSSEC** | 1.5 | 0: missing / 3: DS without DNSKEY / 7: DNSKEY without DS / 10: both present | Checks for DS and DNSKEY records to validate the DNSSEC chain of trust | Without DNSSEC, DNS responses can be spoofed (cache poisoning). An attacker on the network path can redirect traffic by forging DNS answers. Requires specific network conditions. |
| **CAA** | 1.5 | 0: missing / 3: no issue tag / 7: permissive issue / 10: restricted | Verifies Certificate Authority Authorization DNS records and the `issue`/`issuewild` tags | Without CAA, any CA can issue a certificate for the domain. An attacker who compromises a less-secure CA can obtain a valid TLS certificate and intercept traffic. |
| **MX** | 1.0 | 0: missing / 3: null or IP literal / 7: single MX / 10: multiple MX | Validates mail exchangers, detects null MX (`.`) and IP-literal MX entries | A null MX or IP-literal MX breaks email delivery and may indicate misconfiguration. A single MX provides no redundancy -- if it goes down, all inbound email is lost. |
| **NS** | 1.0 | 0: missing / 3: single NS / 7: same provider / 10: diverse providers | Checks nameserver count and provider diversity | A single nameserver or all nameservers on the same provider is a single point of failure. A DDoS or provider outage takes the entire domain offline. |
| **TLSA** | 0.5 | 0: missing / 10: present | Queries TLSA records at `_25._tcp.<domain>` for DANE/SMTP authentication | DANE binds a TLS certificate to a domain via DNS, preventing CA compromise and man-in-the-middle attacks on SMTP connections. Without TLSA, STARTTLS can be silently stripped. |
| **PTR** | 0.5 | 0: missing / 3: partial / 7: no match / 10: match | Resolves A records, performs reverse DNS lookups, and checks if PTR matches the domain | Many mail servers reject or flag emails from IPs without valid reverse DNS. A missing or mismatched PTR hurts deliverability and can indicate a compromised or rented host. |
| **SRV** | 0.25 | 0: missing / 7: partial / 10: all present | Looks for mail-related SRV records (`_submission._tcp`, `_imaps._tcp`, `_pop3s._tcp`) | SRV records allow mail clients to auto-discover server endpoints securely. Their absence forces manual configuration and increases the risk of users connecting to rogue servers. |
| **IPv6** | 0.25 | 0: missing / 10: present | Checks for AAAA records on the domain | Lack of IPv6 is not a direct security risk but indicates incomplete network readiness. Some networks and resolvers are IPv6-only; missing AAAA records can cause connectivity issues. |

For detailed definitions, ideal values, exploitation examples, and impact analysis, see [CHECKS.md](CHECKS.md).

## Weight Rationale

Weights reflect **attacker exploitability** -- how much damage results from exploiting the absence of each control:

- **Critical (4.0)**: Ghost Sender -- full email auth bypass, instant spoofing with zero defenses
- **High (3.0-3.5)**: DMARC, SPF -- direct email spoofing, no enforcement or no sender verification
- **Significant (2.5)**: DKIM -- forge signed emails (weak keys) or bypass DMARC alignment
- **Moderate (1.5)**: DNSSEC, CAA -- DNS hijacking, unauthorized certificates, requires specific conditions
- **Low (1.0)**: MX, NS -- availability attacks, infrastructure mapping, indirect exploitation
- **Minimal (0.25-0.5)**: TLSA, PTR, SRV, IPv6 -- transport interception, reconnaissance, no direct exploitation

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
      cli.py                      # CLI entry point, banner, mode dispatch
      config.py                   # Configuration management (.env support)
      logger.py                   # Rich console logging with file persistence
      dns_utils.py                # DNS query wrapper functions
      scoring.py                  # CheckResult dataclass, scoring logic, weights
      spoof.py                    # Email spoofing engine (9 methods, SMTP relay support)
      checks/
         __init__.py              # Check registry
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
      dkim_selectors/
         __init__.py
         builder.py               # DKIM selector generation and expansion
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
| `--threads N` | Worker threads for file mode (default 16) |
| `--selector-threads N` | Threads for DKIM selector bruteforce (default 16) |
| `--format FMT` | Output format: text, json, csv (default text) |
| `--output PATH` | Output file path |

## Spoof Arguments

| Argument | Description |
|---|---|
| `-d, --domain` | Domain to spoof as (sender = mercure@domain) |
| `-r, --recipient` | Recipient email address |
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
