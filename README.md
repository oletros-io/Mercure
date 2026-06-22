# Mercure - Domain Security Auditor

Mercure is a unified CLI tool for auditing the security posture of a domain. It checks email authentication (SPF, DKIM, DMARC), DNS infrastructure (NS, MX, DNSSEC, CAA), additional records (PTR, TLSA, SRV, IPv6), and active SMTP vulnerabilities (Ghost Sender).

## Scoring

**10/10 = maximum security. 0/10 = no security.**

Each check returns a score from 0 (no security) to 10 (maximum security). A weighted global score out of 10 is computed from all checks.

## Checks

| Check | Weight | Score mapping | What it does | Why it matters |
|---|---|---|---|---|
| **DMARC** | 3.5 | 0: missing / 3: none policy / 7: quarantine / 10: reject pct=100 | Checks DMARC policy (`reject`/`quarantine`/`none`), percentage sampling (`pct`), subdomain policy (`sp`), and reporting endpoints (`rua`/`ruf`) | Without `p=reject` at `pct=100`, receivers may still deliver spoofed emails. `p=none` only monitors -- it does not protect. Missing DMARC means no policy enforcement at all. |
| **SPF** | 3.0 | 0: missing or +all / 3: neutral or unknown / 7: soft fail / 10: hard fail | Validates the Sender Policy Framework record and its `all` mechanism (`-all`, `~all`, `?all`, `+all`) | A missing or permissive SPF (`+all`, `~all`) lets attackers send emails on behalf of the domain. Hard fail (`-all`) is the only policy that tells receiving servers to reject unauthorized senders. |
| **DKIM** | 3.0 | 0: missing / 3: weak key or l= tag / 7: test mode or guessable / 10: strong | Bruteforces DKIM selectors, checks key strength (RSA bits), detects guessable selectors and risky tags (`l=`, `t=y`) | Weak DKIM keys (<2048 bits) can be factored, allowing an attacker to sign forged emails. The `l=` tag lets attackers append content to signed messages. Test mode (`t=y`) means receivers may not enforce failures. |
| **DNSSEC** | 2.5 | 0: missing / 3: DS without DNSKEY / 7: DNSKEY without DS / 10: both present | Checks for DS and DNSKEY records to validate the DNSSEC chain of trust | Without DNSSEC, DNS responses can be spoofed (cache poisoning). An attacker on the network path can redirect traffic by forging DNS answers. |
| **GHOST** | 2.5 | 0: vulnerable / 3: inconclusive / 7: EXO unreachable or rejected / 10: not EXO or mitigated | Ghost Sender attack: probes whether the Exchange Online direct endpoint accepts spoofed mail when MX routes through a third-party SEG | When MX is routed via a SEG (Proofpoint, Mimecast, etc.) but EXO's direct endpoint (`<domain>.mail.protection.outlook.com`) has no partner connector, attackers can bypass SPF/DKIM/DMARC entirely by delivering directly to EXO on port 25. |
| **CAA** | 2.0 | 0: missing / 3: no issue tag / 7: permissive issue / 10: restricted | Verifies Certificate Authority Authorization DNS records and the `issue`/`issuewild` tags | Without CAA, any CA can issue a certificate for the domain. An attacker who compromises a less-secure CA can obtain a valid TLS certificate and intercept traffic. |
| **TLSA** | 1.5 | 0: missing / 10: present | Queries TLSA records at `_25._tcp.<domain>` for DANE/SMTP authentication | DANE binds a TLS certificate to a domain via DNS, preventing CA compromise and man-in-the-middle attacks on SMTP connections. Without TLSA, STARTTLS can be silently stripped. |
| **MX** | 1.5 | 0: missing / 3: null or IP literal / 7: single MX / 10: multiple MX | Validates mail exchangers, detects null MX (`.`) and IP-literal MX entries | A null MX or IP-literal MX breaks email delivery and may indicate misconfiguration. A single MX provides no redundancy -- if it goes down, all inbound email is lost. |
| **NS** | 1.5 | 0: missing / 3: single NS / 7: same provider / 10: diverse providers | Checks nameserver count and provider diversity | A single nameserver or all nameservers on the same provider is a single point of failure. A DDoS or provider outage takes the entire domain offline. |
| **PTR** | 1.0 | 0: missing / 3: partial / 7: no match / 10: match | Resolves A records, performs reverse DNS lookups, and checks if PTR matches the domain | Many mail servers reject or flag emails from IPs without valid reverse DNS. A missing or mismatched PTR hurts deliverability and can indicate a compromised or rented host. |
| **SRV** | 0.5 | 0: missing / 7: partial / 10: all present | Looks for mail-related SRV records (`_submission._tcp`, `_imaps._tcp`, `_pop3s._tcp`) | SRV records allow mail clients to auto-discover server endpoints securely. Their absence forces manual configuration and increases the risk of users connecting to rogue servers. |
| **IPv6** | 0.5 | 0: missing / 10: present | Checks for AAAA records on the domain | Lack of IPv6 is not a direct security risk but indicates incomplete network readiness. Some networks and resolvers are IPv6-only; missing AAAA records can cause connectivity issues. |

## Weight Rationale

Weights reflect real-world exploitability, not theoretical importance:

- **Tier 1 (3.0-3.5)**: Email authentication triad (DMARC, SPF, DKIM) -- directly prevents email spoofing and phishing, the most common attack vector
- **Tier 2 (2.0-2.5)**: Active vulnerabilities and DNS security (Ghost Sender, DNSSEC, CAA) -- bypasses or infrastructure-level attacks
- **Tier 3 (1.0-1.5)**: Infrastructure resilience (TLSA, MX, NS, PTR) -- affects availability, deliverability, and transport security
- **Tier 4 (0.5)**: Complementary (SRV, IPv6) -- nice to have, low direct security impact

## Project Structure

```
mercure_-_domain_security/
   mercure.py                     # Launcher script
   requirements.txt
   mercure/
      __init__.py
      cli.py                      # CLI entry point, banner, output formatting
      config.py                   # Configuration management (.env support)
      logger.py                   # Rich console logging with file persistence
      dns_utils.py                # DNS query wrapper functions
      scoring.py                  # CheckResult dataclass, scoring logic, weights
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

```
python mercure.py -d example.com
```

## Arguments

| Argument | Description |
|---|---|
| `-d, --domain` | Domain to analyze |
| `-f, --file` | File with domains (one per line) |
| `--checks NAMES` | Comma-separated checks to run (default: all). Available: spf,dkim,dmarc,caa,mx,ns,dnssec,ipv6,srv,ptr,tlsa,ghost |
| `--dkim-wordlist PATH` | Custom DKIM selector wordlist |
| `--no-bruteforce` | Disable DKIM selector bruteforce |
| `--aggressive` | Enable aggressive DKIM selector bruteforce |
| `--threads N` | Worker threads for file mode (default 16) |
| `--selector-threads N` | Threads for DKIM selector bruteforce (default 16) |
| `--log-level LEVEL` | debug, info, warning, error, success (default info) |
| `--format FMT` | Output format: text, json, csv (default text) |
| `--output PATH` | Output file path |

## Configuration

Create a `.env` file in the working directory:

```
LOG_RETENTION_DAYS=30
DNS_TIMEOUT=5.0
DEFAULT_THREADS=16
SELECTOR_THREADS=16
DKIM_WORDLIST_PATH=resources/selectors.txt
SMTP_TIMEOUT=10.0
LOG_DIR=log
```

All values have sensible defaults and are optional.

## Examples

Analyze a single domain:

```
python mercure.py -d example.com
```

Run only email authentication checks:

```
python mercure.py -d example.com --checks spf,dkim,dmarc
```

Aggressive DKIM bruteforce with custom wordlist:

```
python mercure.py -d example.com --aggressive --dkim-wordlist selectors.txt --selector-threads 32
```

Analyze multiple domains from a file, export as JSON:

```
python mercure.py -f domains.txt --format json --output results.json --threads 32
```

Export as CSV:

```
python mercure.py -f domains.txt --format csv --output results.csv
```

Run DNS infrastructure checks only:

```
python mercure.py -d example.com --checks caa,dnssec,mx,ns
```

Ghost Sender check only:

```
python mercure.py -d target.com --checks ghost
```
