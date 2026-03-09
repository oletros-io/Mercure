# Mercure - Domain Security Auditor

Mercure is a unified CLI tool for auditing the security posture of a domain. It checks email authentication (SPF, DKIM, DMARC), DNS infrastructure (NS, MX, DNSSEC, CAA), and additional records (PTR, TLSA, SRV, IPv6).

## Checks

Each check returns a score from 0 (best) to 3 (worst). A weighted global score out of 10 is computed.

| Check | Weight | What it does | Why it matters |
|---|---|---|---|
| **SPF** | 3.0 | Validates the Sender Policy Framework record and its `all` mechanism (`-all`, `~all`, `?all`, `+all`) | A missing or permissive SPF (`+all`, `~all`) lets attackers send emails on behalf of the domain. Hard fail (`-all`) is the only policy that tells receiving servers to reject unauthorized senders. |
| **DKIM** | 2.5 | Bruteforces DKIM selectors, checks key strength (RSA bits), detects guessable selectors and risky tags (`l=`, `t=y`) | Weak DKIM keys (<2048 bits) can be factored, allowing an attacker to sign forged emails. Guessable selectors expose the signing infrastructure. The `l=` tag lets attackers append content to signed messages. |
| **DMARC** | 3.0 | Checks DMARC policy (`reject`/`quarantine`/`none`), percentage sampling (`pct`), and reporting endpoints (`rua`/`ruf`) | Without `p=reject` at `pct=100`, receivers may still deliver spoofed emails. `p=none` only monitors -- it does not protect. Missing DMARC means no policy enforcement at all. |
| **CAA** | 1.5 | Verifies Certificate Authority Authorization DNS records and the `issue`/`issuewild` tags | Without CAA, any CA can issue a certificate for the domain. An attacker who compromises a less-secure CA can obtain a valid TLS certificate and intercept traffic. |
| **DNSSEC** | 2.0 | Checks for DS and DNSKEY records to validate the DNSSEC chain of trust | Without DNSSEC, DNS responses can be spoofed (cache poisoning). An attacker on the network path can redirect traffic by forging DNS answers. |
| **MX** | 1.5 | Validates mail exchangers, detects null MX (`.`) and IP-literal MX entries | A null MX or IP-literal MX breaks email delivery and may indicate misconfiguration. A single MX provides no redundancy -- if it goes down, all inbound email is lost. |
| **NS** | 1.5 | Checks nameserver count and provider diversity | A single nameserver or all nameservers on the same provider is a single point of failure. A DDoS or provider outage takes the entire domain offline. |
| **PTR** | 1.0 | Resolves A records, performs reverse DNS lookups, and checks if PTR matches the domain | Many mail servers reject or flag emails from IPs without valid reverse DNS. A missing or mismatched PTR hurts deliverability and can indicate a compromised or rented host. |
| **TLSA** | 1.0 | Queries TLSA records at `_25._tcp.<domain>` for DANE/SMTP authentication | DANE binds a TLS certificate to a domain via DNS, preventing CA compromise and man-in-the-middle attacks on SMTP connections. Without TLSA, STARTTLS can be silently stripped. |
| **SRV** | 0.5 | Looks for mail-related SRV records (`_submission._tcp`, `_imaps._tcp`, `_pop3s._tcp`) | SRV records allow mail clients to auto-discover server endpoints securely. Their absence forces manual configuration and increases the risk of users connecting to rogue servers. |
| **IPv6** | 0.5 | Checks for AAAA records on the domain | Lack of IPv6 is not a direct security risk but indicates incomplete network readiness. Some networks and resolvers are IPv6-only; missing AAAA records can cause connectivity issues. |

## Installation

```
pip install -e .
```

Or install dependencies manually:

```
pip install -r requirements.txt
```

## Arguments

| Argument | Description |
|---|---|
| `-d, --domain` | Domain to analyze |
| `-f, --file` | File with domains (one per line) |
| `--checks NAMES` | Comma-separated checks to run (default: all) |
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
LOG_DIR=log
```

All values have sensible defaults and are optional.

## Examples

Analyze a single domain:

```
mercure -d example.com
```

Run only email authentication checks:

```
mercure -d example.com --checks spf,dkim,dmarc
```

Aggressive DKIM bruteforce with custom wordlist:

```
mercure -d example.com --aggressive --dkim-wordlist selectors.txt --selector-threads 32
```

Analyze multiple domains from a file, export as JSON:

```
mercure -f domains.txt --format json --output results.json --threads 32
```

Export as CSV:

```
mercure -f domains.txt --format csv --output results.csv
```

Run DNS infrastructure checks only:

```
mercure -d example.com --checks caa,dnssec,mx,ns
```
