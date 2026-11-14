# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.0] - 2026-11-14

### Added
- **10 new security checks** bringing total to 49 checks from a single domain name:
  - **SMTP Reconnaissance (--intrusive)**:
    - SMTP-RECON: EHLO hostname analysis, AUTH method enumeration, NTLM Type 1/Type 2 info leak extraction (NetBIOS domain/computer, DNS domain/tree, OS version), HELP command probing
    - SMTP-ENUM: RCPT TO user enumeration against 30 common addresses (postmaster, admin, ceo, ciso, etc.), catch-all detection, differential response analysis
    - SMTP-STRIP: TLS enforcement testing (plaintext delivery attempt), deprecated TLS version probing (TLS 1.0/1.1), STARTTLS certificate hostname mismatch detection
  - **DNS Advanced**:
    - NSEC-WALK (--intrusive): DNSSEC zone walking via NSEC record chain following, NSEC3 parameter analysis (algorithm, iterations, salt strength)
    - DNS-REBIND: Private/reserved IP resolution detection across domain and 16 common subdomains (RFC 1918, loopback, link-local, CGNAT, IPv6 private ranges) - SSRF/rebinding risk
    - SUB-BRUTE (--intrusive): Dictionary-based subdomain enumeration (200+ prefixes), wildcard detection and filtering, sensitive subdomain categorization
  - **Mail/External**:
    - AUTODISCOVER (external): Autodiscover/autoconfig endpoint security (4 HTTP endpoints + SRV + CNAME), info leak detection (server type, internal hostnames, IPs)
    - SPF-RECON: SPF infrastructure mapping - recursive include tree walking, ESP identification (25 known patterns), broad IP range detection, authorized sender inventory
  - **External tools (--intrusive, auto-detected via PATH)**:
    - NUCLEI: vulnerability scanning via ProjectDiscovery nuclei (critical/high/medium/low severity classification)
    - KATANA: web surface discovery via ProjectDiscovery katana (sensitive path detection, forms, JS files)
- **Subfinder integration**: subdomains check now merges crt.sh CT logs with subfinder results when the binary is available in PATH
- **Dual scoring system**:
  - **Security score**: weighted security posture (10 = hardened, 0 = exposed) - same as previous global score
  - **Exploitability score**: weighted exploitability of weaknesses (10 = trivially exploitable, 0 = impractical) - like CVSS vs KEV
- **Auto-save results**: every scan automatically saves full JSON results to `results/YYYYMMDD_XXXXX.txt`
- **385 unit tests** (was 285)

### Changed
- Scoring weights expanded from 39 to 49 checks (security weight 58.75, exploit weight 106.25)
- Console output now shows only global Security + Exploitability scores (per-check details in JSON)
- Results dict includes `scores.security`, `scores.exploitability`, `checks_run`, and per-check `label` field

## [0.4.0] - 2026-11-14

### Added
- **27 new security checks** bringing total to 39 checks from a single domain name:
  - **DNS passive**: SOA analysis, AXFR zone transfer detection, Wildcard DNS, CNAME hygiene (apex/chains), Zone consistency across NS, DNSBL blacklist check
  - **Email standards**: MTA-STS policy validation, SMTP TLS Reporting (TLS-RPT), BIMI brand indicators, DMARC external report authorization (RFC 7489 s7.1), SPF include chain depth analysis (permerror detection)
  - **Gateway/Recon**: SEG fingerprinting (Proofpoint, Mimecast, Barracuda, IronPort, Microsoft Defender, Google, 15+ providers), M365 tenant detection (OpenID, autodiscover, SIP federation), WHOIS/RDAP registration analysis, RPKI route origin validation
  - **TLS/Web**: TLS config (cert chain, cipher strength, deprecated protocols), Certificate Transparency via crt.sh, HSTS header analysis, HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP), security.txt (RFC 9116), HTTP->HTTPS redirect analysis, Cookie security flags (Secure, HttpOnly, SameSite)
  - **Subdomain/Takeover**: crt.sh CT log subdomain enumeration, Dangling CNAME takeover detection (31 service fingerprints: AWS S3/EB/CloudFront, Azure, GitHub Pages, Heroku, Netlify, Vercel, Shopify, etc.)
  - **Intrusive (--intrusive)**: SMTP security posture (banner, STARTTLS, VRFY/EXPN, open relay, SMTP smuggling via raw socket bare-LF injection), Bounce/NDR analysis (backscatter risk, recipient pre-validation)
  - **Port scanning (--intrusive)**: TCP connect scan on 18 common ports with dangerous port flagging, Shodan InternetDB enrichment
- **`--intrusive` flag**: enables SMTP probing, bounce analysis, and port scanning (disabled by default)
- **`--skip-external` flag**: skips checks that call external APIs (crt.sh, Shodan, RDAP, Cloudflare RPKI)
- **Check tagging**: BaseCheck now has `intrusive` and `external` class flags for automatic filtering
- **`mercure/http_utils.py`**: shared HTTP/TLS utility (fetch, TLS cert analysis, deprecated protocol detection, SMTP STARTTLS probing)
- **`mercure/recon.py`**: external data sources (crt.sh CT logs, Shodan InternetDB, RDAP domain lookup with IANA bootstrap)
- **New DNS utils**: `query_soa`, `attempt_axfr`, `resolve_cname_chain`, `query_dnsbl`, `query_all_ns`
- **285 unit tests** (was 132)

### Changed
- Scoring weights expanded from 12 to 39 checks (total weight 46.25)
- CLI help updated with full check catalog organized by category
- `resolve_checks()` now filters by intrusive/external flags automatically

## [0.3.0] - 2026-11-14

### Added
- **Unit test suite**: 132 tests covering all checks, scoring, DNS utils, SMTP delivery, config, and spoof engine
- **DNS cache with TTL**: thread-safe DNS response cache (`_DnsCache`), configurable TTL via `DNS_CACHE_TTL` (default 300s), `clear_cache()` API
- **Typed DNS errors**: `DnsError` enum (NONE, NXDOMAIN, NO_ANSWER, TIMEOUT, SERVFAIL, OTHER) and `DnsResult` dataclass with `__bool__`, `__iter__`, `__len__`
- **Parallel spoof execution**: `--no-parallel` flag to opt out; default runs all 12 methods via `ThreadPoolExecutor(max_workers=6)` with order-preserving results
- **Auto-discovery of check classes**: `checks/__init__.py` uses `pkgutil.iter_modules` to populate `ALL_CHECKS` and `CHECK_MAP` dynamically

### Changed
- **Code structure refactor**: cli.py split into 3 modules:
  - `runner.py`: orchestration (`resolve_checks`, `analyze_domain`, `analyze_file`, `run_spoof_test`)
  - `output.py`: rendering/serialization (banner, tables, JSON/CSV export)
  - `smtp.py`: generic SMTP delivery (`direct_deliver`, `relay_deliver`, `amp_deliver`)
- **Config now lazy-loaded**: `_ConfigProxy` pattern - no import-time `.env` reads, `reset()` method for test injection
- **Logger no longer has import-time side effects**: `_prune()` deferred to first write
- **DKIM key bit counting rewritten**: proper DER ASN.1 parsing of SubjectPublicKeyInfo instead of byte-length approximation
- **PTR matching fixed**: proper domain suffix check (`p == d or p.endswith(f".{d}")`) instead of substring match
- **SPF detection fixed**: `startswith("v=spf1")` on stripped/lowered text instead of `"v=spf1" in t.lower()`
- **SPF +all detection fixed**: regex `r"(^|\s)\+all\b"` instead of simple `in` check
- **Spoof header fixed**: `X-Oletros` renamed to `X-Oletros-Tool`
- **Stale `weight` attributes removed** from all check classes - weights are centralized in `scoring.WEIGHTS`
- `spoof.py` refactored: delivery patterns extracted into `_deliver_via_relay_or_mx()` and `_deliver_via_target_mx()`, shared helpers `_skip_result()`, `_error_result()`, `_log_result()`
- Removed dead `SCORE_STYLES` dict from scoring.py

## [0.2.0] - 2026-10-01

### Added
- **SMTP relay support for spoof mode**: configure an authenticated SMTP relay (OVH, etc.) via `.env` for realistic email delivery
  - `SMTP_RELAY_HOST`, `SMTP_RELAY_PORT`, `SMTP_RELAY_USER`, `SMTP_RELAY_PASS` config options
  - Supports SSL (port 465) and STARTTLS (port 587)
  - Methods routed via relay when configured: `direct`, `null_from`, `subdomain`, `mismatch`, `display_name`
  - Methods always direct (relay would defeat the test): `ghost`, `relay`, `internal`, `backscatter`
  - Falls back to direct MX delivery when relay is not configured
- **3 backscatter variants** for comprehensive NDR/bounce abuse testing:
  - `bs_inject`: content injection via NDR - phishing body in message to dead@target, if NDR includes original body, victim receives attacker content from trusted MTA
  - `bs_amp`: amplification - 5 dead recipients in 1 SMTP session, tests per-recipient NDR generation (1 email -> N bounces)
  - `bs_oob`: auto-reply abuse - sends to functional addresses (info@, contact@, support@, etc.), tests if OOO/vacation auto-replies honor return-path without sender validation (RFC 3834)
- IPv4-forced SMTP connections via `resolve_ipv4()` - fixes `[Errno 97] Address family not supported` on EXO endpoints that resolve to IPv6
- `.env` file created with all configuration options including SMTP relay placeholders
- **`resources/dkim_selectors.txt`**: comprehensive DKIM selector wordlist (5355 selectors) generated from builder.py patterns + vendor prefixes + year/month patterns + aggressive bruteforce + industry-wide classic selectors (ESP, cloud, security vendors, hosting providers, SaaS platforms)
- DKIM wordlist now loaded by default in all bruteforce modes (not just aggressive). Falls back to hardcoded `BASE_SELECTORS` if file missing

### Changed
- **Weights rebalanced for exploitation perspective**: Ghost 4.0 (was 2.5), DKIM 2.5 (was 3.0), DNSSEC 1.5 (was 2.5), CAA 1.5 (was 2.0), MX 1.0 (was 1.5), NS 1.0 (was 1.5), TLSA 0.5 (was 1.5), PTR 0.5 (was 1.0), SRV 0.25 (was 0.5), IPv6 0.25 (was 0.5)
- Spoof email subject now includes the method: "Security Test - direct", "Security Test - ghost", etc.
- Logger info level color changed from dark blue to `dodger_blue1` (light blue) for better readability
- Restructured project: all source files moved to `mercure/` package with `mercure.py` launcher at root
- Scoring direction clarified everywhere: **10/10 = maximum security, 0/10 = no security**
- Per-check scores now displayed as /10 (mapped from internal 0-3 scale: 0, 3, 7, 10)
- Global score threshold adjusted: green >= 7.0, orange >= 4.0, red < 4.0
- DKIM weight increased from 2.5 to 3.0 (cryptographic email auth deserves equal weight to SPF)
- DMARC weight increased from 3.0 to 3.5 (enforcement policy is the most critical email security control)
- DNSSEC weight increased from 2.0 to 2.5 (cache poisoning prevention is critical for trust chain)
- CAA weight increased from 1.5 to 2.0 (unauthorized cert issuance is a real attack vector)
- TLSA weight increased from 1.0 to 1.5 (DANE prevents STARTTLS stripping)
- DKIM evaluation reordered: weak keys and dangerous `l=` tag now score 1/3 (worst), test mode and guessable selectors score 2/3 (moderate)
- DMARC evaluation improved: `quarantine` with `pct < 100` now scores 1/3 instead of 2/3; subdomain policy (`sp=`) now parsed and included in details
- SPF evaluation improved: `redirect=` without explicit `all` mechanism now handled as score 2/3
- All imports converted to relative within the `mercure` package

### Added
- **Dual mode CLI**: `score` (default) and `spoof` modes via `python mercure.py <mode>`
- **Spoof mode** (`python mercure.py spoof -d domain -r recipient`): active email spoofing engine with 12 methods
- `mercure/spoof.py`: full spoofing engine with SMTP delivery, STARTTLS support, MX resolution
- Rich table output for spoof results with color-coded statuses (DELIVERED=red, REJECTED=green, SKIP=grey, ERROR=yellow)
- JSON export for spoof results (`--format json`)
- **Ghost Sender check** (`--checks ghost`): active SMTP probe detecting Exchange Online tenants vulnerable to direct endpoint spoofing
- `SMTP_TIMEOUT` config option (default 10s) for Ghost Sender probe timeout
- `mercure.py` launcher at project root (classic script, no pip install needed)
- `score_to_ten()` function for consistent internal-to-display score conversion
- Scoring explanation in CLI help output
- CHECKS.md, CHANGELOG.md, DETECT.md, HOW-TO.md documentation
- Local `.claude/memory/` for project memory persistence

### Removed
- Root-level Python source files (moved to `mercure/` package)
- `pip install -e .` installation method (replaced by direct script execution)

## [0.1.0] - 2026-06-15

### Added
- Initial release with 11 security checks: SPF, DKIM, DMARC, CAA, MX, NS, DNSSEC, IPv6, SRV, PTR, TLSA
- Rich CLI with banner, colored output, tables
- Multi-domain batch processing with ThreadPoolExecutor
- DKIM selector bruteforce with 100+ base selectors and pattern expansion
- Aggressive mode with year/month/vendor pattern generation
- JSON and CSV export formats
- Daily log rotation with configurable retention
- `.env` configuration support
