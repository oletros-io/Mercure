# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **SMTP relay support for spoof mode**: configure an authenticated SMTP relay (OVH, etc.) via `.env` for realistic email delivery
  - `SMTP_RELAY_HOST`, `SMTP_RELAY_PORT`, `SMTP_RELAY_USER`, `SMTP_RELAY_PASS` config options
  - Supports SSL (port 465) and STARTTLS (port 587)
  - Methods routed via relay when configured: `direct`, `null_from`, `subdomain`, `mismatch`, `display_name`
  - Methods always direct (relay would defeat the test): `ghost`, `relay`, `internal`, `backscatter`
  - Falls back to direct MX delivery when relay is not configured
- **3 backscatter variants** for comprehensive NDR/bounce abuse testing:
  - `bs_inject`: content injection via NDR — phishing body in message to dead@target, if NDR includes original body, victim receives attacker content from trusted MTA
  - `bs_amp`: amplification — 5 dead recipients in 1 SMTP session, tests per-recipient NDR generation (1 email → N bounces)
  - `bs_oob`: auto-reply abuse — sends to functional addresses (info@, contact@, support@, etc.), tests if OOO/vacation auto-replies honor return-path without sender validation (RFC 3834)
- IPv4-forced SMTP connections via `resolve_ipv4()` — fixes `[Errno 97] Address family not supported` on EXO endpoints that resolve to IPv6
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
- **Spoof mode** (`python mercure.py spoof -d domain -r recipient`): active email spoofing engine with 9 methods:
  - `direct`: deliver spoofed email via recipient's MX (tests SPF/DKIM/DMARC enforcement)
  - `ghost`: bypass SEG, deliver directly to EXO endpoint (tests partner connector absence)
  - `null_from`: null envelope sender with spoofed From header (tests bounce-style spoofing)
  - `subdomain`: spoof from `nonexistent.<domain>` (tests DMARC `sp=` subdomain policy)
  - `relay`: route through target's own MX to external recipient (tests open relay)
  - `mismatch`: envelope domain ≠ header From domain (tests DMARC alignment enforcement)
  - `display_name`: neutral sender with spoofed display name (tests BEC-style deception filtering)
  - `internal`: intra-domain spoof via target's MX (tests internal mail source validation)
  - `backscatter`: send to nonexistent@target, bounce to victim (tests recipient validation before accept)
- `mercure/spoof.py`: full spoofing engine with SMTP delivery, STARTTLS support, MX resolution
- Rich table output for spoof results with color-coded statuses (DELIVERED=red, REJECTED=green, SKIP=grey, ERROR=yellow)
- JSON export for spoof results (`--format json`)
- **Ghost Sender check** (`--checks ghost`): active SMTP probe detecting Exchange Online tenants vulnerable to direct endpoint spoofing (bypasses SPF/DKIM/DMARC entirely when MX routes through a third-party SEG without partner connector). Weight: 2.5. Reference: https://ghost-sender.com
- `SMTP_TIMEOUT` config option (default 10s) for Ghost Sender probe timeout
- `mercure.py` launcher at project root (classic script, no pip install needed)
- `score_to_ten()` function for consistent internal-to-display score conversion
- Scoring explanation in CLI help output
- CHECKS.md: detailed per-check reference (definition, ideal value, impact, exploitation examples)
- CHANGELOG.md, DETECT.md, HOW-TO.md documentation
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
