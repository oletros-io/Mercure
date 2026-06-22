# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
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
- **Ghost Sender check** (`--checks ghost`): active SMTP probe detecting Exchange Online tenants vulnerable to direct endpoint spoofing (bypasses SPF/DKIM/DMARC entirely when MX routes through a third-party SEG without partner connector). Weight: 2.5. Reference: https://ghost-sender.com
- `SMTP_TIMEOUT` config option (default 10s) for Ghost Sender probe timeout
- `mercure.py` launcher at project root (classic script, no pip install needed)
- `score_to_ten()` function for consistent internal-to-display score conversion
- Scoring explanation in CLI help output
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
