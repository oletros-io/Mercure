# CHECKS.md - Security Checks Reference

Each check audits a specific aspect of domain security. Scores reflect exploitability: **10/10 = maximum security, 0/10 = no security**.

49 checks organized by category. Weights reflect attacker exploitability - how much damage results from exploiting the absence of each control.

---

## Email Authentication & Policy

---

### GHOST - Ghost Sender (Exchange Online Direct Endpoint Spoofing)

**Weight: 4.0** (highest - bypasses all email authentication)

#### Definition

Detects whether an Exchange Online tenant is vulnerable to the Ghost Sender attack. When a domain's MX routes through a third-party Secure Email Gateway (Proofpoint, Mimecast, Barracuda, etc.) but no **partner connector** is configured in Exchange Online, an attacker can deliver spoofed emails directly to the EXO endpoint (`<dashed-domain>.mail.protection.outlook.com:25`), bypassing SPF, DKIM, and DMARC entirely.

#### Ideal Value

- MX not on Exchange Online -> **10/10** (not applicable)
- MX direct to EXO (no SEG) -> **10/10** (no bypass path)
- SEG + partner connector configured (5.7.51 response) -> **10/10**

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `not_exchange_online` | Domain doesn't use EXO - Ghost Sender not applicable |
| 10/10 | `mx_direct_to_exo` | MX points directly to EXO, no third-party SEG to bypass |
| 10/10 | `partner_connector_configured` | Partner connector blocks unauthorized direct delivery (5.7.51) |
| 7/10 | `exo_unreachable` | EXO endpoint exists but SMTP probe couldn't connect |
| 7/10 | `smtp_rejected` | EXO endpoint rejected the SMTP handshake (500-level) |
| 7/10 | `smtp_temp_reject` | EXO endpoint temporarily rejected (400-level) |
| 3/10 | `exo_exposed_inconclusive` | EXO endpoint responded but behavior unclear |
| 0/10 | `ghost_sender_vulnerable` | EXO endpoint accepts spoofed mail - full bypass confirmed |

#### Impact if Absent/Vulnerable

An attacker sends emails as `ceo@target.com` directly to the EXO endpoint on port 25. The email arrives in the recipient's inbox with no SPF/DKIM/DMARC failure because Exchange Online trusts direct-to-endpoint delivery when no partner connector restricts it. The SEG never sees the email. DMARC aggregate reports won't flag it because EXO doesn't evaluate SPF/DKIM on this path.

#### Exploitation Example

```
1. Discover MX routes through Proofpoint: dig MX target.com -> pphosted.com
2. Derive EXO endpoint: target-com.mail.protection.outlook.com
3. Verify endpoint resolves: dig A target-com.mail.protection.outlook.com
4. Connect directly:
   telnet target-com.mail.protection.outlook.com 25
   EHLO attacker.com
   MAIL FROM:<ceo@target.com>
   RCPT TO:<victim@target.com>
   DATA
   From: CEO <ceo@target.com>
   Subject: Urgent wire transfer
   ...
5. Email lands in inbox - SPF/DKIM/DMARC never evaluated
```

---

### DMARC - Domain-based Message Authentication, Reporting & Conformance

**Weight: 3.5** (enforcement policy - decides what happens to spoofed emails)

#### Definition

Checks the `_dmarc.<domain>` TXT record for the DMARC policy. DMARC tells receiving mail servers what to do when SPF and DKIM checks fail: reject the email, quarantine it, or do nothing. It also enables reporting so domain owners can monitor authentication failures.

#### Ideal Value

`v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@domain.com; ruf=mailto:forensic@domain.com`

- `p=reject` with `pct=100` - all failing emails are rejected
- `sp=reject` - subdomains inherit the same strict policy
- `rua` + `ruf` - aggregate and forensic reports enabled

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `reject_full` | `p=reject` at `pct=100` - maximum enforcement |
| 7/10 | `reject_partial_pct` | `p=reject` but `pct < 100` - some spoofed emails slip through |
| 7/10 | `quarantine` | `p=quarantine` at `pct=100` - spoofed emails go to spam, not rejected |
| 3/10 | `quarantine_partial_pct` | `p=quarantine` with `pct < 100` - partial spam quarantine |
| 3/10 | `none_policy` | `p=none` - monitoring only, no enforcement |
| 3/10 | `unknown_policy` | Unrecognized policy value |
| 0/10 | `no_dmarc` | No DMARC record at all |

#### Impact if Absent/Vulnerable

Without DMARC (or with `p=none`), receiving servers have no policy instruction. Even if SPF and DKIM fail, the server may deliver the email. An attacker can spoof the domain freely - the domain owner won't even know it's happening unless they check third-party reports.

#### Exploitation Example

```
1. Verify no DMARC: dig TXT _dmarc.target.com -> (empty)
2. Or DMARC p=none: dig TXT _dmarc.target.com -> "v=DMARC1; p=none"
3. Send spoofed email from any SMTP server:
   MAIL FROM:<hr@target.com>
   RCPT TO:<employee@target.com>
   DATA
   From: HR <hr@target.com>
   Subject: Password reset required
   ...
4. SPF fails, DKIM fails, but DMARC says "do nothing" -> email delivered
5. With p=none, domain owner gets reports but victims get phished
```

---

### SPF - Sender Policy Framework

**Weight: 3.0** (sender IP authorization - first line of defense)

#### Definition

Checks the domain's TXT record for an SPF policy (`v=spf1`). SPF defines which IP addresses and servers are authorized to send email on behalf of the domain. The `all` mechanism at the end determines what happens to unauthorized senders.

#### Ideal Value

`v=spf1 include:_spf.provider.com -all`

- `-all` (hard fail) - unauthorized IPs are explicitly rejected
- Includes only necessary sending sources

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `hard_fail` | `-all` - unauthorized senders rejected |
| 7/10 | `soft_fail` | `~all` - unauthorized senders marked but not rejected |
| 7/10 | `redirect_no_all` | `redirect=` present without explicit `all` mechanism |
| 3/10 | `neutral_all` | `?all` - no opinion on unauthorized senders |
| 3/10 | `unknown_policy` | SPF record exists but mechanism unclear |
| 0/10 | `allow_all_plus` | `+all` - explicitly allows any IP to send as this domain |
| 0/10 | `no_spf` | No SPF record |

#### Impact if Absent/Vulnerable

Without SPF (or with `+all`/`~all`), any server on the internet can send email claiming to be from the domain. With soft fail (`~all`), most receiving servers will still deliver the email (possibly to spam) rather than rejecting it outright. Only hard fail (`-all`) provides real protection.

#### Exploitation Example

```
1. Check SPF: dig TXT target.com -> "v=spf1 include:_spf.google.com ~all"
2. Soft fail (~all): spoofed emails may land in spam but aren't rejected
3. From any VPS/SMTP relay:
   MAIL FROM:<admin@target.com>
   RCPT TO:<victim@company.com>
   DATA
   From: Admin <admin@target.com>
   Subject: System maintenance - verify your credentials
   ...
4. SPF check: SOFTFAIL (sender IP not in SPF, but ~all = accept anyway)
5. Email delivered to spam folder - many users check spam regularly
6. With -all: email would be rejected outright by compliant receivers
```

---

### DKIM - DomainKeys Identified Mail

**Weight: 2.5** (cryptographic email verification - supports DMARC alignment)

#### Definition

Discovers DKIM selectors via bruteforce and analyzes the corresponding public keys. DKIM allows a sending server to cryptographically sign outgoing emails. The receiving server verifies the signature using the public key published in DNS at `<selector>._domainkey.<domain>`.

#### Ideal Value

- At least one DKIM selector with RSA >= 2048 bits (or Ed25519)
- No `l=` tag (body length limit - allows content injection)
- No `t=y` (test mode - receivers may ignore failures)
- Non-guessable selector names

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `strong_dkim` | Strong keys, no risky tags, non-guessable selectors |
| 7/10 | `test_mode` | Key found but `t=y` (test mode) - failures may be ignored |
| 7/10 | `all_selectors_guessable` | All selectors are common/guessable names |
| 3/10 | `weak_key` | RSA key < 2048 bits - can be factored |
| 3/10 | `dangerous_l_tag` | `l=` tag present - attacker can append content to signed email |
| 0/10 | `no_dkim` | No DKIM selectors found |

#### Impact if Absent/Vulnerable

Without DKIM, emails can't be cryptographically verified. This matters because DMARC alignment requires either SPF or DKIM to pass - if DKIM is absent and SPF fails (e.g., forwarded emails), DMARC fails too. Weak keys (< 2048 bits RSA) can be factored offline, allowing an attacker to forge DKIM signatures. The `l=` tag is particularly dangerous: it lets an attacker take a legitimately signed email and append arbitrary content (phishing links, malware) without breaking the signature.

#### Exploitation Example

```
1. Discover selector: dig TXT default._domainkey.target.com
2. Find weak key: RSA 1024-bit
3. Factor the key offline (feasible with cloud computing, ~$50-100):
   - Extract modulus from the DKIM public key
   - Use CADO-NFS or similar to factor
   - Reconstruct private key
4. Sign forged emails with the factored private key:
   DKIM-Signature: v=1; a=rsa-sha256; d=target.com; s=default; ...
5. Email passes DKIM verification -> DMARC alignment passes
6. Forged email appears fully authenticated

For l= tag exploitation:
1. Intercept a legitimate signed email from target.com
2. Append phishing content after the signed body length
3. Forward to victim - DKIM signature still valid
```

---

### MTA-STS - Mail Transfer Agent Strict Transport Security

**Weight: 1.5** (prevents STARTTLS stripping and MITM on SMTP transport)

#### Definition

Checks for the `_mta-sts.<domain>` TXT record (v=STSv1) and fetches the HTTPS policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`. MTA-STS instructs sending mail servers to require TLS when delivering to this domain's MX hosts and to validate the certificate.

#### Ideal Value

- TXT record: `v=STSv1; id=<unique-id>`
- Policy mode: `enforce` with `max_age >= 86400` (24 hours)
- MX patterns matching the domain's actual MX hosts

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `enforce` | MTA-STS enforce mode with max_age >= 86400 |
| 7/10 | `testing_mode` | Policy in testing mode - reporting only, no enforcement |
| 3/10 | `none_or_invalid` | TXT record exists but policy is invalid or mode is none |
| 0/10 | `no_mta_sts` | No MTA-STS TXT record |

#### Impact if Absent/Vulnerable

Without MTA-STS, a MITM attacker on the path between a sending server and the domain's MX can strip the STARTTLS offer from the EHLO response, forcing plaintext delivery. All email content (credentials, documents, confidential data) becomes visible. Even if both sides support TLS, opportunistic encryption without MTA-STS provides no guarantee - an active attacker can downgrade the connection.

#### Exploitation Example

```
1. No MTA-STS: dig TXT _mta-sts.target.com -> (empty)
2. MITM between sender MTA and target's MX:
   - Intercept SMTP connection
   - Remove "250-STARTTLS" from server's EHLO response
   - Sender proceeds in plaintext
3. All email traffic in clear text
4. Read/modify email content in transit
5. With MTA-STS enforce: sender MUST use TLS and validate cert -> MITM fails
```

---

### SEG - Secure Email Gateway Fingerprinting

**Weight: 1.5** (identifies email security infrastructure)

#### Definition

Fingerprints the domain's email security stack by analyzing MX records and SPF includes against known provider signatures (Proofpoint, Mimecast, Barracuda, IronPort, Microsoft Defender, Google, 15+ providers). Identifies both gateway-level (MX routing) and sender-level (SPF include) provider usage.

#### Ideal Value

- 2+ email security layers identified (e.g., dedicated SEG + cloud provider)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `multi_layer_seg` | 2+ email security providers detected - defense in depth |
| 7/10 | `single_seg` | 1 SEG detected - single layer of email security |
| 3/10 | `no_seg_detected` | No recognized email gateway provider in MX or SPF |
| 0/10 | `no_mx` | No MX records at all |

#### Impact if Absent/Vulnerable

Without a SEG, inbound email filtering depends entirely on the mail server's built-in capabilities. A dedicated SEG (Proofpoint, Mimecast, etc.) adds advanced threat protection: sandboxing, URL rewriting, impersonation detection, attachment analysis. However, a SEG that routes MX through itself while leaving the EXO direct endpoint unprotected creates the Ghost Sender attack surface.

#### Exploitation Example

```
1. No SEG detected: dig MX target.com -> 10 mail.target.com
2. Direct mail server with no advanced filtering:
   - Malware-laden attachments less likely to be sandboxed
   - Phishing URLs not rewritten or detonated
   - No impersonation detection for BEC attacks
3. Or: SEG present but single-layer -> bypass the SEG and all filtering is gone
4. Reconnaissance: the SEG provider reveals the email security investment level
```

---

### DMARC-EXT - DMARC External Report Authorization

**Weight: 1.0** (validates cross-domain DMARC reporting)

#### Definition

Checks whether DMARC aggregate (rua) and forensic (ruf) report URIs that point to external domains have proper authorization via `<source>._report._dmarc.<destination>` TXT records (RFC 7489 Section 7.1). Without this authorization, external reporting destinations silently discard reports.

#### Ideal Value

- All external report URIs authorized with valid `v=DMARC1` records at the `_report._dmarc` subdomain
- Or all report URIs point to the domain's own mailboxes (no external authorization needed)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `internal_reports_only` | All report URIs are on the domain itself - no external auth needed |
| 10/10 | `external_reports_authorized` | External report URIs all have valid authorization records |
| 3/10 | `unauthorized_external_report` | External report destination lacks authorization - reports silently dropped |
| 0/10 | `no_dmarc_reporting` | No DMARC record or no rua/ruf URIs |

#### Impact if Absent/Vulnerable

If external report destinations aren't authorized, DMARC aggregate and forensic reports are silently dropped by the receiving domain. The domain owner thinks monitoring is active but never receives data about authentication failures. Spoofing campaigns go undetected because the feedback loop is broken. An attacker who knows reporting is broken can spoof the domain with more confidence.

#### Exploitation Example

```
1. DMARC has rua pointing to external: "v=DMARC1; p=reject; rua=mailto:dmarc@reporting-service.com"
2. Check authorization: dig TXT target.com._report._dmarc.reporting-service.com -> (empty)
3. Reports are silently dropped by reporting-service.com
4. Domain owner has no visibility into SPF/DKIM/DMARC failures
5. Attacker spoofs target.com -> no DMARC failure alerts generated
6. The p=reject policy still works, but monitoring is blind
```

---

### TLS-RPT - SMTP TLS Reporting

**Weight: 0.5** (TLS failure reporting - low direct security impact)

#### Definition

Checks for the `_smtp._tls.<domain>` TXT record (v=TLSRPTv1). TLS-RPT (RFC 8460) allows sending mail servers to report TLS negotiation failures back to the domain owner, providing visibility into MTA-STS policy violations and STARTTLS issues.

#### Ideal Value

- `v=TLSRPTv1; rua=mailto:tls-reports@domain.com`
- Reporting address actively monitored

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `tls_rpt_configured` | TLS-RPT record with valid rua address |
| 3/10 | `no_reporting_address` | TLS-RPT record exists but no rua defined |
| 0/10 | `no_tls_rpt` | No TLS-RPT record |

#### Impact if Absent/Vulnerable

Without TLS-RPT, the domain owner has no visibility into TLS negotiation failures during mail delivery. If a STARTTLS stripping attack is occurring or an MX server's certificate is misconfigured, there's no automated alert. Combined with missing MTA-STS, this means transport-layer attacks are both possible and invisible.

#### Exploitation Example

```
No direct exploitation vector. TLS-RPT absence impacts:
1. No visibility into STARTTLS downgrade attacks in progress
2. No alerts when MTA-STS policy is violated
3. TLS certificate misconfigurations on MX servers go undetected
4. An active MITM stripping STARTTLS for weeks without detection
```

---

### SPF-DEPTH - SPF Include Chain Analysis

**Weight: 0.5** (SPF complexity - permerror risk)

#### Definition

Recursively walks the SPF include chain to count total DNS lookups. RFC 7208 limits SPF processing to 10 DNS lookups (include, a, mx, ptr, exists, redirect). Exceeding this limit causes a "permerror" - the SPF check fails entirely, which may result in email rejection or, worse, SPF being silently ignored.

#### Ideal Value

- Total DNS lookups < 8 (safe margin below the RFC limit of 10)
- Minimal include chain depth

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `spf_depth_ok` | < 8 DNS lookups - well within RFC limit |
| 3/10 | `spf_near_limit` | 8-10 lookups - near the RFC limit, fragile |
| 0/10 | `spf_permerror` | > 10 lookups - RFC violation, SPF processing may abort |
| 0/10 | `no_spf` | No SPF record |

#### Impact if Absent/Vulnerable

An SPF record exceeding 10 lookups triggers a permerror. Different receivers handle this differently: some treat it as SPF fail (blocking legitimate email), others treat it as a "none" result (ignoring SPF entirely). In the worst case, an attacker can spoof the domain because SPF evaluation aborts before reaching the `-all` mechanism.

#### Exploitation Example

```
1. Check SPF depth: target.com has 12 DNS lookups via nested includes
2. SPF processing aborts at lookup 10 (permerror)
3. The final -all mechanism is never evaluated
4. SPF result: permerror -> some receivers treat as "none"
5. Attacker spoofs from unauthorized IP -> SPF doesn't block it
6. DMARC alignment on SPF path fails -> falls back to DKIM only
```

---

### SPF-RECON - SPF Infrastructure Mapping

**Weight: 0.5** (reconnaissance value - maps email sending infrastructure)

#### Definition

Recursively walks the full SPF include tree to build an inventory of authorized sending infrastructure: IP ranges, include domains, identified ESPs (25 known patterns), and broad CIDR ranges. Maps the domain's entire email-sending ecosystem through passive DNS queries.

#### Ideal Value

- Tight SPF with <= 4 includes
- No broad IP ranges (e.g., /16 or wider)
- Minimal ESP count (dedicated sending infrastructure)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `tight_spf` | 0-1 includes, no broad ranges, minimal providers |
| 7/10 | `moderate_spf` | 2-4 includes, reasonable scope |
| 3/10 | `broad_spf` | 5-10 includes, broad ranges, or 3-4 ESPs |
| 0/10 | `extremely_broad_spf` | 10+ includes, very broad ranges, or 5+ ESPs |
| 0/10 | `no_spf` | No SPF record |

#### Impact if Absent/Vulnerable

A very broad SPF (many includes, wide IP ranges) means a large number of IPs are authorized to send as the domain. Each authorized ESP or IP range is a potential spoofing vector if compromised or misconfigured. The reconnaissance value is significant: an attacker learns which ESPs, marketing platforms, CRM tools, and cloud providers the organization uses - all from passive DNS queries.

#### Exploitation Example

```
1. Walk SPF tree: target.com includes _spf.google.com, spf.protection.outlook.com,
   sendgrid.net, amazonses.com, mktomail.com
2. 5 ESPs identified: Google Workspace, Microsoft 365, SendGrid, Amazon SES, Marketo
3. Broad IP ranges: 2x /16 blocks from legacy includes = ~130,000 authorized IPs
4. Any of these ESPs can send as target.com - compromise one = spoof the domain
5. Social engineering: target uses Marketo -> phish their marketing team
6. The SPF record is a map of the organization's email vendor ecosystem
```

---

### BIMI - Brand Indicators for Message Identification

**Weight: 0.25** (brand trust indicator - minimal security impact)

#### Definition

Checks for a BIMI record at `default._bimi.<domain>` (v=BIMI1). BIMI allows domains with DMARC `p=quarantine` or `p=reject` to display a verified brand logo in supported email clients. A VMC (Verified Mark Certificate) from a trusted CA provides stronger brand verification.

#### Ideal Value

- `v=BIMI1; l=<SVG logo URL>; a=<VMC certificate URL>`
- Logo is a Tiny PS SVG
- VMC from DigiCert or Entrust

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `bimi_with_vmc` | BIMI record with both logo and VMC certificate |
| 7/10 | `bimi_no_vmc` | BIMI record with logo but no VMC |
| 3/10 | `bimi_invalid` | BIMI record exists but no logo URL |
| 0/10 | `no_bimi` | No BIMI record |

#### Impact if Absent/Vulnerable

Without BIMI, email clients don't display a verified brand logo next to the domain's emails. This doesn't directly enable attacks but reduces brand trust signals. With BIMI, recipients can visually verify that an email comes from the claimed brand. A missing BIMI is a missed opportunity for anti-phishing (users can't spot fake emails by missing logo) but has no direct security impact.

#### Exploitation Example

```
No direct exploitation vector. BIMI absence impacts:
1. Emails from the domain lack visual brand verification
2. Users can't distinguish legitimate emails from spoofed ones by logo
3. Phishing emails spoofing the domain look identical to legitimate ones
4. With BIMI+VMC: spoofed emails won't show the verified logo -> visual red flag
```

---

## DNS Infrastructure

---

### AXFR - Zone Transfer

**Weight: 2.0** (full zone dump - critical exposure of all DNS records)

#### Definition

Attempts an AXFR (full zone transfer) against each nameserver for the domain. A successful zone transfer reveals every DNS record in the zone: all subdomains, internal hostnames, mail servers, service records, and infrastructure details.

#### Ideal Value

- AXFR denied on all nameservers (REFUSED or NOTAUTH)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `axfr_denied` | Zone transfer denied on all NS |
| 3/10 | `no_ns` | No nameservers found to test |
| 0/10 | `axfr_allowed` | Zone transfer succeeded - full zone exposed |

#### Impact if Absent/Vulnerable

A successful zone transfer gives an attacker the complete DNS zone file: every subdomain, every A/AAAA/MX/SRV/TXT record. This reveals internal hostnames, dev/staging environments, admin panels, VPN endpoints, database servers, and any other infrastructure published in DNS. It's the equivalent of handing an attacker a map of the entire domain.

#### Exploitation Example

```
1. Attempt AXFR: dig AXFR target.com @ns1.target.com
2. Zone transfer succeeds -> 500+ records dumped
3. Attacker discovers:
   - dev.target.com -> 10.0.1.5 (internal IP exposed)
   - staging-db.target.com -> 192.168.1.100
   - vpn.target.com -> 203.0.113.50
   - admin.target.com -> 198.51.100.10
4. Each discovered subdomain is a new attack surface
5. Internal IPs reveal network architecture
```

---

### DNSSEC - DNS Security Extensions

**Weight: 1.5** (DNS integrity - prevents cache poisoning but hard to exploit in practice)

#### Definition

Checks for DS (Delegation Signer) and DNSKEY records that form the DNSSEC chain of trust. DNSSEC cryptographically signs DNS responses, allowing resolvers to verify that responses haven't been tampered with between the authoritative server and the client.

#### Ideal Value

- DS record present at the parent zone (registrar)
- DNSKEY record present at the authoritative server
- Both form a valid chain of trust

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `dnssec_valid` | DS + DNSKEY both present - chain of trust established |
| 7/10 | `dnskey_no_ds` | DNSKEY published but no DS at parent - chain incomplete |
| 3/10 | `ds_no_dnskey` | DS at parent but no DNSKEY - broken chain |
| 0/10 | `no_dnssec` | Neither DS nor DNSKEY - no DNSSEC |

#### Impact if Absent/Vulnerable

Without DNSSEC, DNS responses can be spoofed via cache poisoning (Kaminsky attack). An attacker on the network path or racing the resolver can inject forged DNS responses, redirecting users to malicious servers. This can be used to hijack email (forge MX responses), intercept web traffic (forge A/AAAA responses), or bypass certificate validation (forge CAA responses). In practice, exploitation requires specific network conditions (on-path or timing the race), making it less immediately exploitable than email auth gaps.

#### Exploitation Example

```
1. Target has no DNSSEC: dig DS target.com -> (empty)
2. Perform DNS cache poisoning (Kaminsky-style):
   - Flood the recursive resolver with forged responses
   - Race the legitimate authoritative response
   - Inject: target.com MX -> attacker-mx.evil.com
3. All email for target.com now routes to attacker's server
4. Or inject forged A record: target.com -> attacker IP
5. Serve phishing site with Let's Encrypt cert (CAA also absent)
6. Users see valid HTTPS - no browser warnings
```

---

### CAA - Certificate Authority Authorization

**Weight: 1.5** (controls which CAs can issue certificates)

#### Definition

Checks for CAA DNS records that specify which Certificate Authorities are authorized to issue TLS certificates for the domain. CAs are required to check CAA records before issuing a certificate (since 2017, per CA/Browser Forum Ballot 187).

#### Ideal Value

```
target.com. CAA 0 issue "letsencrypt.org"
target.com. CAA 0 issuewild ";"
target.com. CAA 0 iodef "mailto:security@target.com"
```

- `issue` restricted to specific CAs
- `issuewild ";"` blocks wildcard certificates
- `iodef` for violation reporting

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `caa_restricted` | `issue` tag present with specific CA restrictions |
| 7/10 | `caa_permissive_issue` | `issue` tag present but permissive values |
| 3/10 | `caa_no_issue_tag` | CAA records exist but no `issue` tag |
| 0/10 | `no_caa` | No CAA records - any CA can issue certificates |

#### Impact if Absent/Vulnerable

Without CAA, any of the ~100+ trusted Certificate Authorities can issue a valid TLS certificate for the domain. If an attacker compromises a less-secure CA (or exploits a validation bypass in any CA), they can obtain a certificate that browsers and clients will trust. With CAA restricted to a single CA, the attacker must compromise that specific CA.

#### Exploitation Example

```
1. Check CAA: dig CAA target.com -> (empty)
2. Any CA can issue a cert. Attacker options:
   a. Find a CA with weak domain validation (e.g., email-based DV
      where attacker controls admin@ or webmaster@)
   b. Exploit BGP hijacking + any CA's HTTP-based DV
   c. Use a compromised/rogue CA
3. Obtain valid cert for target.com
4. Perform MITM attack on target.com HTTPS traffic
5. Intercept credentials, session tokens, API keys
6. With CAA: only the specified CA can issue - attack surface reduced by 99%
```

---

### NSEC-WALK - DNSSEC Zone Walking (intrusive)

**Weight: 1.5** (zone enumeration via DNSSEC - reveals hidden subdomains)

#### Definition

Tests whether DNSSEC NSEC records allow zone walking (enumerating all domain names in the zone by following the NSEC chain). Also analyzes NSEC3 parameters (algorithm, iterations, salt) to assess resistance to offline dictionary attacks. Follows up to 50 NSEC chain links.

#### Ideal Value

- NSEC3 with high iterations (>= 100) and a salt
- Or no NSEC records returned (non-DNSSEC zone)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `nsec3` (strong) | NSEC3 with iterations >= 100, salt present - resistant to walking |
| 7/10 | `no_nsec` | No NSEC/NSEC3 records (non-DNSSEC or no denial-of-existence) |
| 7/10 | `probe_failed` | NSEC probe failed or no NS found |
| 7/10 | `nsec3` (moderate) | NSEC3 with moderate parameters |
| 3/10 | `nsec_no_names` | NSEC present but no names discovered in walk |
| 3/10 | `nsec3` (weak) | NSEC3 with algo=1, iterations < 10, no salt |
| 0/10 | `nsec_walkable` | NSEC chain walkable - domain names discovered |

#### Impact if Absent/Vulnerable

NSEC zone walking reveals every domain name in the zone, similar to a zone transfer but using DNSSEC's denial-of-existence mechanism. An attacker follows the NSEC chain from record to record, building a complete list of hostnames. This reveals internal services, dev environments, admin panels, and other infrastructure that may not be discoverable through CT logs or brute-force.

#### Exploitation Example

```
1. Query nonexistent name: dig A random123.target.com @ns1.target.com
2. Response includes NSEC record: admin.target.com -> api.target.com
3. Follow the chain: dig A admin.target.com -> next NSEC -> backup.target.com
4. Continue walking: build complete list of all zone names
5. Discovered names not in CT logs or brute-force dictionaries
6. With NSEC3: names are hashed, offline cracking required (harder but not impossible)
```

---

### MX - Mail Exchanger

**Weight: 1.0** (email infrastructure availability)

#### Definition

Checks MX records for the domain. MX records define which servers accept email for the domain and in what priority order. Validates that MX records exist, are not null (`.`), are not IP literals, and that redundancy exists.

#### Ideal Value

- Multiple MX records with different priorities
- Hostnames (not IP addresses)
- No null MX (`.`)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `mx_ok` | Multiple MX records - redundancy in place |
| 7/10 | `single_mx` | Only one MX record - no redundancy |
| 3/10 | `null_mx` | Null MX (`.`) - domain explicitly rejects email |
| 3/10 | `ip_literal_mx` | MX points to an IP address (RFC violation) |
| 0/10 | `no_mx` | No MX record at all |

#### Impact if Absent/Vulnerable

A missing MX means no email delivery. A single MX provides no redundancy - if the server goes down, all inbound email is lost or queued until the sender gives up (typically 5 days). Null MX (`.`) explicitly declares the domain doesn't accept email, which can be intentional. IP-literal MX violates RFC 5321 and indicates misconfiguration that some servers will refuse.

#### Exploitation Example

```
1. Single MX: dig MX target.com -> 10 mail.target.com
2. DDoS mail.target.com - all inbound email fails
3. Senders queue email for up to 5 days, then bounce
4. Attacker sets up a lookalike domain with valid MX
5. Sends "our email is down, use this address instead" phish
6. Or: during the outage, targets can't receive MFA codes, password
   reset links, or security alerts - enabling other attacks
```

---

### NS - Nameservers

**Weight: 1.0** (DNS infrastructure resilience)

#### Definition

Checks nameserver count and provider diversity. DNS is the foundation of all domain services - if nameservers go down, everything (web, email, APIs) becomes unreachable. Provider diversity protects against single-provider outages.

#### Ideal Value

- 2+ nameservers
- Spread across different providers/ASNs

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `ns_ok` | Multiple NS across different providers |
| 7/10 | `same_provider_ns` | Multiple NS but all with the same provider |
| 3/10 | `single_ns` | Only one nameserver - single point of failure |
| 0/10 | `no_ns` | No NS records (shouldn't happen in practice) |

#### Impact if Absent/Vulnerable

A single nameserver or all nameservers on the same provider is a single point of failure. A DDoS attack on that provider, or a provider outage, takes the entire domain offline: no website, no email, no API. The 2016 Dyn DNS attack demonstrated this - major sites went offline because their NS records all pointed to Dyn.

#### Exploitation Example

```
1. Single NS: dig NS target.com -> ns1.smallprovider.com
2. DDoS smallprovider.com - target.com disappears from DNS
3. All services (web, email, API) become unreachable
4. Combined with DNS cache poisoning:
   - While legitimate NS is down, attacker answers DNS queries
   - Inject forged records (A, MX, etc.)
   - Redirect traffic to attacker infrastructure
5. Same-provider NS: if Cloudflare goes down (has happened),
   both NS are unreachable simultaneously
```

---

### DNSBL - DNS Blacklist Check

**Weight: 1.0** (IP reputation - indicates compromise or abuse)

#### Definition

Checks the domain's A record IPs against 4 major DNS blacklists: Spamhaus (zen.spamhaus.org), SpamCop (bl.spamcop.net), Barracuda (b.barracudacentral.org), and SORBS (dnsbl.sorbs.net). A blacklisted IP indicates the domain's infrastructure is flagged for spam, abuse, or known compromise.

#### Ideal Value

- All IPs clean across all 4 blacklists

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `clean` | All IPs clean on all blacklists |
| 7/10 | `no_a_record` | No A record to check |
| 0/10 | `blacklisted` | One or more IPs listed on a blacklist |

#### Impact if Absent/Vulnerable

A blacklisted IP means the domain's outbound email will be rejected or spam-filtered by many recipients. More importantly, a listing often indicates the IP has been used for spam or is part of a botnet - suggesting active compromise. From an attacker's perspective, a blacklisted domain is less useful for phishing (emails get blocked) but the listing itself may reveal ongoing abuse.

#### Exploitation Example

```
1. Check DNSBL: target.com resolves to 203.0.113.50
2. 203.0.113.50 listed on Spamhaus SBL
3. Implications:
   - IP may be compromised (part of spam botnet)
   - Outbound email from target.com blocked by many providers
   - Indicates weak outbound email security
4. Attacker targets: investigate why the IP is listed (compromised server = easy entry)
5. Not directly exploitable but strong indicator of poor security hygiene
```

---

### DNS-REBIND - Private/Reserved IP Resolution

**Weight: 1.0** (SSRF/rebinding risk - private IP exposure)

#### Definition

Checks the domain and 16 common subdomains (www, mail, ftp, dev, staging, api, vpn, admin, internal, intranet, test, corp, gateway, proxy, ns1, ns2) for resolution to private/reserved IP ranges: RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16), CGNAT (100.64.0.0/10), and IPv6 private ranges (::1, fc00::/7, fe80::/10).

#### Ideal Value

- All subdomains resolve to public IP addresses only
- No private/reserved IP resolution

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `all_public` | No private IP resolution detected |
| 7/10 | `some_private` | 1-2 subdomains resolve to private IPs |
| 3/10 | `many_private` | 3+ subdomains resolve to private IPs |
| 0/10 | `domain_private` | The apex domain itself resolves to a private IP |

#### Impact if Absent/Vulnerable

DNS records pointing to private/reserved IPs expose internal network topology and create SSRF/DNS rebinding attack vectors. An attacker can use these records to bypass SSRF protections (the domain passes allowlist checks but resolves to an internal IP) or perform DNS rebinding attacks (resolve to a public IP first, then switch to an internal IP after the CORS check).

#### Exploitation Example

```
1. dev.target.com resolves to 10.0.1.5
2. SSRF attack:
   - Find a web feature that fetches URLs (preview, webhook, import)
   - Submit: http://dev.target.com/admin
   - Application resolves dev.target.com -> 10.0.1.5
   - Request hits internal admin panel behind the firewall
3. DNS rebinding:
   - Attacker controls evil.com -> first resolves to attacker IP
   - Browser loads attacker's JavaScript
   - evil.com re-resolves to 10.0.1.5
   - JavaScript now accesses internal network from victim's browser
```

---

### SOA - Start of Authority

**Weight: 0.5** (zone configuration - operational health indicator)

#### Definition

Analyzes the SOA record for timer configuration (refresh, retry, expire, minimum) and admin contact presence. SOA timers control how secondary nameservers synchronize with the primary, affecting propagation speed and resilience.

#### Ideal Value

- Admin contact (rname) present
- Refresh: 3600-86400, Retry: 600-3600, Expire: 604800-2419200, Minimum: 300-3600
- Serial > 0

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `soa_ok` | SOA with valid admin contact and proper timers |
| 7/10 | `soa_weak_timers` | SOA present but one or more timers out of recommended range |
| 3/10 | `no_admin_contact` | SOA present but no admin contact (rname) |
| 0/10 | `no_soa` | No SOA record |

#### Impact if Absent/Vulnerable

Misconfigured SOA timers can cause secondary nameservers to serve stale data (too-long refresh) or lose the zone entirely (too-short expire). A missing admin contact means there's no documented responsible person for the zone. These are operational risks rather than direct security vulnerabilities, but they indicate poor DNS management that often correlates with other misconfigurations.

#### Exploitation Example

```
No direct exploitation. SOA issues impact:
1. Stale zone data: refresh too high -> DNS changes propagate slowly
2. Zone loss: expire too low -> secondary NS drops the zone during primary outage
3. Missing admin: no contact for reporting DNS abuse or zone issues
4. Operational indicator: poor SOA = likely poor DNS management overall
```

---

### WILDCARD - Wildcard DNS Detection

**Weight: 0.5** (catches all subdomains - masks dangling CNAMEs)

#### Definition

Probes for wildcard DNS by querying a random nonexistent subdomain (16-char hex string). If the random subdomain resolves to an IP address, the zone has a wildcard record that catches all undefined subdomains.

#### Ideal Value

- No wildcard (random subdomain returns NXDOMAIN)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `no_wildcard` | No wildcard DNS - random subdomain returns NXDOMAIN |
| 0/10 | `wildcard_enabled` | Wildcard active - random subdomain resolves to IP |

#### Impact if Absent/Vulnerable

Wildcard DNS masks dangling CNAME records (subdomain takeover becomes invisible), makes subdomain enumeration unreliable, and catches typosquatting attempts. While sometimes intentional (CDN routing), wildcards are a security antipattern: they prevent detection of abandoned subdomains and make the attack surface appear smaller than it actually is.

#### Exploitation Example

```
1. Wildcard detected: random.target.com -> 203.0.113.50
2. Impact on security assessment:
   - Dangling CNAME detection fails (everything resolves)
   - Subdomain brute-force returns false positives
   - Can't distinguish real from wildcard subdomains
3. If wildcard points to a web server with virtual hosting:
   - Any subdomain serves the same content
   - Cookie scope issues (cookies set on *.target.com)
   - Potential for subdomain-based XSS if content reflects hostname
```

---

### ZONE - NS Answer Consistency

**Weight: 0.5** (DNS synchronization health)

#### Definition

Queries the same record (A record for the domain) against each nameserver and compares answers. Inconsistent responses indicate synchronization failures between primary and secondary nameservers.

#### Ideal Value

- All nameservers return identical answers for the same query

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `consistent` | All NS return the same answer |
| 7/10 | `single_ns_cannot_compare` | Only one NS - nothing to compare |
| 7/10 | `ns_query_error` | One or more NS returned errors |
| 3/10 | `inconsistent_answers` | Different NS return different answers |

#### Impact if Absent/Vulnerable

Inconsistent DNS responses mean different clients get different answers depending on which nameserver they query. This can cause intermittent service disruptions, unpredictable email routing, and inconsistent TLS certificate validation. An attacker who discovers zone inconsistency knows the zone is poorly managed - and can target the stale nameserver for cache poisoning attacks since it serves outdated records.

#### Exploitation Example

```
1. Query all NS: ns1.target.com returns 203.0.113.50, ns2.target.com returns 198.51.100.10
2. Inconsistent - different clients get different IPs
3. If ns2 is stale:
   - It may serve expired records (old MX, old A records)
   - Old MX may point to decommissioned server -> email loss
   - Cache poisoning: target the stale NS (weaker, less monitored)
4. Operational: intermittent failures hard to diagnose (works for some users, not others)
```

---

### TLSA - DANE/SMTP Authentication

**Weight: 0.5** (transport security - low adoption makes exploitation unlikely)

#### Definition

Checks for TLSA records at `_25._tcp.<domain>`. TLSA records are part of DANE (DNS-based Authentication of Named Entities), which binds a TLS certificate to a domain via DNS. For SMTP, DANE prevents STARTTLS stripping attacks and rogue certificate attacks on mail transport.

#### Ideal Value

- TLSA record at `_25._tcp.<domain>` matching the MX server's certificate
- Requires DNSSEC (TLSA without DNSSEC is meaningless)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `tlsa_present` | TLSA record exists for SMTP |
| 0/10 | `no_tlsa` | No TLSA record |

#### Impact if Absent/Vulnerable

Without DANE/TLSA, SMTP connections are vulnerable to STARTTLS stripping: an attacker in a MITM position can remove the STARTTLS offer from the server's EHLO response, forcing the connection to transmit in plaintext. They can also present a rogue certificate. With TLSA, the sending server knows exactly which certificate to expect and will refuse to downgrade. In practice, DANE adoption for SMTP is very low (~2% of domains), so absence is the norm.

#### Exploitation Example

```
1. No TLSA: dig TLSA _25._tcp.target.com -> (empty)
2. MITM position between sender and target's MX:
   - Intercept SMTP connection
   - Strip STARTTLS from server's EHLO response
   - Sending server falls back to plaintext
3. Read all email content in transit (credentials, documents, etc.)
4. Or: present a rogue certificate for the MX hostname
   - Without TLSA, sending server has no way to verify the cert
   - Accept rogue cert -> attacker decrypts TLS traffic
5. With TLSA: sender verifies cert hash against DNS record -> rejects rogue cert
```

---

### PTR - Reverse DNS

**Weight: 0.5** (email deliverability indicator, not directly exploitable)

#### Definition

Resolves the domain's A records, performs reverse DNS lookups on each IP, and checks whether the PTR record matches the domain. Matching reverse DNS is a trust signal for mail servers - it proves the IP operator intentionally associated the IP with the domain.

#### Ideal Value

- Every A record has a PTR
- PTR contains the domain name (forward-confirmed reverse DNS)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `ptr_match` | PTR records match the domain |
| 7/10 | `ptr_no_match` | PTR exists but doesn't match the domain |
| 3/10 | `partial_ptr` | Some IPs have PTR, some don't |
| 0/10 | `no_ptr` | No reverse DNS for any IP |
| 0/10 | `no_a_record` | Domain has no A record to check |

#### Impact if Absent/Vulnerable

Missing or mismatched PTR primarily affects email deliverability - many mail servers (Gmail, Outlook, corporate) will reject or spam-flag emails from IPs without valid reverse DNS. From an exploitation perspective, lack of PTR makes it harder to trace the domain's infrastructure and doesn't directly enable attacks. However, it can indicate a rented/temporary host (VPS, cloud instance) that may have weaker security controls.

#### Exploitation Example

```
No direct exploitation vector. PTR impacts:
1. Outbound email from the domain's IPs gets rejected by receivers
   that require matching rDNS -> business impact
2. Reconnaissance: mismatched PTR reveals the hosting provider
   and infrastructure details (cloud provider, CDN, shared hosting)
3. Missing PTR on an IP sending as target.com suggests the domain
   owner doesn't control that IP's rDNS -> possible unauthorized sender
```

---

### CNAME - CNAME Hygiene

**Weight: 0.25** (DNS configuration health - RFC compliance)

#### Definition

Checks for CNAME on the zone apex (RFC violation), CNAME chain length, and CNAME+MX coexistence (RFC 5321 violation). CNAME at the apex can cause unpredictable behavior with other record types and is explicitly forbidden by RFC 1034.

#### Ideal Value

- No CNAME on zone apex
- CNAME chain length <= 3
- No CNAME+MX coexistence

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `cname_ok` | No CNAME issues |
| 3/10 | `cname_on_apex` | CNAME on zone apex - RFC violation |
| 3/10 | `cname_chain_too_long` | CNAME chain > 3 hops |
| 3/10 | `cname_mx_coexistence` | CNAME coexists with MX records - undefined behavior |

#### Impact if Absent/Vulnerable

CNAME on the zone apex violates RFC 1034 and causes undefined behavior with MX, NS, and SOA records. Some resolvers will refuse to follow the CNAME, others will follow it and ignore the conflicting records. CNAME+MX coexistence means email delivery is unpredictable - some receivers follow the MX, others follow the CNAME, and some reject entirely. Long CNAME chains increase resolution latency and failure points.

#### Exploitation Example

```
No direct exploitation. CNAME issues impact:
1. CNAME on apex + MX: some email servers can't resolve mail delivery
2. Long CNAME chains: additional resolution steps = more failure points
3. CNAME at apex: can't coexist with SOA/NS -> zone may behave unpredictably
4. Operational: hard-to-diagnose intermittent failures for different clients
```

---

### SRV - Mail Service Records

**Weight: 0.25** (auto-discovery convenience - negligible exploitation value)

#### Definition

Checks for mail-related SRV records: `_submission._tcp` (SMTP submission), `_imaps._tcp` (IMAP over TLS), `_pop3s._tcp` (POP3 over TLS). SRV records enable email clients to auto-discover server endpoints without manual configuration.

#### Ideal Value

- `_submission._tcp.<domain>` -> SMTP submission server
- `_imaps._tcp.<domain>` -> IMAP server
- `_pop3s._tcp.<domain>` -> POP3 server (if applicable)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `mail_srv_ok` | All 3 mail SRV records present |
| 7/10 | `partial_mail_srv` | Some SRV records present |
| 0/10 | `no_mail_srv` | No mail SRV records |

#### Impact if Absent/Vulnerable

Without SRV, email clients can't auto-discover server settings. Users must manually configure IMAP/SMTP servers, which increases the risk of connecting to rogue servers during initial setup (typosquatting, phishing "setup guides"). This is a very low risk - most modern email providers use Autodiscover (Microsoft) or autoconfig (Mozilla) instead of SRV.

#### Exploitation Example

```
No direct exploitation. Indirect risk:
1. User setting up email client for target.com
2. No SRV -> client can't auto-discover settings
3. User searches "target.com email settings"
4. Attacker's SEO-optimized page shows up with rogue server settings
5. User configures client to connect to attacker's IMAP/SMTP
6. Attacker captures credentials on login attempt
```

---

### IPv6 - AAAA Records

**Weight: 0.25** (network readiness - no direct security impact)

#### Definition

Checks whether the domain has AAAA (IPv6) records. IPv6 support indicates modern network infrastructure and ensures the domain is reachable from IPv6-only networks.

#### Ideal Value

- At least one AAAA record pointing to a valid IPv6 address

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `ipv6_present` | AAAA record exists |
| 0/10 | `no_ipv6` | No AAAA record |

#### Impact if Absent/Vulnerable

No direct security impact. Missing IPv6 means the domain is unreachable from IPv6-only networks (rare but growing). Some ISPs and mobile carriers use IPv6 by default - users on these networks rely on NAT64/DNS64 translation to reach IPv4-only domains, which adds latency and potential failure points.

#### Exploitation Example

```
No exploitation vector. IPv6 absence is a readiness indicator:
1. IPv6-only clients can't reach the domain natively
2. Must rely on carrier-grade NAT/translation -> performance impact
3. Does not affect email security, authentication, or spoofing
```

---

## TLS / Certificates / Web

---

### TLS - TLS Configuration

**Weight: 2.0** (transport encryption - MITM prevention)

#### Definition

Checks TLS configuration on both the web server (port 443) and each MX host (STARTTLS on port 25). Analyzes certificate chain, cipher strength, protocol version, self-signed certificates, and deprecated TLS (1.0/1.1) support.

#### Ideal Value

- Valid TLS certificate (not self-signed)
- TLS 1.2+ only (no TLS 1.0/1.1)
- Cipher bits >= 128
- STARTTLS offered on all MX hosts

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `tls_ok` | Valid cert, modern protocol, strong cipher, all MX have STARTTLS |
| 7/10 | `mx_missing_starttls` | Web TLS ok but some MX hosts don't offer STARTTLS |
| 3/10 | `cert_invalid` | Certificate validation failed |
| 3/10 | `self_signed` | Self-signed certificate |
| 3/10 | `weak_cipher` | Cipher strength < 128 bits |
| 3/10 | `deprecated_protocol` | TLS 1.0 or TLS 1.1 in use |
| 0/10 | `no_tls` | No TLS connection possible |

#### Impact if Absent/Vulnerable

Without TLS (or with weak TLS), all traffic between clients and the server is vulnerable to interception. A self-signed certificate triggers browser warnings and enables MITM (no CA validation). Deprecated TLS versions (1.0/1.1) have known vulnerabilities (BEAST, POODLE). Missing STARTTLS on MX means email is transmitted in plaintext between mail servers.

#### Exploitation Example

```
1. TLS 1.0 still enabled: connect with TLS 1.0 from MITM position
2. Exploit POODLE/BEAST to decrypt traffic
3. Or: self-signed cert -> user clicks through warning -> MITM
4. Or: no STARTTLS on MX -> email between servers in cleartext
5. Intercept credentials, session tokens, email content
6. With modern TLS (1.3) + valid cert: MITM not feasible
```

---

### CT - Certificate Transparency

**Weight: 1.0** (certificate monitoring - detects unauthorized issuance)

#### Definition

Queries crt.sh for Certificate Transparency log entries. CT logs record every publicly-trusted certificate issued for the domain, providing visibility into both legitimate and unauthorized certificate issuance. Also counts wildcard certificates and discovered subdomains.

#### Ideal Value

- CT records present (domain has issued certificates that are logged)
- Monitored for unexpected certificates

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `ct_monitored` | CT records found - certificates are being logged |
| 3/10 | `no_ct_records` | No CT log entries - domain may not use TLS, or certs not logged |

#### Impact if Absent/Vulnerable

Without CT monitoring, an attacker who obtains a fraudulent certificate for the domain can use it undetected. CT logs make certificate issuance transparent - if an unexpected certificate appears, it can be detected and revoked. No CT records may indicate the domain doesn't use TLS at all (no certificates to log), which is its own security issue.

#### Exploitation Example

```
1. CT monitoring reveals:
   - Unexpected certificates issued by unknown CAs
   - Wildcard certificates (potential abuse surface)
   - Certificates for dev/staging subdomains (attack surface discovery)
2. No CT records:
   - Domain may not use TLS (no certificates)
   - Or certificates not logged (misissued certs go undetected)
3. Attacker obtains fraudulent cert -> no CT alert -> MITM persists
```

---

### HSTS - HTTP Strict Transport Security

**Weight: 1.0** (forces HTTPS - prevents protocol downgrade)

#### Definition

Checks the `Strict-Transport-Security` response header on the domain's HTTPS endpoint. HSTS instructs browsers to only connect via HTTPS for a specified duration, preventing SSL stripping attacks and accidental HTTP connections.

#### Ideal Value

- `max-age >= 31536000` (1 year)
- `includeSubDomains`
- `preload` (submitted to browser preload list)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `hsts_full` | max-age >= 1 year + includeSubDomains + preload |
| 10/10 | `hsts_strong` | max-age >= 1 year + includeSubDomains |
| 7/10 | `hsts_moderate` | max-age >= 6 months |
| 3/10 | `hsts_weak` | HSTS present but max-age < 6 months |
| 0/10 | `no_hsts` | No HSTS header |
| 0/10 | `unreachable` | HTTPS endpoint unreachable |

#### Impact if Absent/Vulnerable

Without HSTS, users who type `target.com` (without https://) are first connected over HTTP before being redirected to HTTPS. An attacker in a MITM position can intercept this initial HTTP request (SSL stripping) and present a fake HTTP version of the site. With HSTS, the browser refuses to connect over HTTP after the first visit.

#### Exploitation Example

```
1. No HSTS: user visits http://target.com at a coffee shop
2. Attacker on the same WiFi performs SSL stripping:
   - Intercept HTTP request before redirect to HTTPS
   - Present fake HTTP version of target.com
   - Proxy user's traffic, capture credentials
3. With HSTS: browser refuses HTTP connection -> attack fails
4. Without includeSubDomains: subdomains still vulnerable
```

---

### HEADERS - HTTP Security Headers

**Weight: 1.0** (defense-in-depth for web applications)

#### Definition

Checks for 6 critical HTTP security headers: Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cross-Origin-Opener-Policy (COOP).

#### Ideal Value

- All 6 headers present with secure values

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `all_headers` | 6/6 security headers present |
| 7/10 | `most_headers` | 4-5 headers present |
| 3/10 | `some_headers` | 2-3 headers present |
| 0/10 | `missing_headers` | 0-1 headers present |
| 0/10 | `unreachable` | HTTPS endpoint unreachable |

#### Impact if Absent/Vulnerable

Missing security headers leave web applications vulnerable to common attacks: no CSP enables XSS, no X-Frame-Options enables clickjacking, no X-Content-Type-Options enables MIME sniffing attacks, no Referrer-Policy leaks URLs to third parties, no Permissions-Policy allows unrestricted API access (camera, microphone, geolocation), and no COOP enables cross-origin attacks.

#### Exploitation Example

```
1. No CSP: inject malicious JavaScript via XSS
2. No X-Frame-Options: iframe target.com inside attacker's page -> clickjacking
3. No X-Content-Type-Options: upload .txt file interpreted as HTML -> XSS
4. No Referrer-Policy: URLs with tokens/session IDs leak to third parties
5. Each missing header is an independent attack vector
6. All 6 missing = no web-layer defense-in-depth
```

---

### REDIRECT - HTTP to HTTPS Redirect

**Weight: 0.5** (TLS upgrade path)

#### Definition

Checks whether HTTP (port 80) requests are redirected to HTTPS. Validates the redirect status code, destination URL, and whether the upgrade is to the same domain.

#### Ideal Value

- HTTP 301/308 redirect to `https://<same-domain>`

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `http_to_https` | HTTP redirects to HTTPS on the same domain |
| 10/10 | `http_to_https_www` | HTTP redirects to HTTPS with www prefix |
| 7/10 | `http_not_available` | HTTP port not responding (HTTPS-only) |
| 3/10 | `redirect_no_tls` | HTTP redirects but not to HTTPS |
| 3/10 | `http_unreachable` | HTTP returns unexpected status |
| 0/10 | `no_redirect_to_https` | HTTP serves content without redirecting to HTTPS |

#### Impact if Absent/Vulnerable

If HTTP doesn't redirect to HTTPS, users who visit `http://target.com` receive unencrypted content. An attacker on the network path can intercept and modify this content (inject malware, redirect to phishing, capture credentials). Combined with missing HSTS, this creates a persistent downgrade attack vector.

#### Exploitation Example

```
1. http://target.com serves content (200 OK, no redirect)
2. All traffic on HTTP is in cleartext
3. MITM attacker injects malicious JavaScript into the HTTP response
4. User's browser executes attacker's code
5. With redirect to HTTPS: user immediately upgraded to encrypted connection
```

---

### COOKIE - Cookie Security Flags

**Weight: 0.5** (session protection)

#### Definition

Fetches the domain's HTTPS page and analyzes Set-Cookie headers for security flags: `Secure` (HTTPS-only), `HttpOnly` (no JavaScript access), and `SameSite` (CSRF protection).

#### Ideal Value

- All cookies have Secure, HttpOnly, and SameSite flags

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `no_cookies` | No cookies set (nothing to protect) |
| 10/10 | `cookies_secured` | All cookies have Secure + HttpOnly + SameSite |
| 7/10 | `cookies_partial` | Some cookies secured, some missing flags |
| 3/10 | `cookies_insecure` | No cookies have all required flags |
| 0/10 | `unreachable` | HTTPS endpoint unreachable |

#### Impact if Absent/Vulnerable

Cookies without `Secure` can be intercepted over HTTP. Without `HttpOnly`, JavaScript (XSS payloads) can steal session cookies. Without `SameSite`, cookies are sent on cross-origin requests (CSRF attacks). Session hijacking is the primary exploitation path - an attacker who steals a session cookie gains the victim's authenticated access.

#### Exploitation Example

```
1. Session cookie without HttpOnly:
   - XSS payload: document.cookie -> exfiltrates session token
2. Session cookie without Secure:
   - MITM on HTTP intercepts the cookie
3. Session cookie without SameSite:
   - Attacker's page triggers cross-origin request with victim's cookie (CSRF)
4. Combined: XSS + no HttpOnly = instant session hijacking
```

---

### SEC.TXT - security.txt

**Weight: 0.25** (vulnerability disclosure - operational maturity indicator)

#### Definition

Checks for a `security.txt` file at `https://<domain>/.well-known/security.txt` (RFC 9116). This file provides security researchers with a way to report vulnerabilities - Contact and Expires fields are the minimum required.

#### Ideal Value

- Contact field with a valid URI (mailto: or https://)
- Expires field with a future date

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `security_txt_valid` | Contact + Expires fields present |
| 7/10 | `no_expires` | Contact present but no Expires field |
| 3/10 | `invalid_security_txt` | File exists but no Contact field |
| 0/10 | `no_security_txt` | No security.txt file |

#### Impact if Absent/Vulnerable

Without security.txt, researchers who find vulnerabilities have no clear reporting channel. Bugs get disclosed publicly, sold on bug bounty markets, or silently exploited. A missing security.txt doesn't create vulnerabilities but prevents them from being reported and fixed.

#### Exploitation Example

```
No direct exploitation. security.txt absence impacts:
1. Researcher finds XSS/SQLI on target.com
2. No security.txt -> no clear reporting channel
3. Researcher may: disclose publicly, sell the vuln, or just walk away
4. With security.txt: researcher reports -> vulnerability fixed before exploitation
```

---

## Recon / Attack Surface

---

### DANGLING - Subdomain Takeover Detection

**Weight: 3.0** (subdomain takeover = full control of a trusted subdomain)

#### Definition

Enumerates subdomains via crt.sh CT logs, resolves CNAME chains, and checks if the final CNAME target has no A record (dangling). Matches against 31 known takeover-vulnerable service fingerprints: AWS S3/EB/CloudFront, Azure App Service/Front Door/Blob/VM/Traffic Manager, GitHub Pages, Heroku, Netlify, Vercel, Shopify, Zendesk, and more.

#### Ideal Value

- No dangling CNAME records
- All CNAME targets resolve to active services

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `no_dangling` | No dangling CNAMEs detected |
| 7/10 | `enumeration_limited` | Enumeration returned no subdomains to check |
| 3/10 | `dangling_cname_found` | Dangling CNAME found but not on a known takeover service |
| 0/10 | `subdomain_takeover_possible` | Dangling CNAME to a known takeover-vulnerable service |

#### Impact if Absent/Vulnerable

A dangling CNAME pointing to a deprovisioned cloud service allows an attacker to claim that service and control the subdomain. The attacker can serve arbitrary content under `*.target.com`, set cookies for the parent domain, intercept OAuth callbacks, host phishing pages on a trusted domain, and bypass CSP/CORS restrictions that whitelist `*.target.com`.

#### Exploitation Example

```
1. blog.target.com CNAME -> target.herokuapp.com (app deleted)
2. Attacker creates "target" app on Heroku
3. blog.target.com now serves attacker's content
4. Exploitation:
   - Phishing: "blog.target.com/login" on a trusted domain
   - Cookie theft: set cookies for .target.com
   - OAuth hijack: if blog.target.com is an authorized redirect URI
   - CSP bypass: if CSP whitelists *.target.com
5. Victim sees the real target.com domain in the URL bar
```

---

### SUBDOMAINS - Subdomain Enumeration

**Weight: 1.5** (attack surface mapping via CT logs)

#### Definition

Discovers subdomains through Certificate Transparency logs (crt.sh) and optionally through subfinder (if installed). Resolves discovered subdomains and flags sensitive ones (dev, staging, test, admin, internal, vpn, api, beta) that may expose internal services.

#### Ideal Value

- Minimal public subdomain footprint
- No sensitive subdomains (dev, staging, admin, etc.) resolving to public IPs

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `minimal_surface` | < 5 subdomains discovered |
| 7/10 | `normal_surface` | Normal number of subdomains, no sensitive exposure |
| 7/10 | `no_ct_data` | No CT data available |
| 3/10 | `sensitive_subdomains_exposed` | 3+ sensitive subdomains resolving publicly |

#### Impact if Absent/Vulnerable

Exposed sensitive subdomains (dev, staging, admin, vpn) reveal internal infrastructure that may have weaker security controls than production. Dev/staging environments often have debug mode enabled, default credentials, or outdated software. VPN endpoints reveal remote access infrastructure for targeted attacks.

#### Exploitation Example

```
1. CT enumeration reveals: dev.target.com, staging.target.com, admin.target.com
2. dev.target.com: debug mode enabled, stack traces on errors
3. staging.target.com: old version with known CVE
4. admin.target.com: login page with no rate limiting
5. Each sensitive subdomain is a separate attack vector
```

---

### M365 - Microsoft 365 Tenant Detection

**Weight: 1.0** (tenant exposure - reveals organization's cloud platform)

#### Definition

Detects Microsoft 365 usage through MX records (mail.protection.outlook.com), autodiscover CNAME (autodiscover.outlook.com), SIP federation SRV records, and tenant ID extraction via OpenID configuration endpoint.

#### Ideal Value

- M365 indicators present but tenant ID not publicly exposed
- Or: domain doesn't use M365

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `no_m365` | No M365 indicators detected |
| 7/10 | `m365_detected` | M365 indicators present but no tenant ID exposed |
| 7/10 | `m365_tenant_exposed` | M365 tenant ID publicly visible |

#### Impact if Absent/Vulnerable

An exposed M365 tenant ID allows targeted attacks: tenant-specific phishing pages, enumeration of valid user accounts via Azure AD login responses, and identification of federation configurations. Knowing the organization uses M365 shapes the attack approach (target Exchange Online, SharePoint, OneDrive, Teams).

#### Exploitation Example

```
1. Tenant ID extracted from OpenID configuration endpoint
2. Tenant ID: 12345678-abcd-efgh-ijkl-123456789012
3. Attacker can:
   - Enumerate valid accounts via Azure AD login (timing/response differences)
   - Create targeted M365 phishing pages (matching the login flow)
   - Identify federated vs managed authentication
   - Target Exchange Online, SharePoint, Teams
4. Combined with password spraying: slow brute-force against valid accounts
```

---

### AUTODISCOVER - Autodiscover/Autoconfig Endpoint Security

**Weight: 1.0** (mail client auto-configuration - info leak risk)

#### Definition

Probes 4 HTTP autodiscover/autoconfig endpoints, plus SRV and CNAME records. Checks for information leakage (server type, internal hostnames, internal IPs) in responses from autodiscover.xml, root autodiscover, Mozilla autoconfig, and HTTP autoconfig endpoints.

#### Ideal Value

- Autodiscover endpoints return 401/403 (configured but secured)
- No information leakage (internal IPs, server types, internal hostnames)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `no_autodiscover` | No autodiscover endpoints or records found |
| 7/10 | `autodiscover_secured` | Endpoints return 401/403 or SRV/CNAME present but secured |
| 3/10 | `autodiscover_accessible` | Endpoints accessible without authentication |
| 3/10 | `autoconfig_http_unencrypted` | Autoconfig served over unencrypted HTTP |
| 3/10 | `autodiscover_limited_leak` | Minor information leakage detected |
| 0/10 | `autodiscover_info_leak` | Major information leak: server type or internal network details |

#### Impact if Absent/Vulnerable

Accessible autodiscover endpoints can leak internal hostnames, IP addresses, server types (Exchange, Zimbra, Dovecot), and infrastructure details. Unencrypted HTTP autoconfig allows MITM to redirect mail clients to rogue servers. Autodiscover is also a known credential harvesting vector (autodiscover "leak" where requests escalate to parent domains).

#### Exploitation Example

```
1. https://autodiscover.target.com/autodiscover/autodiscover.xml returns 200
2. Response body contains:
   - Internal hostname: mail01.corp.target.internal
   - Internal IP: 10.0.5.20
   - Server type: Exchange 2019
3. Attacker now knows:
   - Internal network scheme (10.0.x.x)
   - Exchange version (check for known CVEs)
   - Internal naming convention (.corp.target.internal)
4. HTTP autoconfig: MITM injects rogue server settings -> credential capture
```

---

### OPEN PORTS - TCP Port Scan (intrusive)

**Weight: 1.0** (attack surface mapping - dangerous service detection)

#### Definition

TCP connect scan on 18 common ports (FTP, SSH, Telnet, SMTP, HTTP, POP3, IMAP, HTTPS, SMB, SMTPS, Submission, IMAPS, POP3S, MySQL, RDP, PostgreSQL, HTTP-alt, HTTPS-alt). Flags dangerous ports (FTP, Telnet, SMB, MySQL, RDP, PostgreSQL) and enriches with Shodan InternetDB data.

#### Ideal Value

- Only expected ports open (HTTP, HTTPS, SMTP, SMTPS, Submission, IMAPS, POP3S)
- No dangerous ports (FTP, Telnet, SMB, database ports, RDP)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `expected_ports_only` | Only standard web/mail ports open |
| 7/10 | `no_a_record` | No A record to scan |
| 7/10 | `unexpected_ports` | Non-standard ports open (not dangerous) |
| 0/10 | `dangerous_ports_open` | Dangerous ports open (FTP, Telnet, SMB, DB, RDP) |

#### Impact if Absent/Vulnerable

Dangerous open ports expose high-risk services to the internet: FTP (cleartext credentials, directory traversal), Telnet (cleartext everything), SMB (EternalBlue, relay attacks), database ports (unauthorized access, SQL injection), RDP (BlueKeep, brute-force). Each is an independent attack vector.

#### Exploitation Example

```
1. Port scan reveals: 21/FTP, 3389/RDP, 3306/MySQL open
2. FTP: anonymous login or brute-force credentials -> file access
3. RDP: brute-force or BlueKeep exploit -> full system access
4. MySQL: connect directly if no auth or weak password -> database dump
5. Each dangerous port is a critical finding on its own
```

---

### SUB-BRUTE - Dictionary Subdomain Enumeration (intrusive)

**Weight: 1.0** (active subdomain discovery - finds non-CT subdomains)

#### Definition

Brute-forces subdomains using a 200+ word dictionary covering common patterns: infrastructure (ns1, mx, cdn), development (dev, staging, test, qa), admin (admin, panel, dashboard), services (api, graphql, ws), security (vpn, sso, auth), and more. Detects and filters wildcard DNS. Categorizes findings as sensitive, infrastructure, or standard.

#### Ideal Value

- Minimal exposed subdomains (0-2 resolving)
- No sensitive subdomains (dev, staging, admin, vpn, etc.)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `minimal_exposure` | 0-2 subdomains found |
| 7/10 | `standard_only` | Only standard/infrastructure subdomains found |
| 7/10 | `wildcard_active` | Wildcard DNS active - results unreliable |
| 3/10 | `some_sensitive` | 1-5 sensitive subdomains found |
| 0/10 | `many_sensitive` | 5+ sensitive subdomains found |

#### Impact if Absent/Vulnerable

Sensitive subdomains found by brute-force (that are not in CT logs) represent hidden attack surface. Dev, staging, admin, CI/CD, database, and monitoring subdomains often have weaker security controls. These hosts may run debug builds, accept default credentials, or expose internal management interfaces.

#### Exploitation Example

```
1. Brute-force discovers: jenkins.target.com, grafana.target.com, k8s.target.com
2. jenkins.target.com: no authentication on CI pipeline -> code execution
3. grafana.target.com: default admin/admin -> view all metrics and dashboards
4. k8s.target.com: Kubernetes dashboard without RBAC -> cluster takeover
5. These weren't in CT logs - only discovered by active enumeration
```

---

### WHOIS - Domain Registration (RDAP)

**Weight: 0.5** (domain lifecycle - expiry and transfer protection)

#### Definition

Queries RDAP (Registration Data Access Protocol) for domain registration details: expiry date, registrar, and transfer lock status. Checks for imminent expiry and missing transfer protection (clientTransferProhibited status).

#### Ideal Value

- Domain expiry > 90 days away
- Transfer lock (clientTransferProhibited) active
- Valid registrar

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `whois_ok` | Domain not expiring, transfer lock active |
| 7/10 | `rdap_unavailable` | RDAP query failed (registry doesn't support RDAP) |
| 3/10 | `domain_renewal_soon` | Domain expires in 31-90 days |
| 3/10 | `no_transfer_lock` | No clientTransferProhibited status |
| 0/10 | `domain_expiring` | Domain expires in 30 days or less |

#### Impact if Absent/Vulnerable

An expiring domain can be registered by an attacker after it drops. Without transfer lock, an attacker who compromises the registrar account (phishing, credential stuffing) can transfer the domain to their own registrar and take full control of all services (web, email, DNS). Domain hijacking is one of the most devastating attacks - complete infrastructure takeover.

#### Exploitation Example

```
1. Domain expires in 15 days, no transfer lock
2. Attacker registers domain after expiry:
   - All email now routes to attacker's MX
   - Website controlled by attacker
   - SSL certificates can be issued by attacker
3. Or: attacker transfers domain before expiry:
   - Social engineer registrar support
   - Compromise registrar account credentials
   - No transfer lock = immediate transfer initiation
```

---

### RPKI - Route Origin Authorization

**Weight: 0.5** (BGP routing security - prevents IP prefix hijacking)

#### Definition

Checks RPKI (Resource Public Key Infrastructure) validity for the domain's IP address via the Cloudflare RPKI API. RPKI allows IP address holders to cryptographically assert which ASN is authorized to originate their IP prefix, preventing BGP hijacking.

#### Ideal Value

- RPKI status: valid (ROA exists and matches the originating AS)

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `rpki_valid` | Valid ROA - authorized AS matches |
| 7/10 | `rpki_unknown` | RPKI status unknown (API error or no A record) |
| 3/10 | `rpki_not_found` | No ROA found for the prefix |
| 0/10 | `rpki_invalid` | ROA exists but doesn't match originating AS - possible hijack |

#### Impact if Absent/Vulnerable

Without RPKI, an attacker can perform BGP hijacking: announce the domain's IP prefix from a rogue AS, causing traffic to be routed to the attacker's infrastructure. This enables MITM on all services (web, email, API), certificate issuance (DV certificates via HTTP validation), and complete traffic interception. RPKI invalid status is worse than not-found - it indicates an active routing mismatch.

#### Exploitation Example

```
1. No ROA for target.com's IP prefix (203.0.113.0/24)
2. Attacker announces 203.0.113.0/24 from rogue AS
3. Traffic destined for target.com routes to attacker
4. Attacker can:
   - Intercept all web traffic (HTTPS downgrade if no HSTS preload)
   - Receive all email (BGP-hijacked MX resolution)
   - Issue DV certificates (pass HTTP validation)
5. With RPKI valid: RPKI-validating networks drop the rogue announcement
```

---

## SMTP Intrusive Checks

---

### SMTP-SEC - SMTP Security Posture (intrusive)

**Weight: 2.0** (SMTP configuration - open relay, smuggling, user enumeration)

#### Definition

Per-MX comprehensive SMTP security assessment: banner/version disclosure, STARTTLS enforcement, VRFY/EXPN user enumeration, open relay testing, and SMTP smuggling detection (bare-LF injection via raw socket). Tests up to 3 MX hosts.

#### Ideal Value

- STARTTLS offered and working
- No version disclosure in banner
- VRFY/EXPN disabled
- Open relay refused
- SMTP smuggling blocked

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `smtp_hardened` | All MX: STARTTLS, no enumeration, no relay, no smuggling |
| 7/10 | `smtp_partial` | Some security measures in place but not all |
| 7/10 | `no_mx` | No MX records to test |
| 3/10 | `user_enumeration` | VRFY or EXPN enabled - user enumeration possible |
| 3/10 | `banner_exposed_no_tls` | Version disclosed in banner without STARTTLS |
| 0/10 | `open_relay` | Open relay detected - anyone can send email through this server |
| 0/10 | `smtp_smuggling` | SMTP smuggling vulnerable (accepts bare LF as message terminator) |

#### Impact if Absent/Vulnerable

An open relay lets any attacker send email through the server, bypassing SPF (the relay's IP is authorized). SMTP smuggling allows injecting additional messages within a single SMTP session, potentially bypassing security filters. VRFY/EXPN enables user enumeration for targeted phishing. Version disclosure helps attackers identify vulnerable software.

#### Exploitation Example

```
1. Open relay detected on mx1.target.com:
   - Send email through target.com's own mail server
   - SPF passes (the email comes from an authorized IP)
   - Bypass all email authentication
2. SMTP smuggling:
   - Inject message within another message's DATA section
   - Bypass content filters (smuggled content not inspected)
3. VRFY: enumerate valid users for targeted phishing
4. Version in banner: "Postfix 3.5.0" -> check for known CVEs
```

---

### SMTP-RECON - SMTP Reconnaissance (intrusive)

**Weight: 2.0** (SMTP intelligence gathering - NTLM info leak, infrastructure discovery)

#### Definition

Per-MX SMTP reconnaissance: EHLO hostname analysis (internal hostnames), AUTH method enumeration, NTLM Type 1/Type 2 challenge-response extraction (NetBIOS domain/computer name, DNS domain/tree, OS version), and HELP command probing. Tests up to 3 MX hosts.

#### Ideal Value

- EHLO returns the public MX hostname (not internal)
- No NTLM auth offered (or NTLM info leak mitigated)
- AUTH PLAIN/LOGIN not offered without TLS
- HELP command disabled or returns generic response

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `minimal_exposure` | No NTLM, no internal hostnames, no plaintext auth |
| 7/10 | `extensions_exposed` | SMTP extensions and HELP response expose some information |
| 7/10 | `no_mx` | No MX records to test |
| 3/10 | `internal_info_leaked` | Internal hostname in EHLO or AUTH PLAIN/LOGIN without TLS |
| 0/10 | `ntlm_info_leak` | NTLM challenge-response leaks AD domain, internal hostname, OS version |

#### Impact if Absent/Vulnerable

NTLM info leak on SMTP is one of the most valuable reconnaissance finds: a single NTLM Type 2 response reveals the Active Directory domain name, internal computer name, DNS tree name, and sometimes OS version - all without authentication. This maps the internal network and enables targeted attacks (Kerberoasting, password spraying against the AD domain).

#### Exploitation Example

```
1. Connect to mx1.target.com:25, EHLO, AUTH NTLM
2. Send NTLM Type 1 message, receive Type 2 challenge
3. Decode Type 2 response:
   - NetBIOS domain: TARGETCORP
   - DNS domain: ad.target.internal
   - Computer name: EXCH01
   - OS: Windows Server 2019
4. Attacker now knows:
   - Internal AD domain name -> password spraying target
   - Internal naming convention -> predict other hostnames
   - Exchange server name -> target for ProxyShell/ProxyLogon
5. All this from a single unauthenticated SMTP connection
```

---

### BOUNCE - NDR/Backscatter Analysis (intrusive)

**Weight: 2.0** (recipient validation - backscatter abuse risk)

#### Definition

Sends a probe email to a nonexistent recipient (`nxuser-<random>@domain`) via the configured SMTP relay. Analyzes whether the server rejects before accepting (safe) or accepts-then-bounces (backscatter risk). Requires SMTP relay configuration in .env.

#### Ideal Value

- Server rejects nonexistent recipients during SMTP transaction (RCPT TO returns 5xx)
- No accept-then-bounce behavior

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `recipient_validated` | RCPT TO rejected (5xx) - recipient validated before accept |
| 10/10 | `sender_rejected` | MAIL FROM rejected - strict sender validation |
| 7/10 | `recipient_temp_reject` | RCPT TO temporarily rejected (4xx) |
| 7/10 | `relay_not_configured` | SMTP relay not configured - can't test |
| 7/10 | `delivery_error` | Connection error during test |
| 7/10 | `data_rejected` | DATA command rejected after accept |
| 7/10 | `inconclusive` | Test ran but results unclear |
| 3/10 | `accepts_invalid_recipients` | Server accepts mail for nonexistent recipients (backscatter risk) |

#### Impact if Absent/Vulnerable

A server that accepts mail for nonexistent recipients then generates a Non-Delivery Report (NDR) creates a backscatter vector. An attacker sends email "from" victim@example.com to nonexistent@target.com. Target's server accepts it, discovers the recipient doesn't exist, and sends an NDR to victim@example.com. The NDR comes from target.com's trusted mail server - bypassing the victim's spam filters.

#### Exploitation Example

```
1. target.com accepts mail for nonexistent recipients
2. Attacker sends: MAIL FROM:<victim@example.com> RCPT TO:<nxuser@target.com>
3. target.com accepts the message
4. target.com discovers nxuser doesn't exist
5. target.com generates NDR to victim@example.com
6. victim receives: "Your message to nxuser@target.com could not be delivered"
7. The NDR comes from target.com's MTA - a trusted server
8. If NDR includes original body: attacker's phishing content delivered by trusted MTA
```

---

### SMTP-ENUM - RCPT TO User Enumeration (intrusive)

**Weight: 1.5** (user enumeration - maps valid email addresses)

#### Definition

Tests 30 common email addresses (postmaster, admin, abuse, info, ceo, cfo, cto, ciso, hr, finance, etc.) via RCPT TO responses on the primary MX. Detects catch-all configuration, response blocking, and differential responses that enable user enumeration.

#### Ideal Value

- RCPT TO blocked or uniform responses for all addresses
- Catch-all disabled
- No differential responses between valid and invalid users

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `mail_from_rejected` | MAIL FROM rejected - server doesn't accept enumeration |
| 10/10 | `rcpt_blocked` | Enumeration blocked (503/530 or disconnect) |
| 10/10 | `all_rejected` | All tested addresses rejected uniformly |
| 7/10 | `no_responses` | No clear responses received |
| 7/10 | `partial_enum` | Some valid, some invalid, but insufficient for certain enumeration |
| 7/10 | `inconclusive` | Test ran but results unclear |
| 7/10 | `connection_error` | SMTP connection failed |
| 7/10 | `no_mx` | No MX records to test |
| 3/10 | `catch_all` | All addresses accepted (catch-all) - masks valid users but accepts all |
| 0/10 | `user_enumeration` | Clear differential: valid users accepted, invalid rejected |

#### Impact if Absent/Vulnerable

User enumeration reveals which email addresses are valid within the organization. An attacker who knows that ceo@target.com, cfo@target.com, and ciso@target.com exist can craft targeted spear-phishing (BEC). Catch-all configuration accepts all mail - enabling backscatter and masking enumeration, but accepting spam/phishing for every possible address.

#### Exploitation Example

```
1. RCPT TO: postmaster@target.com -> 250 OK
2. RCPT TO: admin@target.com -> 250 OK
3. RCPT TO: nonexistent@target.com -> 550 User unknown
4. Differential response = user enumeration confirmed
5. Attacker enumerates: ceo, cfo, cto, ciso, hr, finance -> all valid
6. Targeted BEC attack against C-suite with known-valid addresses
7. Password spraying against validated accounts
```

---

### SMTP-STRIP - SMTP TLS Enforcement (intrusive)

**Weight: 1.5** (TLS downgrade risk on SMTP transport)

#### Definition

Tests MX hosts for: (1) plaintext SMTP delivery acceptance (no STARTTLS requirement), (2) deprecated TLS version support (TLS 1.0, TLS 1.1), and (3) STARTTLS certificate hostname mismatch. Tests up to 3 MX hosts.

#### Ideal Value

- TLS required (530 response without STARTTLS)
- No deprecated TLS versions
- Certificate hostname matches MX hostname

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `tls_enforced` | TLS required on all MX - plaintext rejected |
| 7/10 | `opportunistic_tls` | STARTTLS offered but not required |
| 7/10 | `no_mx` | No MX records to test |
| 3/10 | `deprecated_tls_or_cert_mismatch` | TLS 1.0/1.1 supported or certificate hostname mismatch |
| 0/10 | `plaintext_accepted` | Mail accepted without TLS - full plaintext delivery |

#### Impact if Absent/Vulnerable

If an MX server accepts plaintext delivery, a MITM attacker can strip STARTTLS from the EHLO response, forcing all email to transmit in cleartext. Deprecated TLS versions have known vulnerabilities. A certificate hostname mismatch means TLS-validating senders may refuse to deliver or fall back to plaintext.

#### Exploitation Example

```
1. MX accepts plaintext: MAIL FROM succeeds without STARTTLS
2. MITM between sender and target's MX:
   - Strip STARTTLS from EHLO response
   - Sender falls back to plaintext
   - Read all email content in transit
3. Or: TLS 1.0 supported:
   - Force downgrade to TLS 1.0
   - Exploit POODLE/BEAST to decrypt
4. Or: cert mismatch:
   - Strict senders refuse to deliver (email loss)
   - Opportunistic senders accept rogue cert -> MITM
```

---

## External Tool Integration

---

### NUCLEI - Vulnerability Scanner (intrusive)

**Weight: 2.0** (automated vulnerability scanning - finds known CVEs)

#### Definition

Runs ProjectDiscovery nuclei against the domain's HTTP/HTTPS endpoints. Auto-detected via `shutil.which("nuclei")` - scored as "tool not installed" (7/10) when nuclei is not in PATH. Parses JSONL output and classifies findings by severity (critical, high, medium, low). Timeout: 300s.

#### Ideal Value

- No critical or high severity findings
- Tool installed and returning results

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `no_significant_findings` | No critical/high/medium findings |
| 7/10 | `tool_not_installed` | nuclei not found in PATH |
| 7/10 | `medium_vulnerabilities` | Medium severity findings only |
| 7/10 | `scan_timeout` | Scan timed out after 300s |
| 3/10 | `high_vulnerabilities` | High severity findings detected |
| 0/10 | `critical_vulnerabilities` | Critical severity findings detected |

#### Impact if Absent/Vulnerable

Nuclei tests for thousands of known vulnerabilities: exposed admin panels, default credentials, CVE exploits, misconfigurations, and information disclosures. A critical finding typically means direct exploitation is possible (RCE, auth bypass). Not having nuclei installed means these checks are skipped entirely.

#### Exploitation Example

```
1. nuclei finds: CVE-2023-XXXXX (critical) on target.com
2. Exposed admin panel at /admin with default credentials
3. Exposed .env file leaking database credentials
4. Each nuclei finding is a known, documented vulnerability
5. Many have public exploit code available
6. Critical = likely exploitable with minimal effort
```

---

### KATANA - Web Surface Crawler (intrusive)

**Weight: 0.5** (web surface mapping - passive intelligence)

#### Definition

Runs ProjectDiscovery katana to crawl the domain's web surface (depth 3, concurrency 10). Auto-detected via `shutil.which("katana")` - scored as "tool not installed" (7/10) when katana is not in PATH. Identifies sensitive paths, forms, and JavaScript files against 26 known patterns. Timeout: 180s.

#### Ideal Value

- No sensitive paths exposed (/admin, /.env, /.git, /debug, /actuator, etc.)
- Tool installed and returning results

#### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `minimal_surface` | No URLs discovered (very minimal web presence) |
| 7/10 | `tool_not_installed` | katana not found in PATH |
| 7/10 | `surface_mapped` | URLs discovered but no sensitive paths |
| 7/10 | `crawl_timeout` | Crawl timed out after 180s |
| 3/10 | `sensitive_paths_found` | 1-4 sensitive paths detected |
| 0/10 | `many_sensitive_paths` | 5+ sensitive paths detected |

#### Impact if Absent/Vulnerable

Katana discovers the web attack surface: hidden endpoints, admin panels, debug interfaces, configuration files, API documentation, and JavaScript files that may contain secrets. Sensitive paths like /.env, /.git, /actuator, or /debug expose application internals, credentials, or debugging interfaces.

#### Exploitation Example

```
1. katana discovers: /admin, /.env, /api/swagger, /debug/console
2. /.env: contains DB_PASSWORD, AWS_SECRET_KEY -> full compromise
3. /.git: git repository exposed -> source code leak
4. /debug/console: interactive Python/Ruby console -> RCE
5. /api/swagger: full API documentation -> attack surface mapped
6. Each sensitive path is an independent finding to investigate
```

---

## Weight Rationale (Exploitation Perspective)

Weights are ordered by **attacker impact** - how much damage an attacker can do by exploiting the absence of each control:

| Tier | Weight | Checks | Attacker Capability |
|---|---|---|---|
| **Critical** | 3.0-4.0 | Ghost (4.0), DMARC (3.5), Dangling (3.0), SPF (3.0) | Full email auth bypass, subdomain takeover, unrestricted spoofing |
| **High** | 2.0-2.5 | DKIM (2.5), AXFR (2.0), TLS (2.0), SMTP-SEC (2.0), SMTP-RECON (2.0), Bounce (2.0), Nuclei (2.0) | Forge signed emails, dump full zone, MITM, open relay, AD recon, backscatter, known CVEs |
| **Significant** | 1.0-1.5 | DNSSEC (1.5), CAA (1.5), MTA-STS (1.5), SEG (1.5), Subdomains (1.5), SMTP-ENUM (1.5), SMTP-STRIP (1.5), NSEC-Walk (1.5), DMARC-EXT (1.0), M365 (1.0), CT (1.0), HSTS (1.0), Headers (1.0), DNSBL (1.0), Open Ports (1.0), DNS-Rebind (1.0), MX (1.0), NS (1.0), Autodiscover (1.0), Sub-Brute (1.0) | DNS hijacking, TLS downgrade, user enumeration, zone walking, SSRF, port exposure, sensitive subdomain discovery |
| **Low** | 0.5 | SOA, Wildcard, TLS-RPT, Redirect, Cookie, SPF-Depth, SPF-Recon, RPKI, Zone Consistency, TLSA, PTR, WHOIS, Katana | Operational issues, session theft, transport interception, BGP risk, recon intelligence |
| **Minimal** | 0.25 | CNAME, BIMI, Security.txt, SRV, IPv6 | DNS hygiene, brand trust, disclosure channel, auto-discovery, network readiness |
