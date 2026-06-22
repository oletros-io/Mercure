# CHECKS.md - Security Checks Reference

Each check audits a specific aspect of domain security. Scores reflect exploitability: **10/10 = maximum security, 0/10 = no security**.

---

## GHOST — Ghost Sender (Exchange Online Direct Endpoint Spoofing)

**Weight: 4.0** (highest — bypasses all email authentication)

### Definition

Detects whether an Exchange Online tenant is vulnerable to the Ghost Sender attack. When a domain's MX routes through a third-party Secure Email Gateway (Proofpoint, Mimecast, Barracuda, etc.) but no **partner connector** is configured in Exchange Online, an attacker can deliver spoofed emails directly to the EXO endpoint (`<dashed-domain>.mail.protection.outlook.com:25`), bypassing SPF, DKIM, and DMARC entirely.

### Ideal Value

- MX not on Exchange Online → **10/10** (not applicable)
- MX direct to EXO (no SEG) → **10/10** (no bypass path)
- SEG + partner connector configured (5.7.51 response) → **10/10**

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `not_exchange_online` | Domain doesn't use EXO — Ghost Sender not applicable |
| 10/10 | `mx_direct_to_exo` | MX points directly to EXO, no third-party SEG to bypass |
| 10/10 | `partner_connector_configured` | Partner connector blocks unauthorized direct delivery (5.7.51) |
| 7/10 | `exo_unreachable` | EXO endpoint exists but SMTP probe couldn't connect |
| 7/10 | `smtp_rejected` | EXO endpoint rejected the SMTP handshake (500-level) |
| 7/10 | `smtp_temp_reject` | EXO endpoint temporarily rejected (400-level) |
| 3/10 | `exo_exposed_inconclusive` | EXO endpoint responded but behavior unclear |
| 0/10 | `ghost_sender_vulnerable` | EXO endpoint accepts spoofed mail — full bypass confirmed |

### Impact if Absent/Vulnerable

An attacker sends emails as `ceo@target.com` directly to the EXO endpoint on port 25. The email arrives in the recipient's inbox with no SPF/DKIM/DMARC failure because Exchange Online trusts direct-to-endpoint delivery when no partner connector restricts it. The SEG never sees the email. DMARC aggregate reports won't flag it because EXO doesn't evaluate SPF/DKIM on this path.

### Exploitation Example

```
1. Discover MX routes through Proofpoint: dig MX target.com → pphosted.com
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
5. Email lands in inbox — SPF/DKIM/DMARC never evaluated
```

---

## DMARC — Domain-based Message Authentication, Reporting & Conformance

**Weight: 3.5** (enforcement policy — decides what happens to spoofed emails)

### Definition

Checks the `_dmarc.<domain>` TXT record for the DMARC policy. DMARC tells receiving mail servers what to do when SPF and DKIM checks fail: reject the email, quarantine it, or do nothing. It also enables reporting so domain owners can monitor authentication failures.

### Ideal Value

`v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@domain.com; ruf=mailto:forensic@domain.com`

- `p=reject` with `pct=100` — all failing emails are rejected
- `sp=reject` — subdomains inherit the same strict policy
- `rua` + `ruf` — aggregate and forensic reports enabled

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `reject_full` | `p=reject` at `pct=100` — maximum enforcement |
| 7/10 | `reject_partial_pct` | `p=reject` but `pct < 100` — some spoofed emails slip through |
| 7/10 | `quarantine` | `p=quarantine` at `pct=100` — spoofed emails go to spam, not rejected |
| 3/10 | `quarantine_partial_pct` | `p=quarantine` with `pct < 100` — partial spam quarantine |
| 3/10 | `none_policy` | `p=none` — monitoring only, no enforcement |
| 3/10 | `unknown_policy` | Unrecognized policy value |
| 0/10 | `no_dmarc` | No DMARC record at all |

### Impact if Absent/Vulnerable

Without DMARC (or with `p=none`), receiving servers have no policy instruction. Even if SPF and DKIM fail, the server may deliver the email. An attacker can spoof the domain freely — the domain owner won't even know it's happening unless they check third-party reports.

### Exploitation Example

```
1. Verify no DMARC: dig TXT _dmarc.target.com → (empty)
2. Or DMARC p=none: dig TXT _dmarc.target.com → "v=DMARC1; p=none"
3. Send spoofed email from any SMTP server:
   MAIL FROM:<hr@target.com>
   RCPT TO:<employee@target.com>
   DATA
   From: HR <hr@target.com>
   Subject: Password reset required
   ...
4. SPF fails, DKIM fails, but DMARC says "do nothing" → email delivered
5. With p=none, domain owner gets reports but victims get phished
```

---

## SPF — Sender Policy Framework

**Weight: 3.0** (sender IP authorization — first line of defense)

### Definition

Checks the domain's TXT record for an SPF policy (`v=spf1`). SPF defines which IP addresses and servers are authorized to send email on behalf of the domain. The `all` mechanism at the end determines what happens to unauthorized senders.

### Ideal Value

`v=spf1 include:_spf.provider.com -all`

- `-all` (hard fail) — unauthorized IPs are explicitly rejected
- Includes only necessary sending sources

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `hard_fail` | `-all` — unauthorized senders rejected |
| 7/10 | `soft_fail` | `~all` — unauthorized senders marked but not rejected |
| 7/10 | `redirect_no_all` | `redirect=` present without explicit `all` mechanism |
| 3/10 | `neutral_all` | `?all` — no opinion on unauthorized senders |
| 3/10 | `unknown_policy` | SPF record exists but mechanism unclear |
| 0/10 | `allow_all_plus` | `+all` — explicitly allows any IP to send as this domain |
| 0/10 | `no_spf` | No SPF record |

### Impact if Absent/Vulnerable

Without SPF (or with `+all`/`~all`), any server on the internet can send email claiming to be from the domain. With soft fail (`~all`), most receiving servers will still deliver the email (possibly to spam) rather than rejecting it outright. Only hard fail (`-all`) provides real protection.

### Exploitation Example

```
1. Check SPF: dig TXT target.com → "v=spf1 include:_spf.google.com ~all"
2. Soft fail (~all): spoofed emails may land in spam but aren't rejected
3. From any VPS/SMTP relay:
   MAIL FROM:<admin@target.com>
   RCPT TO:<victim@company.com>
   DATA
   From: Admin <admin@target.com>
   Subject: System maintenance — verify your credentials
   ...
4. SPF check: SOFTFAIL (sender IP not in SPF, but ~all = accept anyway)
5. Email delivered to spam folder — many users check spam regularly
6. With -all: email would be rejected outright by compliant receivers
```

---

## DKIM — DomainKeys Identified Mail

**Weight: 2.5** (cryptographic email verification — supports DMARC alignment)

### Definition

Discovers DKIM selectors via bruteforce and analyzes the corresponding public keys. DKIM allows a sending server to cryptographically sign outgoing emails. The receiving server verifies the signature using the public key published in DNS at `<selector>._domainkey.<domain>`.

### Ideal Value

- At least one DKIM selector with RSA >= 2048 bits (or Ed25519)
- No `l=` tag (body length limit — allows content injection)
- No `t=y` (test mode — receivers may ignore failures)
- Non-guessable selector names

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `strong_dkim` | Strong keys, no risky tags, non-guessable selectors |
| 7/10 | `test_mode` | Key found but `t=y` (test mode) — failures may be ignored |
| 7/10 | `all_selectors_guessable` | All selectors are common/guessable names |
| 3/10 | `weak_key` | RSA key < 2048 bits — can be factored |
| 3/10 | `dangerous_l_tag` | `l=` tag present — attacker can append content to signed email |
| 0/10 | `no_dkim` | No DKIM selectors found |

### Impact if Absent/Vulnerable

Without DKIM, emails can't be cryptographically verified. This matters because DMARC alignment requires either SPF or DKIM to pass — if DKIM is absent and SPF fails (e.g., forwarded emails), DMARC fails too. Weak keys (< 2048 bits RSA) can be factored offline, allowing an attacker to forge DKIM signatures. The `l=` tag is particularly dangerous: it lets an attacker take a legitimately signed email and append arbitrary content (phishing links, malware) without breaking the signature.

### Exploitation Example

```
1. Discover selector: dig TXT default._domainkey.target.com
2. Find weak key: RSA 1024-bit
3. Factor the key offline (feasible with cloud computing, ~$50-100):
   - Extract modulus from the DKIM public key
   - Use CADO-NFS or similar to factor
   - Reconstruct private key
4. Sign forged emails with the factored private key:
   DKIM-Signature: v=1; a=rsa-sha256; d=target.com; s=default; ...
5. Email passes DKIM verification → DMARC alignment passes
6. Forged email appears fully authenticated

For l= tag exploitation:
1. Intercept a legitimate signed email from target.com
2. Append phishing content after the signed body length
3. Forward to victim — DKIM signature still valid
```

---

## DNSSEC — DNS Security Extensions

**Weight: 1.5** (DNS integrity — prevents cache poisoning but hard to exploit in practice)

### Definition

Checks for DS (Delegation Signer) and DNSKEY records that form the DNSSEC chain of trust. DNSSEC cryptographically signs DNS responses, allowing resolvers to verify that responses haven't been tampered with between the authoritative server and the client.

### Ideal Value

- DS record present at the parent zone (registrar)
- DNSKEY record present at the authoritative server
- Both form a valid chain of trust

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `dnssec_valid` | DS + DNSKEY both present — chain of trust established |
| 7/10 | `dnskey_no_ds` | DNSKEY published but no DS at parent — chain incomplete |
| 3/10 | `ds_no_dnskey` | DS at parent but no DNSKEY — broken chain |
| 0/10 | `no_dnssec` | Neither DS nor DNSKEY — no DNSSEC |

### Impact if Absent/Vulnerable

Without DNSSEC, DNS responses can be spoofed via cache poisoning (Kaminsky attack). An attacker on the network path or racing the resolver can inject forged DNS responses, redirecting users to malicious servers. This can be used to hijack email (forge MX responses), intercept web traffic (forge A/AAAA responses), or bypass certificate validation (forge CAA responses). In practice, exploitation requires specific network conditions (on-path or timing the race), making it less immediately exploitable than email auth gaps.

### Exploitation Example

```
1. Target has no DNSSEC: dig DS target.com → (empty)
2. Perform DNS cache poisoning (Kaminsky-style):
   - Flood the recursive resolver with forged responses
   - Race the legitimate authoritative response
   - Inject: target.com MX → attacker-mx.evil.com
3. All email for target.com now routes to attacker's server
4. Or inject forged A record: target.com → attacker IP
5. Serve phishing site with Let's Encrypt cert (CAA also absent)
6. Users see valid HTTPS — no browser warnings
```

---

## CAA — Certificate Authority Authorization

**Weight: 1.5** (controls which CAs can issue certificates)

### Definition

Checks for CAA DNS records that specify which Certificate Authorities are authorized to issue TLS certificates for the domain. CAs are required to check CAA records before issuing a certificate (since 2017, per CA/Browser Forum Ballot 187).

### Ideal Value

```
target.com. CAA 0 issue "letsencrypt.org"
target.com. CAA 0 issuewild ";"
target.com. CAA 0 iodef "mailto:security@target.com"
```

- `issue` restricted to specific CAs
- `issuewild ";"` blocks wildcard certificates
- `iodef` for violation reporting

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `caa_restricted` | `issue` tag present with specific CA restrictions |
| 7/10 | `caa_permissive_issue` | `issue` tag present but permissive values |
| 3/10 | `caa_no_issue_tag` | CAA records exist but no `issue` tag |
| 0/10 | `no_caa` | No CAA records — any CA can issue certificates |

### Impact if Absent/Vulnerable

Without CAA, any of the ~100+ trusted Certificate Authorities can issue a valid TLS certificate for the domain. If an attacker compromises a less-secure CA (or exploits a validation bypass in any CA), they can obtain a certificate that browsers and clients will trust. With CAA restricted to a single CA, the attacker must compromise that specific CA.

### Exploitation Example

```
1. Check CAA: dig CAA target.com → (empty)
2. Any CA can issue a cert. Attacker options:
   a. Find a CA with weak domain validation (e.g., email-based DV
      where attacker controls admin@ or webmaster@)
   b. Exploit BGP hijacking + any CA's HTTP-based DV
   c. Use a compromised/rogue CA
3. Obtain valid cert for target.com
4. Perform MITM attack on target.com HTTPS traffic
5. Intercept credentials, session tokens, API keys
6. With CAA: only the specified CA can issue — attack surface reduced by 99%
```

---

## MX — Mail Exchanger

**Weight: 1.0** (email infrastructure availability)

### Definition

Checks MX records for the domain. MX records define which servers accept email for the domain and in what priority order. Validates that MX records exist, are not null (`.`), are not IP literals, and that redundancy exists.

### Ideal Value

- Multiple MX records with different priorities
- Hostnames (not IP addresses)
- No null MX (`.`)

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `mx_ok` | Multiple MX records — redundancy in place |
| 7/10 | `single_mx` | Only one MX record — no redundancy |
| 3/10 | `null_mx` | Null MX (`.`) — domain explicitly rejects email |
| 3/10 | `ip_literal_mx` | MX points to an IP address (RFC violation) |
| 0/10 | `no_mx` | No MX record at all |

### Impact if Absent/Vulnerable

A missing MX means no email delivery. A single MX provides no redundancy — if the server goes down, all inbound email is lost or queued until the sender gives up (typically 5 days). Null MX (`.`) explicitly declares the domain doesn't accept email, which can be intentional. IP-literal MX violates RFC 5321 and indicates misconfiguration that some servers will refuse.

### Exploitation Example

```
1. Single MX: dig MX target.com → 10 mail.target.com
2. DDoS mail.target.com — all inbound email fails
3. Senders queue email for up to 5 days, then bounce
4. Attacker sets up a lookalike domain with valid MX
5. Sends "our email is down, use this address instead" phish
6. Or: during the outage, targets can't receive MFA codes, password
   reset links, or security alerts — enabling other attacks
```

---

## NS — Nameservers

**Weight: 1.0** (DNS infrastructure resilience)

### Definition

Checks nameserver count and provider diversity. DNS is the foundation of all domain services — if nameservers go down, everything (web, email, APIs) becomes unreachable. Provider diversity protects against single-provider outages.

### Ideal Value

- 2+ nameservers
- Spread across different providers/ASNs

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `ns_ok` | Multiple NS across different providers |
| 7/10 | `same_provider_ns` | Multiple NS but all with the same provider |
| 3/10 | `single_ns` | Only one nameserver — single point of failure |
| 0/10 | `no_ns` | No NS records (shouldn't happen in practice) |

### Impact if Absent/Vulnerable

A single nameserver or all nameservers on the same provider is a single point of failure. A DDoS attack on that provider, or a provider outage, takes the entire domain offline: no website, no email, no API. The 2016 Dyn DNS attack demonstrated this — major sites went offline because their NS records all pointed to Dyn.

### Exploitation Example

```
1. Single NS: dig NS target.com → ns1.smallprovider.com
2. DDoS smallprovider.com — target.com disappears from DNS
3. All services (web, email, API) become unreachable
4. Combined with DNS cache poisoning:
   - While legitimate NS is down, attacker answers DNS queries
   - Inject forged records (A, MX, etc.)
   - Redirect traffic to attacker infrastructure
5. Same-provider NS: if Cloudflare goes down (has happened),
   both NS are unreachable simultaneously
```

---

## TLSA — DANE/SMTP Authentication

**Weight: 0.5** (transport security — low adoption makes exploitation unlikely)

### Definition

Checks for TLSA records at `_25._tcp.<domain>`. TLSA records are part of DANE (DNS-based Authentication of Named Entities), which binds a TLS certificate to a domain via DNS. For SMTP, DANE prevents STARTTLS stripping attacks and rogue certificate attacks on mail transport.

### Ideal Value

- TLSA record at `_25._tcp.<domain>` matching the MX server's certificate
- Requires DNSSEC (TLSA without DNSSEC is meaningless)

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `tlsa_present` | TLSA record exists for SMTP |
| 0/10 | `no_tlsa` | No TLSA record |

### Impact if Absent/Vulnerable

Without DANE/TLSA, SMTP connections are vulnerable to STARTTLS stripping: an attacker in a MITM position can remove the STARTTLS offer from the server's EHLO response, forcing the connection to transmit in plaintext. They can also present a rogue certificate. With TLSA, the sending server knows exactly which certificate to expect and will refuse to downgrade. In practice, DANE adoption for SMTP is very low (~2% of domains), so absence is the norm.

### Exploitation Example

```
1. No TLSA: dig TLSA _25._tcp.target.com → (empty)
2. MITM position between sender and target's MX:
   - Intercept SMTP connection
   - Strip STARTTLS from server's EHLO response
   - Sending server falls back to plaintext
3. Read all email content in transit (credentials, documents, etc.)
4. Or: present a rogue certificate for the MX hostname
   - Without TLSA, sending server has no way to verify the cert
   - Accept rogue cert → attacker decrypts TLS traffic
5. With TLSA: sender verifies cert hash against DNS record → rejects rogue cert
```

---

## PTR — Reverse DNS

**Weight: 0.5** (email deliverability indicator, not directly exploitable)

### Definition

Resolves the domain's A records, performs reverse DNS lookups on each IP, and checks whether the PTR record matches the domain. Matching reverse DNS is a trust signal for mail servers — it proves the IP operator intentionally associated the IP with the domain.

### Ideal Value

- Every A record has a PTR
- PTR contains the domain name (forward-confirmed reverse DNS)

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `ptr_match` | PTR records match the domain |
| 7/10 | `ptr_no_match` | PTR exists but doesn't match the domain |
| 3/10 | `partial_ptr` | Some IPs have PTR, some don't |
| 0/10 | `no_ptr` | No reverse DNS for any IP |
| 0/10 | `no_a_record` | Domain has no A record to check |

### Impact if Absent/Vulnerable

Missing or mismatched PTR primarily affects email deliverability — many mail servers (Gmail, Outlook, corporate) will reject or spam-flag emails from IPs without valid reverse DNS. From an exploitation perspective, lack of PTR makes it harder to trace the domain's infrastructure and doesn't directly enable attacks. However, it can indicate a rented/temporary host (VPS, cloud instance) that may have weaker security controls.

### Exploitation Example

```
No direct exploitation vector. PTR impacts:
1. Outbound email from the domain's IPs gets rejected by receivers
   that require matching rDNS → business impact
2. Reconnaissance: mismatched PTR reveals the hosting provider
   and infrastructure details (cloud provider, CDN, shared hosting)
3. Missing PTR on an IP sending as target.com suggests the domain
   owner doesn't control that IP's rDNS → possible unauthorized sender
```

---

## SRV — Mail Service Records

**Weight: 0.25** (auto-discovery convenience — negligible exploitation value)

### Definition

Checks for mail-related SRV records: `_submission._tcp` (SMTP submission), `_imaps._tcp` (IMAP over TLS), `_pop3s._tcp` (POP3 over TLS). SRV records enable email clients to auto-discover server endpoints without manual configuration.

### Ideal Value

- `_submission._tcp.<domain>` → SMTP submission server
- `_imaps._tcp.<domain>` → IMAP server
- `_pop3s._tcp.<domain>` → POP3 server (if applicable)

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `mail_srv_ok` | All 3 mail SRV records present |
| 7/10 | `partial_mail_srv` | Some SRV records present |
| 0/10 | `no_mail_srv` | No mail SRV records |

### Impact if Absent/Vulnerable

Without SRV, email clients can't auto-discover server settings. Users must manually configure IMAP/SMTP servers, which increases the risk of connecting to rogue servers during initial setup (typosquatting, phishing "setup guides"). This is a very low risk — most modern email providers use Autodiscover (Microsoft) or autoconfig (Mozilla) instead of SRV.

### Exploitation Example

```
No direct exploitation. Indirect risk:
1. User setting up email client for target.com
2. No SRV → client can't auto-discover settings
3. User searches "target.com email settings"
4. Attacker's SEO-optimized page shows up with rogue server settings
5. User configures client to connect to attacker's IMAP/SMTP
6. Attacker captures credentials on login attempt
```

---

## IPv6 — AAAA Records

**Weight: 0.25** (network readiness — no direct security impact)

### Definition

Checks whether the domain has AAAA (IPv6) records. IPv6 support indicates modern network infrastructure and ensures the domain is reachable from IPv6-only networks.

### Ideal Value

- At least one AAAA record pointing to a valid IPv6 address

### Score Mapping

| Score | Reason | Meaning |
|---|---|---|
| 10/10 | `ipv6_present` | AAAA record exists |
| 0/10 | `no_ipv6` | No AAAA record |

### Impact if Absent/Vulnerable

No direct security impact. Missing IPv6 means the domain is unreachable from IPv6-only networks (rare but growing). Some ISPs and mobile carriers use IPv6 by default — users on these networks rely on NAT64/DNS64 translation to reach IPv4-only domains, which adds latency and potential failure points.

### Exploitation Example

```
No exploitation vector. IPv6 absence is a readiness indicator:
1. IPv6-only clients can't reach the domain natively
2. Must rely on carrier-grade NAT/translation → performance impact
3. Does not affect email security, authentication, or spoofing
```

---

## Weight Rationale (Exploitation Perspective)

Weights are ordered by **attacker impact** — how much damage an attacker can do by exploiting the absence of each control:

| Tier | Weight | Checks | Attacker Capability |
|---|---|---|---|
| **Critical** | 4.0 | Ghost | Full email auth bypass — instant spoofing with zero defenses |
| **High** | 3.0-3.5 | DMARC, SPF | Direct email spoofing — no enforcement or no sender verification |
| **Significant** | 2.5 | DKIM | Forge signed emails (weak keys) or bypass DMARC alignment |
| **Moderate** | 1.5 | DNSSEC, CAA | DNS hijacking, unauthorized certificates — requires specific conditions |
| **Low** | 1.0 | MX, NS | Availability attacks, infrastructure mapping — indirect exploitation |
| **Minimal** | 0.25-0.5 | TLSA, PTR, SRV, IPv6 | Transport interception (TLSA), reconnaissance, no direct exploitation |
