# DETECT.md - Detection Analysis

How a SOC/WAF/EDR would detect Mercure's traffic, how the tool behaves, and what residual signals remain.

## 1. Baseline - Traffic Fingerprint

Without any evasion, Mercure generates a recognizable multi-protocol pattern across DNS, SMTP, HTTP, and TCP:

### DNS (Passive Mode - 31 checks)

| Behavior | Detection Signal | Severity |
|---|---|---|
| Burst of TXT queries (`_dmarc.`, `v=spf1`, `selector._domainkey.`, `_mta-sts.`, `_tls-rpt.`, `_bimi.`, `_dmarc-ext.`) | Unusual volume of TXT queries from a single source in a short window | Medium |
| Sequential checks across 17+ record types (A, AAAA, MX, NS, CAA, DS, DNSKEY, TLSA, SRV, TXT, PTR, SOA, CNAME, NSEC, NAPTR) + service-specific queries | Full DNS reconnaissance fingerprint - very few legitimate clients query all types | High |
| DKIM selector bruteforce (100-5300+ TXT queries to `*._domainkey.domain`) | Massive volume of NXDOMAIN responses for non-existent selectors | High |
| Aggressive mode year/month patterns (`dkim-2024-q1._domainkey.`, etc.) | Sequential enumeration pattern in subdomain queries | High |
| DNSBL lookups (reversed IP queries to zen.spamhaus.org, bl.spamcop.net, b.barracudacentral.org, dnsbl.sorbs.net) | Reverse-IP DNS queries to known blacklist zones | Low |
| SPF recursive include tree walking (multiple TXT lookups following `include:` and `redirect=` chains) | Cascade of TXT queries to third-party domains tracking SPF include tree | Low |
| Wildcard detection (random hex subdomain query) | Single A query to random nonsense subdomain, then no follow-up | Low |
| Zone consistency checks (same query to multiple NS) | Identical queries sent to every authoritative NS | Low |
| CNAME chain resolution on apex | CNAME query on zone apex (unusual for most clients) | Low |
| Concurrent DNS queries via ThreadPoolExecutor | Parallel resolution from same source IP | Low |

### SMTP (Ghost/Spoof - Active)

| Behavior | Detection Signal | Severity |
|---|---|---|
| SMTP connection to `*.mail.protection.outlook.com:25` (Ghost Sender check) | Direct SMTP probe to EXO endpoint from non-mail IP. EHLO mimics `mail.<domain>` but source IP doesn't match SPF | Medium |
| SMTP connections to recipient MX on port 25 (Spoof mode, direct) | Direct SMTP delivery of spoofed emails - full email content in mail server logs | Critical |
| SMTP connections via authenticated relay (Spoof mode, relay) | Relay logs authenticated user. SPF passes for relay domain but DMARC alignment fails | High |
| Multiple SMTP sessions to same MX within seconds (Spoof mode, 12 methods) | Repeated connections with different senders/envelopes is a spoofing test pattern | High |
| Multi-recipient RCPT TO to dead addresses in single session (bs_amp) | 5 RCPT TO to nonexistent addresses in one SMTP session - classic amplification probe | High |
| Emails to functional mailboxes from spoofed return-path (bs_oob) | Messages to info@/contact@/support@ with return-path set to external victim | Medium |

### SMTP (Intrusive Checks)

| Behavior | Detection Signal | Severity |
|---|---|---|
| SMTP EHLO + AUTH enumeration + NTLM Type 1 handshake on each MX | NTLM authentication initiation from non-Outlook client, followed by cancellation (`*`) | Critical |
| Sequential RCPT TO to 30 common addresses (postmaster, admin, ceo, ciso, hr, finance...) | Dictionary-style user enumeration via RCPT TO - classic SMTP attack pattern | Critical |
| Plaintext SMTP MAIL FROM without STARTTLS (TLS strip test) | Deliberate refusal to upgrade to TLS, testing plaintext acceptance | High |
| Deprecated TLS version negotiation (TLS 1.0, TLS 1.1) | STARTTLS with explicitly pinned deprecated protocol version | Medium |
| SMTP HELP command probe | HELP command after EHLO - uncommon in legitimate mail flow | Low |
| SMTP certificate analysis (STARTTLS + getpeercert) | TLS handshake with cert inspection but no mail delivery | Low |

### HTTP/TLS (External Checks)

| Behavior | Detection Signal | Severity |
|---|---|---|
| HTTPS connection to port 443 with TLS analysis (cipher, version, cert chain) | Single HTTPS GET from non-browser user-agent with TLS metadata inspection | Low |
| HTTP to HTTPS redirect test (GET http://domain) | Plaintext HTTP request to check redirect behavior | Low |
| Security header probing (GET / and inspect response headers) | Single GET request analyzing CSP, HSTS, X-Frame-Options, etc. | Low |
| Cookie security analysis (parse Set-Cookie flags) | Single request checking Secure/HttpOnly/SameSite on response cookies | Low |
| security.txt fetch (`/.well-known/security.txt`) | Fetch of RFC 9116 endpoint | Low |
| Autodiscover endpoint probing (4 HTTP URLs + SRV + CNAME) | GET to `autodiscover.domain/autodiscover.xml`, `.well-known/autoconfig/...` etc. | Medium |
| crt.sh API queries | HTTPS request to crt.sh searching domain certificates | Low |
| Shodan InternetDB API | HTTPS query to internetdb.shodan.io for IP enrichment | Low |
| RDAP/WHOIS lookup | HTTPS to RDAP bootstrap then registrar endpoint | Low |

### TCP (Intrusive)

| Behavior | Detection Signal | Severity |
|---|---|---|
| TCP connect scan on 18 ports (21, 22, 23, 25, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443) | Sequential TCP SYN/connect to well-known ports from single source | High |

### DNS (Intrusive)

| Behavior | Detection Signal | Severity |
|---|---|---|
| NSEC chain walking (up to 50 NSEC queries following next-name pointers to NS) | Sequential NSEC record queries walking the zone chain - zone enumeration pattern | High |
| NSEC3 parameter probing (DNSSEC query with DO flag to trigger NSEC3 in authority) | DNS query with EDNS + DO flag for random subdomain to elicit NSEC3 response | Low |
| Subdomain dictionary brute-force (200+ A queries: www, mail, dev, staging, admin, vpn, git, jenkins...) | Burst of A queries for common subdomain prefixes from single source | High |

### External Tool Execution (Intrusive)

| Behavior | Detection Signal | Severity |
|---|---|---|
| subfinder execution (passive subdomain enum via multiple sources) | DNS/API queries to certificate transparency, search engines, DNS aggregators with subfinder's user-agent | Medium |
| nuclei execution (vulnerability scanning with template matching) | HTTP requests with nuclei's user-agent, template-specific payloads, multi-path probing | Critical |
| katana execution (web crawling depth 3, concurrency 10) | Rapid sequential/parallel HTTP crawling with katana's user-agent, link extraction, form discovery | High |

**Baseline detection scores:**
- Passive mode only: **~75%** for DNS-aware monitoring
- With spoof mode: **~95%** (actual email delivery attempts)
- With intrusive mode: **~99%** (SMTP probing, port scanning, zone walking, user enumeration)
- With external tools (nuclei/katana): **~99%** (tool-specific user-agents and scan signatures)

## 2. Feature Inventory

| Feature | Evasion Type | Status | Detection Impact |
|---|---|---|---|
| Standard DNS resolution via system resolver | Passive | Active | Blends with normal DNS traffic |
| Configurable DNS timeout | Timing | Active | Prevents timeout-based fingerprinting |
| Configurable thread count | Rate control | Active | Allows throttling to avoid burst detection |
| No HTTP/TLS traffic in passive mode (except Ghost SMTP) | Protocol absence | Active | No web fingerprinting possible for passive checks |
| Ghost Sender SMTP probe | Active recon | Active | SMTP handshake to EXO port 25 with identifiable EHLO |
| Log-to-disk only | No exfiltration | Active | No outbound data channel to detect |
| `--intrusive` flag gating | Operational control | Active | Intrusive checks disabled by default - reduces detection surface |
| `--skip-external` flag | Operational control | Active | Skips external API calls (crt.sh, Shodan, RDAP) - eliminates third-party traffic |
| SMTP NTLM Type 1/2 exchange | Active recon | Active (intrusive) | NTLM handshake attempt is highly anomalous from non-Outlook clients |
| RCPT TO user enumeration (30 addresses) | Active recon | Active (intrusive) | Sequential RCPT TO pattern is classic attack signature |
| TLS downgrade testing (TLS 1.0/1.1 probing) | Active recon | Active (intrusive) | Deprecated protocol negotiation visible in TLS logs |
| Plaintext SMTP delivery attempt | Active recon | Active (intrusive) | Deliberate TLS avoidance is suspicious |
| NSEC zone walking | Active recon | Active (intrusive) | Sequential NSEC queries to authoritative NS |
| NSEC3 parameter probing | Passive | Active (intrusive) | Single DNSSEC query - low footprint |
| Dictionary subdomain brute-force (200+ prefixes) | Active recon | Active (intrusive) | High-volume A queries to predictable names |
| TCP port scanning (18 ports) | Active recon | Active (intrusive) | Sequential connect scan from single source |
| Nuclei subprocess execution | Active scanning | Active (intrusive) | nuclei's own user-agent, template payloads, scan cadence |
| Katana subprocess execution | Active crawling | Active (intrusive) | katana's own user-agent, aggressive crawl pattern |
| Subfinder integration (merged with crt.sh) | Passive recon | Active | subfinder's own API calls and DNS queries |
| HTTP/TLS probing (HSTS, headers, redirect, cookie, security.txt) | Active recon | Active (external) | Single HTTP(S) requests with non-browser user-agent |
| Autodiscover endpoint probing (4 URLs) | Active recon | Active (external) | Requests to known autodiscover/autoconfig paths |
| Certificate Transparency query (crt.sh) | Passive recon | Active (external) | HTTPS to crt.sh API |
| Shodan InternetDB enrichment | Passive recon | Active (external) | HTTPS to internetdb.shodan.io API |
| RDAP domain lookup | Passive recon | Active (external) | HTTPS to RDAP endpoints |
| Dual scoring (security + exploitability) | Analysis only | Active | No detection surface - post-processing of results |
| Auto-save results to results/YYYYMMDD_XXXXX.txt | Local storage | Active | No detection surface - local JSON file only |

## 3. Deep Dives

### 3.1 DNS Query Pattern

**Defender's view**: A DNS monitoring system (Passive DNS, DNS firewall, or SIEM with DNS logs) will see:

1. A burst of queries to the target domain across multiple record types
2. A high NXDOMAIN ratio from DKIM selector bruteforce
3. Sequential queries to `_domainkey.` subdomains with common selector names
4. Additional TXT queries to `_dmarc.`, `_mta-sts.`, `_tls-rpt.`, `_bimi.` subdomains
5. SOA, AXFR attempt, CNAME, DNSBL queries expanding the fingerprint
6. Recursive SPF include tree walking generating TXT queries to third-party domains

**Mercure's behavior**: Queries are made through the system's configured DNS resolver (typically ISP or corporate resolver). No direct queries to authoritative nameservers (except for zone consistency and NSEC walk checks).

**Residual signal**: The query pattern is distinctive. A defender who logs DNS queries at the recursive resolver level can reconstruct the full check sequence and identify it as a security audit tool. With 49 checks, the query volume and type diversity is significantly higher than earlier versions.

### 3.2 DKIM Selector Bruteforce

**Defender's view**: 100+ (default) or 5300+ (with wordlist) TXT queries to `*._domainkey.target.com` in rapid succession. The NXDOMAIN ratio will be very high (typically 95%+).

**Detection rules**:
```
# Sigma-style rule
title: DKIM Selector Enumeration
detection:
  selection:
    query_type: TXT
    query_name|endswith: '._domainkey.'
  condition: selection | count(query_name) > 50 within 5m from same source
```

**Mercure's behavior**: No randomization of query order. No delays between queries. Thread pool fires as fast as the resolver allows.

**Residual signal**: Even with threading reduced to 1, the sequential pattern of `default._domainkey`, `selector1._domainkey`, `google._domainkey` etc. is recognizable.

### 3.3 Ghost Sender SMTP Probe

**Defender's view**: An SMTP connection to `<dashed-domain>.mail.protection.outlook.com:25` from an external, non-mail-server IP. The SMTP session performs `MAIL FROM` + `RCPT TO` without sending `DATA` - a classic SMTP enumeration pattern.

**Detection rules**:
```
# Sigma-style rule
title: Ghost Sender SMTP Probe
detection:
  selection:
    dst_port: 25
    dst_hostname|endswith: '.mail.protection.outlook.com'
  filter_legitimate:
    src_ip|cidr: <known_seg_ranges>
  condition: selection and not filter_legitimate
```

**Mercure's behavior**: Single SMTP connection per domain. EHLO with `mail.<target-domain>` (mimics legitimate MTA), MAIL FROM with `postmaster@<target-domain>`, RCPT TO with `postmaster@target`. No DATA command, no actual email delivery. Connection closed with RSET+QUIT. No unique tool signature in SMTP handshake.

**Residual signal**: The SMTP session is logged by Exchange Online. Microsoft's internal telemetry captures the source IP, EHLO hostname, and MAIL FROM. The EHLO and MAIL FROM look legitimate but the source IP won't match the domain's SPF-authorized servers. The defender can see the probe in Exchange Online message trace (even failed sessions are logged).

**Key difference from DNS checks**: This is an **active probe** that touches the target's mail infrastructure directly. It leaves a trail in Exchange Online logs, unlike passive DNS queries that only touch the recursive resolver.

### 3.4 Spoof Mode - SMTP Email Delivery

**Defender's view**: Multiple SMTP connections to the recipient's MX on port 25 within seconds. Each connection attempts a full SMTP transaction (EHLO -> MAIL FROM -> RCPT TO -> DATA) with a spoofed sender. The only non-standard header is `X-Oletros-Tool`.

**Detection rules**:
```
# Sigma-style rule
title: Mercure Spoof Test Detection
detection:
  selection_header:
    email_header|contains: 'X-Oletros-Tool'
  selection_subject:
    smtp_subject|startswith: 'Security Test - '
  selection_pattern:
    smtp_mail_from|startswith: 'mercure@'
  condition: selection_header or (selection_subject and selection_pattern)
```

**Mercure's behavior**: 4 sequential SMTP connections per target domain:
1. Direct delivery via recipient MX with spoofed sender
2. Ghost delivery to EXO direct endpoint (if applicable)
3. Null envelope sender with spoofed From header
4. Subdomain sender (`nonexistent.<domain>`)

Each connection uses EHLO `mail.<sender-domain>` (mimics legitimate MTA), attempts STARTTLS if offered. Message-ID format: `<uuid>@<sender-domain>`. Subject includes method: `Security Test - direct`, `Security Test - ghost`, etc.

**Residual signals**:
- `X-Oletros-Tool` header (intentional attribution - only identifiable signature)
- Source IP in SMTP connection logs (not SPF-authorized for the spoofed domain)
- `mercure@` sender local-part pattern
- Subject contains "Security Test - <method>"
- Nine connections to the same MX in rapid succession (or mix of relay + direct)
- Exchange Online message trace records all delivery attempts (even failed)
- Lorem ipsum body content

### 3.5 SMTP Reconnaissance (Intrusive)

**Defender's view**: On each MX host, an SMTP session performs EHLO, inspects extensions, issues AUTH NTLM with a Type 1 negotiate message, cancels with `*` after receiving Type 2 challenge, then issues HELP. This is a textbook SMTP information gathering sequence.

**Detection rules**:
```
# Sigma-style rule
title: SMTP NTLM Probe (Non-Outlook Client)
detection:
  selection:
    smtp_command: 'AUTH NTLM'
    src_ip|not_in: <known_exchange_servers>
  condition: selection

title: SMTP Reconnaissance Sequence
detection:
  selection:
    smtp_commands|ordered: ['EHLO', 'AUTH NTLM', '*', 'HELP', 'QUIT']
  timeframe: 30s
  condition: selection
```

**Mercure's behavior**: Connects to up to 3 MX hosts. Per host: EHLO -> parse extensions and AUTH methods -> if NTLM advertised, send Type 1 negotiate -> parse Type 2 challenge (extracts NetBIOS domain/computer, DNS domain/tree) -> cancel with `*` -> HELP -> QUIT. The NTLM Type 1 message uses flags `0x00088207` (negotiate Unicode, OEM, NTLM, domain info, workstation info).

**Residual signals**:
- NTLM Type 1 negotiate message in SMTP session logs (unique flag pattern)
- AUTH cancellation with `*` immediately after Type 2 response
- HELP command after AUTH sequence (unusual in production mail flow)
- No actual authentication - probe only, no credentials submitted
- All exchanges logged by the MX (Exchange, Postfix, etc.)
- Up to 3 MX hosts probed in sequence within seconds

**Detection note**: NTLM info leak via SMTP is a well-known technique (used by Metasploit's `smtp_ntlm_domain` module, nmap scripts, etc.). Any SMTP AUTH NTLM from a non-Exchange source should trigger an alert. The Type 1 flags and cancellation pattern are highly distinctive.

### 3.6 SMTP User Enumeration (Intrusive)

**Defender's view**: A single SMTP session issues MAIL FROM with a probe address (`probe@test.local`), then fires 30 sequential RCPT TO commands for common usernames (postmaster, admin, ceo, ciso, hr, finance, billing, legal, compliance, etc.).

**Detection rules**:
```
# Sigma-style rule
title: SMTP User Enumeration via RCPT TO
detection:
  selection:
    smtp_command: 'RCPT TO'
    smtp_mail_from|contains: 'probe@test.local'
  condition: selection | count(smtp_rcpt_to) > 10 within 2m from same session

title: SMTP RCPT TO Dictionary Attack
detection:
  selection:
    smtp_rcpt_to_user|in: ['postmaster', 'admin', 'ceo', 'cfo', 'cto', 'ciso', 'security']
  timeframe: 5m
  condition: selection | count() > 5 from same source
```

**Mercure's behavior**: Connects to the lowest-priority MX. Attempts STARTTLS if available. MAIL FROM: `probe@test.local`. Then 30 sequential RCPT TO for common addresses. Analyzes 250 (valid) vs 550/553/551 (invalid) responses. Detects catch-all (all 250) and blocked (503/530/disconnect).

**Residual signals**:
- `probe@test.local` as MAIL FROM (distinctive non-existent domain)
- 30 RCPT TO in a single session to predictable addresses
- No DATA command (no message sent) - pure enumeration
- Differential response analysis reveals which users exist
- MX server logs the full session

### 3.7 SMTP TLS Stripping Test (Intrusive)

**Defender's view**: Multiple SMTP connections to each MX testing TLS enforcement: (1) a connection that deliberately does NOT issue STARTTLS before MAIL FROM, (2) connections that negotiate deprecated TLS 1.0, (3) connections that negotiate deprecated TLS 1.1, (4) a connection that inspects the STARTTLS certificate.

**Detection rules**:
```
# Sigma-style rule
title: SMTP Plaintext Delivery Attempt
detection:
  selection:
    smtp_tls: false
    smtp_command: 'MAIL FROM'
  filter:
    smtp_response_code: 530
  condition: selection

title: Deprecated TLS Negotiation
detection:
  selection:
    tls_version|in: ['TLSv1', 'TLSv1.1']
    dst_port: 25
  condition: selection
```

**Mercure's behavior**: Per MX host, up to 4 separate connections: (1) plaintext test - EHLO then MAIL FROM without STARTTLS, (2) TLS 1.0 STARTTLS with pinned version, (3) TLS 1.1 STARTTLS with pinned version, (4) normal STARTTLS with certificate inspection. Uses `ssl.CERT_NONE` and `check_hostname=False` to avoid validation failures.

**Residual signals**:
- Plaintext MAIL FROM attempt (many modern MX enforce TLS via 530 response)
- TLS version pinning to deprecated protocols (visible in TLS handshake logs)
- 4 connections to same MX in rapid succession with different TLS behaviors
- Certificate inspection without mail delivery
- `ssl.CERT_NONE` means no client-side verification - anomalous for production MTA

### 3.8 NSEC Zone Walking (Intrusive)

**Defender's view**: A sequence of up to 50 NSEC record queries sent directly to the domain's authoritative nameserver. Each query asks for the NSEC record of the last discovered name, following the chain to enumerate zone contents.

**Detection rules**:
```
# Sigma-style rule
title: NSEC Zone Walk
detection:
  selection:
    query_type: NSEC
    query_flags|contains: 'DO'
  condition: selection | count(query_name) > 10 within 5m to same authoritative NS
```

**Mercure's behavior**: (1) Sends a random hex subdomain query with EDNS DO flag to elicit NSEC/NSEC3 in the authority section. (2) If NSEC found: follows next-name pointers for up to 50 steps, querying each name's NSEC record directly from the first NS. (3) If NSEC3 found: analyzes algorithm, iterations, salt length. Queries go directly to the authoritative NS IP (not through the recursive resolver).

**Residual signals**:
- Direct queries to authoritative NS (bypasses recursive resolver logging)
- Sequential NSEC queries following chain order
- EDNS with DO (DNSSEC OK) flag on all queries
- Random hex subdomain as initial probe (trigger for NSEC/NSEC3 response)
- Up to 50 queries in rapid succession to the same NS

### 3.9 Subdomain Brute-Force (Intrusive)

**Defender's view**: 200+ A record queries for common subdomain prefixes (www, mail, dev, staging, admin, vpn, git, jenkins, grafana, db, ldap, sso, etc.) from a single source in rapid succession, with 20 concurrent threads.

**Detection rules**:
```
# Sigma-style rule
title: Subdomain Dictionary Brute-Force
detection:
  selection:
    query_type: A
    query_name|regex: '^(dev|staging|admin|vpn|git|jenkins|db|ldap|sso|backup)\.'
  condition: selection | count() > 20 within 5m from same source

title: Wildcard Detection Probe
detection:
  selection:
    query_type: A
    query_name|regex: '^[0-9a-f]{20}\.'
  condition: selection
```

**Mercure's behavior**: (1) Wildcard detection: queries a random 20-char hex subdomain. (2) If wildcard detected, marks results accordingly and filters false positives. (3) 200+ A queries via ThreadPoolExecutor with 20 workers. (4) Categorizes results as sensitive, infrastructure, or standard.

**Residual signals**:
- High-volume A queries to predictable prefixes from single source
- 20-char hex subdomain query as wildcard probe
- 20 concurrent DNS queries (thread pool)
- Mix of NXDOMAIN and valid responses (unless wildcard active)
- Query list matches well-known subdomain wordlists (SecLists-adjacent)

### 3.10 External Tool Execution (Intrusive)

**Defender's view**: When nuclei, katana, or subfinder are installed, Mercure shells out to these binaries as subprocesses. Each tool has its own detection profile that is well-documented in the security community.

**Subfinder**:
- Queries multiple passive sources (crt.sh, VirusTotal, SecurityTrails, Censys, etc.)
- DNS resolution of discovered subdomains
- User-agent: `subfinder` (configurable)
- **Footprint**: primarily API calls to third-party services, some DNS resolution

**Nuclei**:
- HTTP/HTTPS requests with template-specific payloads
- User-agent: `Nuclei - Open-source project (github.com/projectdiscovery/nuclei)`
- Probes for known CVEs, misconfigurations, exposed panels, default credentials
- `-severity critical,high,medium,low` runs all severity templates
- 300-second timeout
- **Footprint**: hundreds of HTTP requests with known attack signatures

**Katana**:
- Web crawling with depth 3, concurrency 10
- User-agent: katana's default (identifiable)
- Link extraction, form discovery, JS file enumeration
- 180-second timeout
- **Footprint**: aggressive crawl pattern, rapid sequential page fetches

**Detection rules**:
```
# WAF rule
SecRule REQUEST_HEADERS:User-Agent "@contains Nuclei" "id:10001,deny,log"
SecRule REQUEST_HEADERS:User-Agent "@contains katana" "id:10002,deny,log"

# Sigma-style rule
title: ProjectDiscovery Tool Detection
detection:
  selection_nuclei:
    http_user_agent|contains: 'Nuclei'
  selection_katana:
    http_user_agent|contains: 'katana'
  condition: selection_nuclei or selection_katana
```

**Residual signals**:
- Tool-specific user-agent strings (most WAFs block these)
- Template payload patterns in HTTP requests (nuclei)
- Aggressive crawl cadence with no rendering (katana)
- Subprocess visible in process listing (`ps aux`)
- nuclei/katana write to stdout/stderr - captured by Mercure but process is visible

### 3.11 HTTP/TLS Probing (External)

**Defender's view**: HTTP(S) connections to the web server analyzing security configuration. Includes TLS handshake analysis, security header inspection, redirect chain following, cookie flag analysis, and well-known endpoint probing.

**Mercure's behavior**: For each external HTTP check:
- **TLS**: connects to port 443, analyzes cipher suite, protocol version, certificate chain, then STARTTLS to each MX on port 25
- **HSTS**: single GET, parses `Strict-Transport-Security` header
- **Headers**: single GET, parses CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP
- **Redirect**: GET to `http://domain`, follows redirect chain to `https://`
- **Cookie**: single GET, parses Set-Cookie flags
- **security.txt**: GET to `/.well-known/security.txt` and `/security.txt`
- **Autodiscover**: GET to 4 autodiscover/autoconfig URLs + SRV/CNAME lookups

**Residual signals**:
- Non-browser user-agent (Python requests/urllib)
- Single request per endpoint (no browsing pattern)
- No JavaScript execution or rendering
- Autodiscover probing hits known paths that some WAFs flag
- Rapid sequential requests to multiple endpoints without referrer chain

### 3.12 Port Scanning (Intrusive)

**Defender's view**: TCP connect scan to 18 well-known ports from a single source IP, sequential, with 2-second timeout per port.

**Detection rules**:
```
# Sigma-style rule
title: TCP Port Scan
detection:
  selection:
    dst_port|in: [21, 22, 23, 25, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
  condition: selection | count(dst_port) > 5 within 2m from same source
```

**Mercure's behavior**: Sequential TCP connect (not SYN scan) to the domain's first A record IP. Tests 18 ports: FTP(21), SSH(22), Telnet(23), SMTP(25), HTTP(80), POP3(110), IMAP(143), HTTPS(443), SMB(445), SMTPS(465), Submission(587), IMAPS(993), POP3S(995), MySQL(3306), RDP(3389), Postgres(5432), HTTP-alt(8080), HTTPS-alt(8443). Enriches with Shodan InternetDB data.

**Residual signals**:
- Full TCP handshake per port (connect, not SYN scan - completes handshake)
- 18 connections from same source within seconds
- No application-layer data sent after handshake (connect-only)
- Source IP logged in firewall/IDS
- Shodan API query reveals the requesting IP to Shodan

### 3.13 Relay Mode Detection Profile

**Defender's view**: When relay is configured, 5 of 9 methods route through the authenticated SMTP relay (e.g. `ssl0.ovh.net:465`). The recipient MX sees the relay's IP, not the attacker's.

**Detection differences vs direct**:
- SPF: passes for relay domain (e.g. `ovh.net`), but DMARC alignment fails because From domain differs
- Source IP: relay provider's IP - no direct attribution to attacker's IP in recipient logs
- `Received:` headers: contain relay hostname and relay's internal routing - identifiable as OVH/provider infrastructure
- `Authentication-Results:` header: SPF pass on relay domain, DKIM depends on relay's signing policy

**Relay-side detection**: The relay provider logs the authenticated session - username, source IP, recipients, timestamps. This is the primary attribution trail when using relay.

**Residual signals specific to relay mode**:
- Relay server name visible in `Received:` headers
- Authenticated user's email domain may differ from spoofed From domain
- Some relays add `X-Authenticated-Sender` or similar headers
- Relay provider may rate-limit or block after repeated sends with mismatched From domains

**Risk level**: **HIGH** (reduced from CRITICAL vs direct). The attacker's IP is hidden behind the relay, but the relay provider has full attribution.

**Risk level**: **CRITICAL**. Unlike score mode (passive DNS queries), spoof mode actively attempts to deliver emails. This leaves evidence in:
- Recipient mail server logs
- Exchange Online message trace
- SEG logs (Proofpoint, Mimecast, etc.)
- DMARC aggregate reports (rua)
- DMARC forensic reports (ruf)
- SPF authentication results in received headers

### 3.14 Multi-Domain Batch Mode

**Defender's view**: When Mercure processes a file of domains, the same query pattern repeats for each domain. This creates a periodic, machine-like cadence.

**Residual signal**: Identical check ordering across multiple domains is a strong indicator of automated tooling.

## 4. Limitation Inventory

| Residual Signal | Mode | Severity | Mitigation |
|---|---|---|---|
| High NXDOMAIN ratio from DKIM bruteforce | All modes | High | Use `--no-bruteforce` to skip selector enumeration |
| Full 49-check DNS/HTTP/SMTP reconnaissance | Default | High | Use `--checks` to limit to specific checks |
| SMTP probe to EXO endpoint on port 25 | Ghost check | High | Exclude ghost check: `--checks spf,dkim,dmarc,...` |
| Source IP not in SPF for EHLO domain | Ghost + Spoof (direct) | Medium | EHLO mimics `mail.<domain>` but source IP won't match SPF |
| Authenticated relay user mismatch | Spoof (relay) | Medium | Relay authenticates as one user but sends as another domain |
| `X-Oletros-Tool` header in delivered emails | Spoof mode | High | Intentional attribution header (only tool-specific signature) |
| `mercure@` sender + `Security Test - <method>` subject | Spoof mode | Medium | Identifiable spoofing test pattern |
| Source IP in recipient SMTP logs | Spoof mode | Critical | Direct attribution to testing origin |
| DMARC failure reports to `rua`/`ruf` endpoints | Spoof mode | High | SPF/DKIM failures generate reports to domain owner |
| Query volume spike | Batch mode | Medium | Reduce `--threads` to 1-2, add delays (not implemented) |
| Sequential query pattern | All modes | Medium | Query order is fixed; no randomization |
| Recursive resolver logs | All modes | Low | Use a dedicated resolver or DNS-over-HTTPS (external) |
| NTLM Type 1 negotiate on SMTP | Intrusive (smtp_recon) | Critical | NTLM auth attempt logged by MX - highly anomalous |
| AUTH cancellation with `*` after Type 2 | Intrusive (smtp_recon) | High | Cancel pattern unique to recon probes |
| HELP command after AUTH sequence | Intrusive (smtp_recon) | Medium | HELP is uncommon in production mail |
| 30 sequential RCPT TO to common usernames | Intrusive (smtp_enum) | Critical | Dictionary-style enumeration pattern in SMTP logs |
| `probe@test.local` as MAIL FROM | Intrusive (smtp_enum) | High | Non-existent domain as envelope sender |
| Plaintext SMTP delivery attempt (no STARTTLS) | Intrusive (smtp_tls_strip) | High | Deliberate TLS avoidance logged as plaintext session |
| Deprecated TLS 1.0/1.1 negotiation | Intrusive (smtp_tls_strip) | Medium | Pinned deprecated version visible in TLS logs |
| Up to 50 NSEC queries following chain | Intrusive (nsec_walk) | High | Zone walk pattern to authoritative NS |
| Random hex subdomain as NSEC trigger | Intrusive (nsec_walk) | Low | Single probe query, could be legitimate resolver |
| 200+ A queries for common subdomains | Intrusive (subdomain_brute) | High | Dictionary pattern with 20 concurrent threads |
| Wildcard detection via random hex query | Intrusive (subdomain_brute) | Low | Single A query for 20-char hex name |
| TCP connect to 18 ports sequentially | Intrusive (open_ports) | High | Port scan pattern in firewall logs |
| Shodan InternetDB query for target IP | Intrusive (open_ports) | Low | Shodan API request from your source IP |
| nuclei user-agent and template payloads | Intrusive (nuclei) | Critical | Well-known scanner signature blocked by most WAFs |
| katana user-agent and crawl pattern | Intrusive (katana) | High | Crawler signature, aggressive link extraction |
| subfinder DNS/API queries | Passive (subdomains) | Medium | Multiple passive source queries from single IP |
| HTTP requests to autodiscover/autoconfig URLs | External (autodiscover) | Medium | Known endpoint paths that WAFs may flag |
| Non-browser user-agent on HTTP checks | External (web checks) | Low | Python user-agent on single requests |

## 5. Risk Matrix

| Mode | Basic DNS Monitoring | Corporate DNS Firewall | Enterprise SIEM + DNS |
|---|---|---|---|
| Single domain, no bruteforce | Low (10%) | Low (15%) | Medium (30%) |
| Single domain, default (passive) | Medium (30%) | Medium (45%) | High (65%) |
| Single domain, aggressive | High (50%) | High (70%) | High (85%) |
| Single domain, intrusive | High (70%) | Very High (85%) | Very High (95%) |
| Single domain, intrusive + external tools | Very High (85%) | Very High (95%) | Critical (99%) |
| Batch mode, default (passive) | High (60%) | High (75%) | Very High (90%) |
| Batch mode, aggressive | Very High (80%) | Very High (90%) | Very High (95%) |
| Batch mode, intrusive | Very High (90%) | Critical (95%) | Critical (99%) |
| Batch mode, intrusive + external tools | Critical (95%) | Critical (99%) | Critical (99%) |
| Spoof mode (direct) | Very High (85%) | Very High (95%) | Critical (99%) |
| Spoof mode (relay) | High (60%) | High (75%) | Very High (90%) |

## 6. Recommendations

| Target Profile | Recommended Config | Rationale |
|---|---|---|
| No monitoring | `python mercure.py -d target.com --aggressive --intrusive` | Full coverage with all 49 checks, speed doesn't matter |
| No monitoring + external tools | `python mercure.py -d target.com --aggressive --intrusive` (with nuclei/katana/subfinder in PATH) | Maximum coverage: 49 checks + vuln scanning + crawling + passive enum |
| Basic DNS logs | `python mercure.py -d target.com --threads 2` | Reduce burst, keep bruteforce, skip intrusive |
| Corporate DNS firewall | `python mercure.py -d target.com --no-bruteforce` | Avoid DKIM enumeration spike, passive checks only |
| Enterprise SIEM | `python mercure.py -d target.com --checks spf,dmarc,caa --no-bruteforce` | Minimal footprint, high-value checks only |
| Stealth recon | Manual `dig` queries for SPF/DMARC/CAA only | Mercure's pattern is too recognizable for stealth |
| External tools only (no SMTP intrusive) | `python mercure.py -d target.com --checks subdomains,ct,tls,hsts,headers,whois,rpki` | Web and recon checks without touching SMTP or scanning ports |
| SMTP-focused intrusive audit | `python mercure.py -d target.com --intrusive --checks ghost,smtp_sec,smtp_recon,smtp_enum,smtp_tls_strip,bounce` | Full SMTP recon without DNS/web noise |
| Maximum stealth intrusive | `python mercure.py -d target.com --intrusive --checks smtp_recon,nsec_walk --skip-external` | Targeted intrusive checks, no external APIs, minimal footprint |

## 7. Behavioral Analysis

### Statistical Detection

A DNS/network monitoring system with behavioral baselines can detect Mercure via:

1. **Query type diversity**: 17+ different DNS record types to a single domain within seconds is abnormal for any legitimate client
2. **NXDOMAIN ratio**: DKIM bruteforce generates 95%+ NXDOMAIN, far above normal baselines
3. **Query cadence**: Machine-generated queries have sub-second intervals with no human think time
4. **Subdomain enumeration**: `*._domainkey` and dictionary subdomain queries follow predictable patterns
5. **Protocol diversity**: DNS + SMTP + HTTP + TCP from same source within minutes (intrusive/external mode)
6. **SMTP command sequence**: EHLO -> AUTH NTLM -> cancel -> HELP is a recon-specific pattern never seen in production mail
7. **RCPT TO volume**: 30 RCPT TO in one session without DATA is pure enumeration
8. **Port scan cadence**: 18 sequential TCP connects with uniform timeout is machine behavior
9. **Tool user-agents**: nuclei and katana user-agent strings are blocklisted by most WAFs

### ML-Based Detection

Supervised models trained on DNS/network logs would flag Mercure based on:

**Passive mode feature vector:**
- `(query_type_count=17, nxdomain_ratio=0.95, queries_per_minute=500, unique_subdomains=5300, txt_query_ratio=0.8)`
- This vector is far outside the cluster of normal browsing/email behavior

**Intrusive mode feature vector:**
- `(smtp_sessions=10, rcpt_per_session=30, auth_ntlm_cancel=true, plaintext_smtp_attempt=true, tls_deprecated_negotiate=true, nsec_queries=50, tcp_ports_scanned=18, query_type_count=17+)`
- Multi-protocol recon signature combining SMTP, DNS, and TCP anomalies

**External tools feature vector:**
- `(http_requests=500+, unique_paths=200+, known_scanner_ua=true, crawl_depth=3, form_interaction=true)`
- Aggressive web scanning pattern with tool-specific signatures

### Bypass Limitations

Mercure does NOT implement:
- Query order randomization
- Inter-query delays or jitter
- DNS-over-HTTPS/TLS (resolver selection is external)
- Split queries across multiple resolvers
- Time-spread scanning (all checks run immediately)
- User-agent rotation for HTTP checks
- SMTP session timing randomization
- Custom user-agent for nuclei/katana subprocess calls
- Source IP rotation or proxy chaining
- NTLM probe obfuscation (standard Type 1 flags)
- RCPT TO timing jitter or subset selection

These are intentional: Mercure is an auditing tool, not a stealth scanner. Defenders should assume that a determined attacker would implement these techniques independently.
