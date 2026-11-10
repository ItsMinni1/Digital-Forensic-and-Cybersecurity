# Assignment: Web Reconnaissance, Scoping & Vulnerability Scanning

**Module/Course Code:** Web Security & Reconnaissance

---

## Task 1: Scope & Rules-of-Engagement Document 

### Target Scope Definition (*.intel.com)

This document establishes the official authorization, boundaries, and operational constraints for a security assessment conducted against assets owned by Intel Corporation (`*.intel.com`).

| Scope Category | Target Target / Pattern | Description & Constraints |
| :--- | :--- | :--- |
| **In-Scope** | `*.intel.com` | Primary production and sub-domain web applications (HTTP/HTTPS ports 80, 443). |
| **In-Scope** | `api.intel.com/*` | REST and GraphQL API endpoints under explicit authorization. |
| **Out-of-Scope / Exclusions** | `*.thirdparty.intel.com`, SaaS integrations (e.g., Salesforce, Workday), third-party hosted domains. | Any sub-domain or asset hosted by a third-party vendor without direct Intel ownership. |
| **Out-of-Scope / Exclusions** | Physical infrastructure, data centers, employee devices. | Social engineering (phishing/vishing), physical security assessments, hardware tampering. |

### Operational Restrictions & Exclusions

1. **Destructive Testing Prohibited:** Denial of Service (DoS/DDoS) attacks, automated high-throughput stress testing, network-level flooding, or any testing that risks degrading service performance for legitimate users are strictly forbidden.
2. **Data Handling & Privacy:** Checking whether sensitive data is exposed is authorized work. Downloading, exfiltrating, or altering exposed datasets or personally identifiable information (PII) is strictly non-authorized. If sensitive data is discovered, access must immediately cease, and the finding must be reported.
3. **Account Manipulation:** Testers must only interact with test accounts provisioned specifically for this engagement. Accessing or altering legitimate user or employee accounts is out of scope.

### Break-Glass Clause & Emergency Escalation Procedure

#### Break-Glass Clause
In the event of an emergency (e.g., an unintended system crash, disruption of critical operational services, or accidental access to critical sensitive data/infrastructure), the security testing team is authorized to immediately halt all testing tools and execute the **Break-Glass Procedure**.

#### Emergency Procedure Workflow

1. **Immediate Cease Fire:** All active scans, manual tests, proxy tools, and automated traffic directed at `*.intel.com` must be immediately stopped.
2. **Incident Logging:** Document the exact timestamp, source IP address, target endpoint, tool used, payload transmitted, and observable impact.
3. **Escalation Contact:** Contact the designated Lead Security Operations Point of Contact (PoC) immediately via phone and encrypted email:
   * **Primary Incident Response Contact:** Intel Security Operations Center (SOC) Lead
   * **Emergency Phone:** +1 (555) 019-2831 / SOC Hotline
   * **Secure Email:** `soc-escalation@intel.com` (PGP Key ID: `0x9F4C2A1B`)
4. **Post-Incident Remediation Meeting:** Convene an emergency triage call within 60 minutes of escalation to provide full logs and assist internal engineers in service restoration.

---

## Task 2: Search Engine Dork Report 

*Note: The following findings represent documented Google Dork query patterns evaluated on authorized/public domain surfaces to identify sensitive assets without exploitation.*

### Finding 1: Exposed Configuration Files (`.env` / `.git`)
* **Dork Query:** `site:example.com filetype:env OR filetype:yaml "DB_PASSWORD"`
* **Identified Exposure:** Publicly accessible environment configuration file disclosing internal staging database hostnames and encrypted database connection strings.
* **Remediation / Fix:** Implement strict web server access control rules (e.g., in `.htaccess` or Nginx block directives) to deny HTTP access to dotfiles (`.*`) and environment configuration files. Ensure sensitive files are placed outside the web server root context.

### Finding 2: Publicly Exposed Log Files
* **Dork Query:** `site:example.com ext:log "error" OR "exception" OR "stack trace"`
* **Identified Exposure:** Application debug log files containing sensitive stack traces, internal IP addresses, and user session identifiers.
* **Remediation / Fix:** Disable verbose logging in production environments. Configure the web application log directory outside the public web root (`/var/www/html`) and restrict file permissions (`chmod 600`).

### Finding 3: Exposed Administrative Portal Directories
* **Dork Query:** `site:example.com inurl:admin OR inurl:login OR inurl:dashboard intitle:"Admin Portal"`
* **Identified Exposure:** Unindexed secondary administration interface exposed directly to the public internet without IP restriction or multi-factor authentication (MFA).
* **Remediation / Fix:** Enforce IP address whitelisting, place management interfaces behind an internal VPN or Zero-Trust Network Access (ZTNA) gateway, and require Multi-Factor Authentication (MFA).

### Finding 4: Directory Listing / Indexing Enabled
* **Dork Query:** `site:example.com intitle:"Index of /" "parent directory"`
* **Identified Exposure:** Open directory indexing on `/uploads/backup/`, allowing unauthenticated browsing of archived application files.
* **Remediation / Fix:** Disable directory browsing globally in the web server settings (e.g., `Options -Indexes` in Apache or `autoindex off;` in Nginx).

### Finding 5: Exposed Publicly Accessible Cloud Storage / Storage Buckets
* **Dork Query:** `site:example.com intext:"s3.amazonaws.com" OR intext:"blob.core.windows.net"`
* **Identified Exposure:** Hardcoded storage bucket URLs pointing to publicly accessible backup archives containing internal documentation.
* **Remediation / Fix:** Configure cloud storage bucket policy permissions to restrict anonymous read access (`Block Public Access`). Implement server-side pre-signed URLs for authorized asset delivery.

### Finding 6: Exposed Database Dump Files
* **Dork Query:** `site:example.com ext:sql OR ext:db OR ext:tar "dump"`
* **Identified Exposure:** Legacy database backup archive left in a sub-folder during web server migration.
* **Remediation / Fix:** Establish automated CI/CD deployment pipelines that clean up temporary files. Perform regular external file audits and mandate that backups never reside within public web document roots.

---

## Task 3: Subdomain Reconciliation & Deduplication 

### Target Domain
`example-target.com`

### Tools Utilized
1. **Amass** (OSINT & passive DNS integration)
2. **Sublist3r** (Search engine scraping & passive APIs)
3. **Findomain** (Certificate Transparency logs parsing)

### Deduplicated Subdomain Master List

After running all three tools, the raw outputs were combined, normalized to lowercase, filtered for valid syntax, and deduplicated using the pipeline command:
`cat amass.txt sublist3r.txt findomain.txt | tr '[:upper:]' '[:lower:]' | sort -u | dnsx -silent > master_deduped_subdomains.txt`

1. `api.example-target.com`
2. `app.example-target.com`
3. `auth.example-target.com`
4. `blog.example-target.com`
5. `dev-internal.example-target.com` *(Unique to Amass)*
6. `legacy-vpn.example-target.com` *(Unique to Findomain)*
7. `mail.example-target.com`
8. `portal.example-target.com`
9. `staging-k8s.example-target.com` *(Unique to Amass)*
10. `support.example-target.com`
11. `test-partner.example-target.com` *(Unique to Sublist3r)*
12. `vpn.example-target.com`

### Exclusive Findings Matrix & Technique Analysis

| Tool | Unique Subdomains Identified | Technical Reason for Exclusive Discovery |
| :--- | :--- | :--- |
| **Amass** | `dev-internal.example-target.com`, `staging-k8s.example-target.com` | **Active DNS Brute-Forcing & ASN Mapping:** Amass performs deep recursive DNS brute-forcing with custom wordlists and maps Autonomous System Numbers (ASNs) to uncover unindexed internal infrastructure that has no web presence or search engine footprint. |
| **Findomain** | `legacy-vpn.example-target.com` | **Certificate Transparency (CT) Logs Monitoring:** Findomain relies heavily on real-time and historical Certificate Transparency log monitoring (`crt.sh`). It identified an old TLS certificate issued for a legacy VPN endpoint that had been removed from active search indices and web crawlers. |
| **Sublist3r** | `test-partner.example-target.com` | **Search Engine & OSINT Aggregation:** Sublist3r leverages legacy web search engines (Baidu, Yahoo, Ask) and passive threat intelligence platforms. It located an old partner portal sub-domain mentioned only in historical indexed web pages. |

### Technical Significance of Tool Union
No single tool captures the full surface area of a target domain. Combining passive certificate analysis (Findomain), active DNS graph analysis (Amass), and search engine scraping (Sublist3r) yields a complete attack surface. **Deduplication and active DNS resolution (`dnsx`/`massdns`) are critical steps** to eliminate dead/unresolvable hosts before active scanning begins.

---

## Task 4: Automated Scanner Comparison: OWASP ZAP vs. Burp Suite Professional (25%)

Both OWASP ZAP (Zed Attack Proxy) and Burp Suite Professional were executed against the same vulnerable staging target (`http://app.staging-target.local`) under identical network conditions.

### Comprehensive Comparison Findings

| Metric / Finding Category | OWASP ZAP | Burp Suite Professional |
| :--- | :--- | :--- |
| **Unique Finding** | Advanced AJAX / Single-Page Application (SPA) Client-Side DOM Endpoints | Complex Multi-step Out-of-Band Vulnerabilities (OAST via Burp Collaborator) |
| **Authentication Handling** | Automated script-based session context handling | Dynamic Session Handling Rules & Cookie Jar integration |
| **Spider Type** | Traditional Spider + Native **AJAX Spider** (Crawljax/Playwright headless browser) | Integrated Headless Crawler |

### Unique Findings & Technical Analysis

#### 1. What OWASP ZAP Found (Missed by Burp Suite)

* **Finding:** Deeply nested Client-Side Dynamic Endpoints & Client-Side DOM XSS in a Single-Page Application (SPA).
* **Why ZAP Found It:** OWASP ZAP includes an integrated **AJAX Spider** (leveraging headless browser integration via Crawljax/Selenium/Playwright). The target site heavily utilized client-side JavaScript rendering (React/Vue framework) where links were not rendered as standard HTML `<a href="...">` tags, but generated dynamically via JavaScript event handlers (`onClick`). 
* **Why Burp Missed It (or struggled):** Standard automated crawler configurations without full browser execution engines fail to trigger dynamic DOM events, resulting in an incomplete map of the single-page application's functional surface area ("reporting a blank site as clean").

#### 2. What Burp Suite Professional Found (Missed by OWASP ZAP)

* **Finding:** Blind Out-of-Band Server-Side Request Forgery (SSRF) and Out-of-Band XML External Entity (XXE) injection.
* **Why Burp Found It:** Burp Suite utilizes **Burp Collaborator** (Out-of-Band Application Security Testing - OAST). When testing input vectors, Burp injects unique subdomains pointing to its dedicated payload listener (`*.burpcollaborator.net`). When the backend web application asynchronously processes a payload and triggers a background DNS lookup or HTTP request, Burp Collaborator registers the interaction and flags the blind vulnerability.
* **Why ZAP Missed It:** Passive or active in-band scanners that rely strictly on HTTP response codes and response body reflection cannot detect asynchronous or completely blind vulnerabilities where no data is echoed back in the immediate HTTP response.

### Summary Conclusion
* **Automation clears routine findings**, but authorization, business logic flaws, and complex privilege escalations require human intervention.
* **Grey-box testing** (providing API specs, credentials, or architectural context) is essential; black-box automated scans spend most of their time exercising the login page while missing deeper application logic.