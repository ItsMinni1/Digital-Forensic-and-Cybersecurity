# Assignment: Client-Side Security & Malware Fundamentals

## Task 1: Malware Family Classification Table 

The table below outlines nine distinct malware families, providing a real-world historical example, the primary vector/method of spread, and the fundamental technical or procedural control that would have mitigated or prevented the threat.

| Malware Family | Real-World Example | Primary Spread Method | Effective Preventative Control |
| :--- | :--- | :--- | :--- |
| **1. Virus** | **ILOVEYOU** (2000) | Execution of malicious email attachments requiring explicit user interaction (opening a VBS script). | **Content Filtering & End-User Training:** Restricting executable attachments (`.vbs`, `.exe`) at the email gateway and user awareness training. |
| **2. Worm** | **WannaCry** (2017) | Self-propagation across network connections by exploiting unpatched vulnerabilities (SMBv1 / EternalBlue) without user interaction. | **Vulnerability Patching & Network Segmentation:** Timely application of security patches (MS17-010) and isolating legacy SMB protocols. |
| **3. Trojan** | **Emotet** | Disguised as legitimate software or documents (malicious Office macros) delivered via phishing emails. | **Macro Restrictions & EDR:** Disabling execution of unsigned macros via Group Policy and deploying Endpoint Detection and Response. |
| **4. Ransomware** | **Ryuk** | Lateral movement following initial compromise (often via Trojan/phishing), encrypting local and network files. | **Immutable Backups & Least Privilege:** Maintaining offline/air-gapped backups and enforcing strict access control lists (ACLs) on network shares. |
| **5. Spyware / Keylogger** | **DarkComet** | Bundled with cracked software or delivered via drive-by downloads to covertly record keystrokes and sensitive data. | **Application Whitelisting (AppLocker):** Restricting execution strictly to trusted, authorized software binaries. |
| **6. Adware** | **Superfish** | Pre-installed vendor software or bundled with free downloads, hijacking browser sessions and injecting unauthorized SSL certificates. | **Software Inventory Control & Certificate Pinning:** Strict endpoint software policies and enforcing TLS certificate validation. |
| **7. Rootkit** | **Stuxnet** | Kernel-mode driver insertion or system binary modification to conceal active processes and files from the operating system. | **Secure Boot & Driver Signature Enforcement:** Ensuring hardware-level root of trust and requiring cryptographically signed kernel drivers. |
| **8. Botnet** | **Mirai** | Automated scanning and exploitation of weak/default credentials on networked devices to enlist them in a C2 network. | **Credential Management & Network Firewalls:** Enforcing strong, non-default passwords and disabling exposed management interfaces (SSH/Telnet). |
| **9. Fileless Malware** | **Astaroth** | Living-off-the-Land Binaries (LotLBins) executing malicious code directly in volatile memory via native utilities (e.g., PowerShell, WMI). | **Behavioral Monitoring & Script Block Logging:** Implementing PowerShell constrained language mode and memory-based behavioral detection. |

---

## Task 2: Payload Lab Write-Up & Mechanics 

### Legal and Scope Constraints

Authorized penetration testing and security research must operate strictly within a clear legal framework. Performing security testing against any computer system without explicit, prior written authorization from the system owner constitutes an offense under legislation such as the **Computer Misuse Act 1990** (UK) or the **Computer Fraud and Abuse Act (CFAA)** (US).

Before executing any client-side payload testing or handler listener configuration, the following prerequisites must be established:

1. **Written Permission / Authorization:** A formal contract or authorization letter clearly defining the client, target assets, and testing window.
2. **Defined Scope of Work (SoW):** Strict boundaries specifying permitted target IP addresses, domain names, user accounts, and excluded infrastructure (e.g., operational production databases).
3. **Rules of Engagement (RoE):** Agreed-upon testing hours, emergency contact protocols, communication channels for critical vulnerability disclosures, and explicit limitations on disruptive techniques (e.g., Denial of Service).

---

### Payload Architecture & Handler Configuration Concepts

Client-side exploitation often relies on a **reverse shell** connection model. In this setup, the target machine initiates an outbound network connection back to the handler listening on the security analyst's system.

#### Connection Direction & NAT Dynamics

* **Why Outbound Traffic Works:** Perimeter firewalls typically enforce strict inbound filtering rules while allowing standard outbound traffic (e.g., TCP ports 80, 443, or 53). Reverse payloads leverage this asymmetric policy.
* **Role of Network Address Translation (NAT):** When the testing platform resides behind a router/NAT interface, direct inbound connections from an external target are blocked unless port forwarding is configured or tunneling mechanisms (e.g., SSH remote forwarding or dedicated reverse proxy infrastructure) are established.
* **Parameter Matching Requirements:** The handler (listener) and generated payload must align perfectly across three primary parameters:
  1. **Payload Type:** Matching architecture (x86/x64) and platform (Windows/Linux).
  2. **LHOST (Listen Host):** The IP address accessible by the target pointing to the listening interface.
  3. **LPORT (Listen Port):** The specific TCP port configured to accept incoming reverse session requests.

If any parameter mismatches, the connection will fail silently without returning descriptive client-side error logs.

---

### Technical Analysis: UAC Restrictions and Token Privileges

#### UAC Token Architecture

When a user belonging to the local `Administrators` group logs into a Windows system with User Account Control (UAC) enabled, Windows issues two separate access tokens:

1. **Filtered Standard User Token:** Used for routine operations, stripping administrative privileges (e.g., `SeDebugPrivilege`, `SeImpersonatePrivilege`).
2. **Elevated Administrative Token:** Retained in an inactive state until an application explicitly requests privilege elevation via a UAC prompt (Consent Prompt or Credential Prompt).

#### Why Initial `getsystem` Execution Fails

When an initial reverse session is established under a standard execution context (even if logged in as an administrator):

* The payload executes within the context of the **Filtered Standard User Token**.
* Attempting to issue system-level elevation commands (such as `getsystem` in command-and-control frameworks) relies on privilege exploitation techniques (e.g., named pipe impersonation or service creation).
* Because the process lacks elevated rights and privileges like `SeDebugPrivilege` or `SeLoadDriverPrivilege`, Windows security boundaries prevent the service creation or token impersonation calls, resulting in an `Access Denied` error.

To successfully transition to `NT AUTHORITY\SYSTEM`, an explicit UAC bypass technique or credentialed elevation must first be performed to escalate the process into a high-integrity execution environment.

---

## Task 3: Career Statement 

### Target Specialism

My primary career objective is to specialize as an **Offensive Security Operations Specialist / Red Teamer**, focusing on adversary emulation, client-side security assessment, and post-exploitation analytics.

### Target Entry Credential

To validate foundational practical skillsets in hands-on penetration testing and offensive methodologies, my target entry credential is the **Offensive Security Certified Professional (OSCP)**.

### Portfolio Development Goals (Three-Month Plan)

To demonstrate practical competency to prospective engineering leads and recruiters, I am building three concrete portfolio artifacts over the next 90 days:

1. **Client-Side Exploit Analysis & Detection Lab (GitHub Repository):**
   * A documented laboratory repository showcasing benign proof-of-concept scripts demonstrating client-side execution vectors paired with corresponding Sigma rules and Sysmon detection configurations.

2. **Automated Infrastructure Deployment Script (Terraform / Ansible):**
   * An open-source Infrastructure-as-Code repository that automatically provisions an isolated, dual-homed Active Directory laboratory environment containing enterprise logging infrastructure (ELK stack) for testing defensive controls.

3. **Published Technical Post-Mortem & Vulnerability Write-Up (Technical Blog):**
   * A comprehensive, publicly accessible technical write-up analyzing a publicly disclosed client-side vulnerability (e.g., Office macro execution or protocol handler abuse), breaking down the underlying root cause, memory mechanics, and recommended enterprise remediation steps.