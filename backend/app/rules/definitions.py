"""CyberMate Rule Catalog.
Contains 49 deterministic rules for defensive cybersecurity diagnosis,
mapping observable indicators and facts to defensive threat classifications,
MITRE ATT&CK techniques, confidence scoring, and prescriptive mitigations.
"""
from typing import List
from app.rules.condition import Rule, Condition


def get_all_rules() -> List[Rule]:
    """Returns the comprehensive collection of 49 defensive cybersecurity rules."""
    rules: List[Rule] = [
        # =========================================================================
        # 1. AUTHENTICATION & ACCESS CONTROL (AUTH-001 to AUTH-010)
        # =========================================================================
        Rule(
            id="AUTH-001",
            name="Repeated Failed Authentication (Brute Force)",
            category="Authentication",
            threat="Brute Force Attack",
            severity="HIGH",
            base_confidence=0.88,
            mitre_technique="T1110.001 - Password Guessing",
            conditions=[
                Condition(field="failed_login_count", operator="gte", value=5, description="5 or more failed login attempts recorded"),
            ],
            explanation_template="A sequence of repeated failed login attempts indicates systematic password guessing or dictionary attacks targeting the authentication endpoint.",
            recommendations=[
                "Implement temporary IP rate limiting and progressive account lockout thresholds.",
                "Verify whether multi-factor authentication (MFA) is strictly enforced for the account.",
                "Review perimeter authentication logs for source IP addresses and ASN origins.",
                "Deploy CAPTCHA or proof-of-work challenge on consecutive login failures."
            ]
        ),
        Rule(
            id="AUTH-002",
            name="Successful Authentication After Multiple Failures",
            category="Authentication",
            threat="Account Takeover",
            severity="CRITICAL",
            base_confidence=0.92,
            mitre_technique="T1110 - Brute Force / Account Access",
            conditions=[
                Condition(field="failed_login_count", operator="gte", value=5, description="Repeated failed login attempts"),
                Condition(field="successful_login_after_failures", operator="is_true", description="Successful authentication immediately following failures"),
            ],
            explanation_template="Repeated failed logins followed by a successful authentication strongly suggests the attacker succeeded in guessing or cracking valid credentials.",
            recommendations=[
                "Immediately revoke active sessions and refresh tokens for this account across all devices.",
                "Force an immediate out-of-band credential reset.",
                "Audit recent actions performed in the session (profile updates, MFA changes, emails sent).",
                "Lock the account pending verification with the legitimate user via secondary channel."
            ]
        ),
        Rule(
            id="AUTH-003",
            name="Distributed Credential Stuffing Campaign",
            category="Authentication",
            threat="Credential Stuffing",
            severity="HIGH",
            base_confidence=0.85,
            mitre_technique="T1110.004 - Credential Stuffing",
            conditions=[
                Condition(field="failed_login_count", operator="gte", value=10, description="High volume of login failures"),
                Condition(field="multiple_accounts_targeted", operator="is_true", description="Failures distributed across multiple distinct usernames"),
                Condition(field="distributed_ips", operator="is_true", description="Authentication attempts originating from distributed IP addresses"),
            ],
            min_conditions_match=2,
            explanation_template="High volume of authentication attempts across multiple distinct user accounts from distributed IPs indicates automated credential stuffing from public data breaches.",
            recommendations=[
                "Check observed credentials against haveibeenpwned or internal leaked credential monitors.",
                "Activate Web Application Firewall (WAF) bot management rules on the login endpoint.",
                "Mandate password reset for all affected accounts and enforce strong unique passwords.",
                "Require FIDO2/WebAuthn hardware or biometric MFA."
            ]
        ),
        Rule(
            id="AUTH-004",
            name="Password Spraying against Directory",
            category="Authentication",
            threat="Password Spraying",
            severity="HIGH",
            base_confidence=0.84,
            mitre_technique="T1110.003 - Password Spraying",
            conditions=[
                Condition(field="multiple_accounts_targeted", operator="is_true", description="Multiple accounts targeted simultaneously"),
                Condition(field="single_source_ip", operator="is_true", description="Requests originating from a unified IP or subnet"),
            ],
            explanation_template="Single source IP attempting single-password logins across many accounts is characteristic of password spraying designed to evade single-account lockout thresholds.",
            recommendations=[
                "Block the attacking IP address or CIDR range at the border firewall/WAF.",
                "Analyze authentication logs for common seasonal passwords (e.g., SeasonYear!).",
                "Enforce smart lockout policies based on tenant-wide heuristics."
            ]
        ),
        Rule(
            id="AUTH-005",
            name="MFA Fatigue / Push Prompt Bombing",
            category="Authentication",
            threat="MFA Fatigue Attack",
            severity="CRITICAL",
            base_confidence=0.90,
            mitre_technique="T1621 - Multi-Factor Authentication Request Generation",
            conditions=[
                Condition(field="repeated_mfa_prompts", operator="is_true", description="Excessive rapid MFA push notifications pushed to user"),
                Condition(field="mfa_accepted_unusual_time", operator="is_true", description="MFA prompt accepted during odd hours or after denial"),
            ],
            min_conditions_match=1,
            explanation_template="Spamming repeated MFA push requests until the user inadvertently or desperately approves is an established technique to bypass 2FA.",
            recommendations=[
                "Switch MFA policy from simple one-tap push approval to Number Matching.",
                "Temporarily disable push-based MFA for the targeted identity and switch to FIDO2 or TOTP.",
                "Revoke all current sessions for the user and inspect recent sign-in IP and device."
            ]
        ),
        Rule(
            id="AUTH-006",
            name="Impossible Travel / Geo-velocity Anomaly",
            category="Authentication",
            threat="Session Hijacking or Credential Sharing",
            severity="HIGH",
            base_confidence=0.86,
            mitre_technique="T1078 - Valid Accounts",
            conditions=[
                Condition(field="impossible_travel", operator="is_true", description="Sign-ins from geographically distant locations within an impossible timeframe"),
                Condition(field="login_from_unusual_location", operator="is_true", description="Access from anomalous country or autonomous system"),
            ],
            min_conditions_match=1,
            explanation_template="Logins from geographic locations separated by distances that cannot be physically traversed within the elapsed interval indicates stolen session cookies or proxy exploitation.",
            recommendations=[
                "Revoke current access tokens and user browser cookies.",
                "Verify if the user was routing through an enterprise VPN or satellite link.",
                "Enforce conditional access policies requiring managed compliant devices."
            ]
        ),
        Rule(
            id="AUTH-007",
            name="Dormant Account Sudden Reactivation",
            category="Authentication",
            threat="Compromised Stale Identity",
            severity="MEDIUM",
            base_confidence=0.78,
            mitre_technique="T1078.002 - Domain Accounts",
            conditions=[
                Condition(field="dormant_account_activity", operator="is_true", description="Account inactive for >90 days suddenly logging in"),
                Condition(field="login_from_unknown_ip", operator="is_true", description="Access initiated from unrecognized external IP"),
            ],
            explanation_template="An inactive or legacy account suddenly becoming active from an unfamiliar IP address is frequently used by adversaries seeking stealthy footholds.",
            recommendations=[
                "Disable or deprovision the dormant account immediately.",
                "Interview the account owner or line manager to verify legitimate return to service.",
                "Enforce automated lifecycle deprovisioning for inactive identities."
            ]
        ),
        Rule(
            id="AUTH-008",
            name="Unauthorized Administrative Account Creation",
            category="Account",
            threat="Privilege Escalation / Backdoor Account",
            severity="CRITICAL",
            base_confidence=0.94,
            mitre_technique="T1136.001 - Local Account",
            conditions=[
                Condition(field="unexpected_account_creation", operator="is_true", description="New account generated outside standard provisioning windows"),
                Condition(field="privilege_escalation", operator="is_true", description="Elevated or administrative roles granted to new account"),
            ],
            explanation_template="Creation of new accounts granted administrative or root privileges without change management ticket indicates backdoor persistence or insider threat.",
            recommendations=[
                "Immediately disable and quarantine the newly generated account.",
                "Review security event log ID 4720 (User Created) and 4728 (Member Added to Security Group).",
                "Investigate the parent process and session that executed the account creation."
            ]
        ),
        Rule(
            id="AUTH-009",
            name="MFA Disabled Following Password Change",
            category="Authentication",
            threat="Defensive Neutralization / Account Hijacking",
            severity="CRITICAL",
            base_confidence=0.95,
            mitre_technique="T1556 - Modify Authentication Process",
            conditions=[
                Condition(field="password_changed_unexpectedly", operator="is_true", description="Password changed without prior ticket or user knowledge"),
                Condition(field="mfa_disabled", operator="is_true", description="MFA method removed or downgraded"),
            ],
            explanation_template="An abrupt password alteration followed immediately by deactivation of MFA is a textbook signature of hostile account consolidation by an adversary.",
            recommendations=[
                "Immediately lock the account at identity provider level (Entra ID, Okta, Google Workspace).",
                "Revoke all active OAuth app grants and secondary email recovery options.",
                "Engage incident responder to contact user via verified offline voice phone call."
            ]
        ),
        Rule(
            id="AUTH-010",
            name="New Device Detected with Unknown Source IP",
            category="Authentication",
            threat="Suspicious Authentication Activity",
            severity="MEDIUM",
            base_confidence=0.72,
            mitre_technique="T1078 - Valid Accounts",
            conditions=[
                Condition(field="new_device_detected", operator="is_true", description="Unrecognized user-agent, hardware UUID, or browser fingerprint"),
                Condition(field="login_from_unknown_ip", operator="is_true", description="Login originating from non-allowlisted IP address"),
            ],
            explanation_template="A novel hardware device accessing critical systems from an unknown IP address requires identity verification.",
            recommendations=[
                "Prompt the user for immediate secondary biometric challenge or SMS/FIDO2 re-auth.",
                "Inspect device compliance status in endpoint management system (Intune, Jamf).",
                "Review whether the user was traveling or purchased new hardware."
            ]
        ),

        # =========================================================================
        # 2. NETWORK & PERIMETER (NET-001 to NET-008)
        # =========================================================================
        Rule(
            id="NET-001",
            name="DNS Tunneling Data Exfiltration",
            category="Network",
            threat="Data Exfiltration via DNS Tunneling",
            severity="HIGH",
            base_confidence=0.91,
            mitre_technique="T1071.004 - DNS",
            conditions=[
                Condition(field="dns_tunneling_indicators", operator="is_true", description="High frequency of unusually long subdomains with high entropy"),
                Condition(field="unusual_outbound_traffic", operator="is_true", description="Elevated outbound network volume"),
            ],
            min_conditions_match=1,
            explanation_template="Volumetric queries for randomized subdomains (e.g. base64-encoded strings under an external domain) is a hallmark of covert DNS tunneling for data exfiltration or C2.",
            recommendations=[
                "Sinkhole the suspicious root domain on internal recursive DNS servers.",
                "Enforce DNS inspection on perimeter firewalls to drop high-entropy TXT/NULL queries.",
                "Trace internal source IP issuing the DNS requests and isolate the host from LAN."
            ]
        ),
        Rule(
            id="NET-002",
            name="High-Volume Outbound Data Exfiltration",
            category="Network",
            threat="Data Exfiltration Indicators",
            severity="CRITICAL",
            base_confidence=0.89,
            mitre_technique="T1048 - Exfiltration Over Alternative Protocol",
            conditions=[
                Condition(field="large_data_transfer", operator="is_true", description="Unusually large outbound transfer volume (Gigabytes)"),
                Condition(field="unknown_external_ip", operator="is_true", description="Destination is an unclassified or unmonitored external endpoint"),
            ],
            explanation_template="Sudden burst of substantial outbound traffic to an unknown external server strongly indicates unauthorized data staging and intellectual property theft.",
            recommendations=[
                "Sever outbound egress connectivity for the sending machine immediately.",
                "Capture netflow and packet traces to analyze payload content and destination hosting provider.",
                "Inspect file system logs on the source host for recent archive generation (.zip, .7z, .tar)."
            ]
        ),
        Rule(
            id="NET-003",
            name="Command & Control (C2) Periodic Beaconing",
            category="Network",
            threat="Botnet / C2 Beaconing",
            severity="HIGH",
            base_confidence=0.87,
            mitre_technique="T1071.001 - Web Protocols",
            conditions=[
                Condition(field="c2_beaconing", operator="is_true", description="Periodic outbound HTTPS/TCP heartbeat connections with regular jitter"),
                Condition(field="unknown_external_ip", operator="is_true", description="Connection destination not belonging to recognized CDNs or cloud providers"),
            ],
            min_conditions_match=1,
            explanation_template="Consistent outbound communication at strict intervals to external hosts indicates active Trojan or malware beaconing to a command-and-control server.",
            recommendations=[
                "Add destination IP and domain to corporate firewall and EDR blocklists.",
                "Identify the operating system process holding the open socket using netstat/lsof.",
                "Capture memory dump of the associated process for malware string extraction."
            ]
        ),
        Rule(
            id="NET-004",
            name="Internal Reconnaissance & Port Scanning",
            category="Network",
            threat="Internal Network Reconnaissance",
            severity="MEDIUM",
            base_confidence=0.83,
            mitre_technique="T1046 - Network Service Discovery",
            conditions=[
                Condition(field="suspicious_port_activity", operator="is_true", description="High count of TCP SYN packets across sequential or common service ports"),
                Condition(field="unexpected_connections", operator="is_true", description="Attempts to connect to multiple internal RFC1918 addresses"),
            ],
            min_conditions_match=1,
            explanation_template="Rapid sequential port connection attempts to internal hosts indicates automated network scanning tools (nmap, masscan) probing for lateral movement paths.",
            recommendations=[
                "Isolate the scanning endpoint at the switch port / 802.1X VLAN level.",
                "Review running processes on the host to detect unauthorized scanner executables.",
                "Inspect honeypot traps or canary tokens on the scanned subnets."
            ]
        ),
        Rule(
            id="NET-005",
            name="Traffic to Known Tor Exit Node or Proxy",
            category="Network",
            threat="Suspicious Anonymized Proxy Traffic",
            severity="HIGH",
            base_confidence=0.85,
            mitre_technique="T1090.003 - Tor",
            conditions=[
                Condition(field="tor_or_proxy_traffic", operator="is_true", description="Outbound or inbound connection matched against public Tor exit node list"),
            ],
            explanation_template="Traffic directly contacting known Tor relays or commercial anonymizing proxies violates corporate defensive visibility policies and suggests evasion.",
            recommendations=[
                "Block Tor directory authorities and published exit node lists at edge firewall.",
                "Identify user identity and process making the anonymized connection.",
                "Perform forensic examination of the endpoint for unauthorized VPN or proxy software."
            ]
        ),
        Rule(
            id="NET-006",
            name="Denial of Service / SYN Flood Traffic Spike",
            category="Network",
            threat="Denial-of-Service Indicators",
            severity="HIGH",
            base_confidence=0.86,
            mitre_technique="T1498 - Network Denial of Service",
            conditions=[
                Condition(field="dos_traffic_spike", operator="is_true", description="Severe spike in connection requests or bandwidth exhaustion"),
                Condition(field="high_cpu_usage", operator="is_true", description="Perimeter gateway or web server CPU at 100% capacity"),
            ],
            min_conditions_match=1,
            explanation_template="Extreme volumetric traffic spike coupled with resource exhaustion indicates an incoming volumetric or protocol-level Denial of Service attack.",
            recommendations=[
                "Engage upstream ISP or cloud DDoS mitigation shield (Cloudflare, AWS Shield).",
                "Enable SYN cookies and rate limiting on edge load balancers.",
                "Blackhole or geoblock non-essential foreign traffic sources temporarily."
            ]
        ),
        Rule(
            id="NET-007",
            name="ARP Spoofing / Man-in-the-Middle Attempt",
            category="Network",
            threat="ARP Spoofing / MitM Attack",
            severity="HIGH",
            base_confidence=0.89,
            mitre_technique="T1557.002 - ARP Cache Poisoning",
            conditions=[
                Condition(field="arp_spoofing_detected", operator="is_true", description="Duplicate MAC addresses claiming gateway IP address"),
            ],
            explanation_template="Gratuitous ARP messages attempting to redirect local subnet traffic through an unauthorized host signifies active local sniffing or tampering.",
            recommendations=[
                "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on managed access switches.",
                "Track down physical switch port associated with rogue MAC address and disable port.",
                "Inspect machines on the broadcast domain for ettercap, arpspoof, or scapy scripts."
            ]
        ),
        Rule(
            id="NET-008",
            name="Suspicious Inbound Connection on High-Risk Admin Port",
            category="Network",
            threat="Exposed Administrative Service Probe",
            severity="MEDIUM",
            base_confidence=0.79,
            mitre_technique="T1190 - Exploit Public-Facing Application",
            conditions=[
                Condition(field="unknown_external_ip", operator="is_true", description="Connection from untrusted external IP address"),
                Condition(field="suspicious_port_activity", operator="is_true", description="Inbound attempts on RDP (3389), SSH (22), or SMB (445)"),
            ],
            explanation_template="Direct external connections to administrative services like RDP, SMB, or SSH suggest internet-wide automated crawlers seeking unpatched entry points.",
            recommendations=[
                "Immediately restrict admin port access to internal corporate VPN or zero-trust bastion.",
                "Review host firewall rules to prevent raw public interface exposure.",
                "Audit successful authentications on that service over the preceding 24 hours."
            ]
        ),

        # =========================================================================
        # 3. SYSTEM & ENDPOINT (SYS-001 to SYS-010)
        # =========================================================================
        Rule(
            id="SYS-001",
            name="Ransomware Bulk File Encryption Activity",
            category="System",
            threat="Ransomware Indicators",
            severity="CRITICAL",
            base_confidence=0.96,
            mitre_technique="T1486 - Data Encrypted for Impact",
            conditions=[
                Condition(field="suspicious_file_activity", operator="is_true", description="High-frequency file renames, deletions, or mass extensions (.locked, .enc)"),
                Condition(field="high_cpu_usage", operator="is_true", description="Intense CPU utilization driven by storage cryptographic operations"),
            ],
            explanation_template="Rapid mass modification and renaming of document files accompanied by high continuous CPU usage is an acute indicator of active ransomware encryption.",
            recommendations=[
                "Disconnect the affected host from network cables and Wi-Fi instantly to stop lateral spread.",
                "Do NOT reboot the system immediately; volatile memory holds encryption keys.",
                "Preserve offline immutable backups and verify restore integrity.",
                "Alert incident response commander and check for ransom note drops."
            ]
        ),
        Rule(
            id="SYS-002",
            name="Defense Evasion: Security Tools / Antivirus Disabled",
            category="Endpoint",
            threat="Defense Evasion / Tampering",
            severity="CRITICAL",
            base_confidence=0.93,
            mitre_technique="T1562.001 - Disable or Modify Tools",
            conditions=[
                Condition(field="antivirus_disabled", operator="is_true", description="Endpoint protection agent or real-time protection stopped"),
            ],
            explanation_template="Unexpected termination or disabling of security defenses is a primary tactical step taken by attackers prior to executing malware payloads.",
            recommendations=[
                "Re-enable endpoint security agent immediately via administrative orchestrator.",
                "Audit administrative audit logs to identify who or what script stopped the service.",
                "Perform full offline memory and disk triage scan on the endpoint."
            ]
        ),
        Rule(
            id="SYS-003",
            name="Living-off-the-Land (LotL) Binary Abuse",
            category="System",
            threat="Living-off-the-Land Binary Abuse",
            severity="HIGH",
            base_confidence=0.88,
            mitre_technique="T1218 - System Binary Proxy Execution",
            conditions=[
                Condition(field="lotl_execution", operator="is_true", description="Legitimate system tools (powershell.exe, certutil.exe, mshta.exe) invoked with network download arguments"),
            ],
            explanation_template="Adversaries abuse pre-installed operating system binaries to download external payloads or bypass application whitelisting policies.",
            recommendations=[
                "Terminate the suspicious parent process and its child subprocess trees.",
                "Enable PowerShell ScriptBlock Logging and Constrained Language Mode.",
                "Enforce Application Control (WDAC / AppLocker) rules restricting script interpreters."
            ]
        ),
        Rule(
            id="SYS-004",
            name="Persistence via Scheduled Task or Cron Creation",
            category="System",
            threat="Persistence Mechanism Established",
            severity="HIGH",
            base_confidence=0.86,
            mitre_technique="T1053 - Scheduled Task/Job",
            conditions=[
                Condition(field="unexpected_startup_program", operator="is_true", description="New task scheduled to run at system boot or on recurring timer"),
                Condition(field="unknown_executable", operator="is_true", description="Task invokes an unverified executable or script in temp directories"),
            ],
            min_conditions_match=1,
            explanation_template="Creation of automated startup tasks executing unverified binaries provides the adversary persistence across system reboots.",
            recommendations=[
                "Inspect task properties and delete the rogue scheduled task / cron entry.",
                "Locate and hash the referenced payload file, submit hash to VirusTotal / threat intel.",
                "Audit event ID 4698 (A scheduled task was created)."
            ]
        ),
        Rule(
            id="SYS-005",
            name="Persistence via Registry Run Key Modification",
            category="System",
            threat="Persistence via Registry Run Key",
            severity="HIGH",
            base_confidence=0.85,
            mitre_technique="T1547.001 - Registry Run Keys / Startup Folder",
            conditions=[
                Condition(field="registry_persistence", operator="is_true", description="HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry added"),
            ],
            explanation_template="Addition of registry run keys ensures malicious code launches each time any user logs into the workstation.",
            recommendations=[
                "Delete the unauthorized registry value from the Run/RunOnce key.",
                "Review the executable pointed to by the value and quarantine it.",
                "Enable Sysmon Event ID 12/13 monitoring for Registry modifications."
            ]
        ),
        Rule(
            id="SYS-006",
            name="Volume Shadow Copy Deletion",
            category="System",
            threat="Shadow Copy Deletion / Anti-Recovery Action",
            severity="CRITICAL",
            base_confidence=0.95,
            mitre_technique="T1490 - Inhibit System Recovery",
            conditions=[
                Condition(field="shadow_copy_deleted", operator="is_true", description="Execution of 'vssadmin delete shadows' or 'wmic shadowcopy delete'"),
            ],
            explanation_template="Wiping volume shadow copies is done to inhibit system recovery and is almost universally associated with impending or ongoing ransomware deployment.",
            recommendations=[
                "Immediately declare major incident and isolate the host from all enterprise networks.",
                "Check central backup repositories for immediate isolation/air-gapping.",
                "Kill the invoking process tree and preserve memory image."
            ]
        ),
        Rule(
            id="SYS-007",
            name="Process Injection / Memory Hollowing",
            category="System",
            threat="Process Injection / Memory Hollowing",
            severity="CRITICAL",
            base_confidence=0.91,
            mitre_technique="T1055 - Process Injection",
            conditions=[
                Condition(field="process_injection_detected", operator="is_true", description="Process memory allocated with PAGE_EXECUTE_READWRITE across boundaries"),
            ],
            explanation_template="Writing executable code into legitimate system processes (such as svchost.exe or explorer.exe) allows malware to disguise its presence.",
            recommendations=[
                "Terminate the hollowed process and trace the initiating parent process.",
                "Collect memory triage dump using WinPmem or LiME.",
                "Perform full EDR root-cause analysis on preceding file writes."
            ]
        ),
        Rule(
            id="SYS-008",
            name="Unsigned Process with High CPU / Crypto-mining Signature",
            category="System",
            threat="Suspicious Process / Cryptominer",
            severity="MEDIUM",
            base_confidence=0.82,
            mitre_technique="T1496 - Resource Hijacking",
            conditions=[
                Condition(field="unknown_process", operator="is_true", description="Unsigned or unrecognized executable"),
                Condition(field="high_cpu_usage", operator="is_true", description="Continuous high CPU or GPU utilization exceeding 90%"),
            ],
            explanation_template="Unsigned binary consuming continuous peak processing capacity is classic behavior of illicit cryptocurrency mining malware.",
            recommendations=[
                "Kill the process and delete the binary from disk.",
                "Review how the binary was placed on the system (download history, scheduled tasks).",
                "Inspect outbound connection destinations for known mining pool stratums."
            ]
        ),
        Rule(
            id="SYS-009",
            name="Suspicious Obfuscated PowerShell Execution",
            category="System",
            threat="Obfuscated Script Execution",
            severity="HIGH",
            base_confidence=0.88,
            mitre_technique="T1059.001 - PowerShell",
            conditions=[
                Condition(field="obfuscated_powershell", operator="is_true", description="PowerShell launched with -EncodedCommand or heavy base64 strings"),
            ],
            explanation_template="Heavily obfuscated or base64-encoded command lines are routinely used to bypass static antivirus string matching.",
            recommendations=[
                "Decode the base64 command block using defensive tools (e.g. CyberChef) to inspect payload intent.",
                "Check for dropped scripts in %TEMP% or %APPDATA% directories.",
                "Review process ancestry to understand what spawned PowerShell."
            ]
        ),
        Rule(
            id="SYS-010",
            name="Unauthorized Kernel Driver Load",
            category="Endpoint",
            threat="Bring Your Own Vulnerable Driver (BYOVD)",
            severity="CRITICAL",
            base_confidence=0.94,
            mitre_technique="T1068 - Exploitation for Privilege Escalation",
            conditions=[
                Condition(field="kernel_driver_loaded", operator="is_true", description="Unrecognized third-party or vulnerable signed kernel driver loaded into ring 0"),
            ],
            explanation_template="Adversaries drop known vulnerable signed drivers to bypass driver signature enforcement and disable EDR sensors from ring 0.",
            recommendations=[
                "Enable Hypervisor-Protected Code Integrity (HVCI) and Microsoft Vulnerable Driver Blocklist.",
                "Isolate system and collect kernel memory dump.",
                "Re-image the endpoint; ring-0 tampering cannot be reliably cleansed while live."
            ]
        ),

        # =========================================================================
        # 4. APPLICATION & WEB (APP-001 to APP-006)
        # =========================================================================
        Rule(
            id="APP-001",
            name="SQL Injection (SQLi) Inbound Attack Pattern",
            category="Application",
            threat="SQL Injection Attempt",
            severity="HIGH",
            base_confidence=0.90,
            mitre_technique="T1190 - Exploit Public-Facing Application",
            conditions=[
                Condition(field="sqli_patterns_detected", operator="is_true", description="Payload containing UNION SELECT, OR 1=1, or SQL comment syntax in parameters"),
            ],
            explanation_template="Structured query parameters containing SQL syntax indicate an attacker attempting to manipulate backend database queries or dump schema data.",
            recommendations=[
                "Verify that all database queries utilize parameterized prepared statements or ORM abstractions.",
                "Deploy WAF rules to sanitize and drop SQL metacharacters in query strings and headers.",
                "Audit database user account privileges to enforce least-privilege access."
            ]
        ),
        Rule(
            id="APP-002",
            name="Cross-Site Scripting (XSS) Injection Pattern",
            category="Application",
            threat="Cross-Site Scripting (XSS)",
            severity="MEDIUM",
            base_confidence=0.81,
            mitre_technique="T1059.007 - JavaScript",
            conditions=[
                Condition(field="xss_patterns_detected", operator="is_true", description="Unsanitized script tags or event handlers (<script>, onload=, javascript:) in web input"),
            ],
            explanation_template="Injection of HTML markup and JavaScript into input fields threatens application users with session hijacking and UI redressing.",
            recommendations=[
                "Implement strict Content-Security-Policy (CSP) headers without 'unsafe-inline'.",
                "Ensure contextual output encoding on all user-supplied content.",
                "Mark all authentication session cookies with HttpOnly and SameSite=Strict flags."
            ]
        ),
        Rule(
            id="APP-003",
            name="Remote Code Execution (RCE) Probe",
            category="Application",
            threat="Remote Code Execution Attempt",
            severity="CRITICAL",
            base_confidence=0.93,
            mitre_technique="T1203 - Exploitation for Client Execution",
            conditions=[
                Condition(field="rce_probe_detected", operator="is_true", description="OS command chaining characters (; | & `) or deserialization gadgets in HTTP payload"),
            ],
            explanation_template="Supplying shell metacharacters or deserialization payloads to web endpoints indicates an active attempt to execute arbitrary commands on the server.",
            recommendations=[
                "Disable dynamic shell command execution functions (system, exec, popen, eval).",
                "Patch web application runtime dependencies immediately against known CVEs.",
                "Confine application process inside rootless Docker container or read-only container file system."
            ]
        ),
        Rule(
            id="APP-004",
            name="Directory / Path Traversal Attack",
            category="Application",
            threat="Path Traversal / Arbitrary File Read",
            severity="HIGH",
            base_confidence=0.87,
            mitre_technique="T1005 - Data from Local System",
            conditions=[
                Condition(field="path_traversal_patterns", operator="is_true", description="File path parameters containing '../..' or '/etc/passwd' or 'windows/win.ini'"),
            ],
            explanation_template="Supplying path traversal sequences allows unauthorized attackers to escape web roots and view system configuration or credential files.",
            recommendations=[
                "Use path canonicalization and validate that resolved paths reside inside the designated base directory.",
                "Never pass unvalidated user input directly to filesystem APIs.",
                "Run the web server process with minimal read permissions on system files."
            ]
        ),
        Rule(
            id="APP-005",
            name="Server-Side Request Forgery (SSRF) Cloud Metadata Probe",
            category="Application",
            threat="Server-Side Request Forgery (SSRF)",
            severity="CRITICAL",
            base_confidence=0.92,
            mitre_technique="T1078.004 - Cloud Accounts",
            conditions=[
                Condition(field="ssrf_probe_detected", operator="is_true", description="Web requests forcing server to fetch 169.254.169.254 cloud metadata endpoints"),
            ],
            explanation_template="Probing the 169.254.169.254 cloud metadata service is the standard vector to extract temporary IAM role credentials and cloud API keys.",
            recommendations=[
                "Enforce IMDSv2 (token-based session) on AWS EC2 or equivalent on GCP/Azure.",
                "Implement network egress firewalls preventing application containers from reaching link-local IP 169.254.169.254.",
                "Validate and allowlist all outbound URLs requested by the server."
            ]
        ),
        Rule(
            id="APP-006",
            name="API Broken Object Level Authorization (BOLA / IDOR)",
            category="Application",
            threat="API BOLA / Unauthorized Data Access",
            severity="HIGH",
            base_confidence=0.84,
            mitre_technique="T1530 - Data from Cloud Storage Object",
            conditions=[
                Condition(field="bola_enumeration_detected", operator="is_true", description="Single user session sequentially requesting numerical or UUID resources of other tenants"),
            ],
            explanation_template="Iterating through numeric or predictable object IDs without session ownership checks indicates exploitation of broken object level authorization.",
            recommendations=[
                "Enforce object-level ownership checks at the database query layer.",
                "Replace predictable sequential IDs with cryptographically random UUIDv4.",
                "Apply strict per-user API rate limits."
            ]
        ),

        # =========================================================================
        # 5. EMAIL & SOCIAL ENGINEERING (EMAIL-001 to EMAIL-005)
        # =========================================================================
        Rule(
            id="EMAIL-001",
            name="Spearphishing Email with Typosquatted Domain",
            category="Email",
            threat="Phishing / Brand Impersonation",
            severity="HIGH",
            base_confidence=0.89,
            mitre_technique="T1566.002 - Spearphishing Link",
            conditions=[
                Condition(field="phishing_indicators", operator="is_true", description="Inbound email contains lookalike domain, urgent threat tone, or fake login portal"),
            ],
            explanation_template="Messages disguised as legitimate services (Microsoft 365, HR, Banking) containing deceptively similar domain names are designed to harvest credentials.",
            recommendations=[
                "Quarantine the email tenant-wide and purge from all recipient inboxes.",
                "Block the malicious domain and IP address at the email gateway and web proxy.",
                "Identify any users who clicked the link and immediately reset their credentials."
            ]
        ),
        Rule(
            id="EMAIL-002",
            name="Malicious Email Attachment with Macro/Script Payload",
            category="Email",
            threat="Malware Delivery via Attachment",
            severity="CRITICAL",
            base_confidence=0.93,
            mitre_technique="T1566.001 - Spearphishing Attachment",
            conditions=[
                Condition(field="suspicious_attachment", operator="is_true", description="Attachment with double extension, embedded VBA macro, or container file (.iso, .vhd)"),
            ],
            explanation_template="Inbound email with macro-enabled documents or disk image containers is a common delivery vehicle for loaders, info-stealers, or ransomware.",
            recommendations=[
                "Block attachments containing executable formats (.iso, .vhd, .exe, .scr, .hta) at email gateway.",
                "Enforce Microsoft Office Group Policy disabling macros in documents downloaded from the Internet.",
                "Perform endpoint scan on any host where the attachment was downloaded or opened."
            ]
        ),
        Rule(
            id="EMAIL-003",
            name="Business Email Compromise (BEC) / CEO Fraud",
            category="Email",
            threat="Business Email Compromise (BEC)",
            severity="HIGH",
            base_confidence=0.86,
            mitre_technique="T1656 - Impersonation",
            conditions=[
                Condition(field="bec_impersonation", operator="is_true", description="Email display name spoofing corporate executive requesting urgent wire transfer or gift cards"),
            ],
            explanation_template="Impersonating senior leadership requesting urgent out-of-band financial transactions is standard social engineering to circumvent financial controls.",
            recommendations=[
                "Verify any wire transfer request with the executive in person or via verified secondary phone call.",
                "Configure external sender warning banners at the email gateway.",
                "Enforce strict DMARC, DKIM, and SPF validation policies with p=reject."
            ]
        ),
        Rule(
            id="EMAIL-004",
            name="Suspicious Mailbox Forwarding Rule Created",
            category="Email",
            threat="Email Exfiltration via Forwarding Rule",
            severity="HIGH",
            base_confidence=0.90,
            mitre_technique="T1114.003 - Email Forwarding Rule",
            conditions=[
                Condition(field="mailbox_forwarding_rule", operator="is_true", description="New rule created forwarding incoming emails to an external personal address"),
            ],
            explanation_template="Attackers who gain mailbox access frequently configure hidden forwarding rules to continuously exfiltrate sensitive correspondence without ongoing logins.",
            recommendations=[
                "Delete the unauthorized forwarding rule from the user's Exchange / Google mailbox settings.",
                "Audit all emails forwarded by the rule to identify compromised corporate data.",
                "Enforce tenant policy prohibiting auto-forwarding to external domains."
            ]
        ),
        Rule(
            id="EMAIL-005",
            name="Mass Phishing Campaign Received by Multiple Employees",
            category="Email",
            threat="Mass Phishing Campaign",
            severity="MEDIUM",
            base_confidence=0.80,
            mitre_technique="T1566 - Phishing",
            conditions=[
                Condition(field="mass_phishing_campaign", operator="is_true", description="Identical phishing email broadcast to large distribution lists"),
            ],
            explanation_template="Simultaneous distribution of phishing lures across multiple departments indicates an untargeted or broad-spectrum external campaign.",
            recommendations=[
                "Perform administrative message trace and purge all copies from enterprise mailboxes.",
                "Broadcast security advisory alerting staff not to interact with the message.",
                "Submit message headers and URLs to corporate threat intelligence feed."
            ]
        ),

        # =========================================================================
        # 6. CLOUD & IDENTITY PROVIDER (CLOUD-001 to CLOUD-005)
        # =========================================================================
        Rule(
            id="CLOUD-001",
            name="Cloud IAM Role Assumption Anomaly",
            category="Cloud",
            threat="Cloud Privilege Escalation",
            severity="HIGH",
            base_confidence=0.88,
            mitre_technique="T1078.004 - Cloud Accounts",
            conditions=[
                Condition(field="cloud_iam_anomaly", operator="is_true", description="Cross-account role assumption or unexpected STS GetSessionToken invocation"),
            ],
            explanation_template="Unexpected assumption of privileged cloud roles from anomalous IP addresses suggests stolen cloud API credentials or role misconfigurations.",
            recommendations=[
                "Revoke temporary STS session tokens for the assumed role.",
                "Enforce MFA condition on all IAM role assumption policies.",
                "Audit CloudTrail / Activity Log for actions taken during the assumed session."
            ]
        ),
        Rule(
            id="CLOUD-002",
            name="Cloud Storage Bucket Made Public",
            category="Cloud",
            threat="Cloud Data Exposure",
            severity="CRITICAL",
            base_confidence=0.94,
            mitre_technique="T1530 - Data from Cloud Storage Object",
            conditions=[
                Condition(field="public_bucket_exposure", operator="is_true", description="S3 bucket policy or blob container access altered from private to public read/write"),
            ],
            explanation_template="Modifying cloud object storage permissions to allow public anonymous access directly exposes internal data, backups, or logs to the public internet.",
            recommendations=[
                "Enable 'Block Public Access' at the cloud account / organization level immediately.",
                "Revert the bucket policy to strictly authenticated least-privilege.",
                "Review S3 access logs to determine if unauthorized external IPs downloaded files."
            ]
        ),
        Rule(
            id="CLOUD-003",
            name="Cryptomining in Cloud Compute Fleet",
            category="Cloud",
            threat="Cloud Resource Hijacking",
            severity="HIGH",
            base_confidence=0.91,
            mitre_technique="T1496 - Resource Hijacking",
            conditions=[
                Condition(field="cloud_mining_detected", operator="is_true", description="Sudden deployment of GPU/compute-heavy VM instances communicating with crypto mining pools"),
            ],
            explanation_template="Compromised cloud credentials are often used to spin up costly high-performance computing clusters to mine cryptocurrency at the organization's expense.",
            recommendations=[
                "Immediately terminate unauthorized virtual machine instances.",
                "Rotate the compromised cloud IAM access keys and root credentials.",
                "Set AWS Service Quotas / Azure Budget Alerts to prevent unauthorized instance scaling."
            ]
        ),
        Rule(
            id="CLOUD-004",
            name="Bulk Cloud Secret / KMS Key Extraction",
            category="Cloud",
            threat="Credential Access / Secret Exfiltration",
            severity="CRITICAL",
            base_confidence=0.93,
            mitre_technique="T1552 - Unsecured Credentials",
            conditions=[
                Condition(field="bulk_secret_access", operator="is_true", description="High-frequency GetSecretValue or Decrypt requests across multiple distinct secrets"),
            ],
            explanation_template="Automated enumeration and bulk extraction of secrets from AWS Secrets Manager or HashiCorp Vault is done to gather database and API tokens for deep compromise.",
            recommendations=[
                "Disable the API key or IAM role executing the bulk secret downloads.",
                "Assume all accessed secrets are compromised; initiate emergency rotation of database passwords and API tokens.",
                "Audit application code to identify how the calling credential was originally exposed."
            ]
        ),
        Rule(
            id="CLOUD-005",
            name="Sudden Deployment in Unused Cloud Region",
            category="Cloud",
            threat="Anomalous Cloud Infrastructure Provisioning",
            severity="HIGH",
            base_confidence=0.85,
            mitre_technique="T1535 - Unused/Unsupported Cloud Regions",
            conditions=[
                Condition(field="unused_cloud_region", operator="is_true", description="Infrastructure provisioned in geographical region never utilized by the enterprise"),
            ],
            explanation_template="Adversaries frequently launch rogue cloud infrastructure in obscure foreign regions where organizations lack active monitoring sensors.",
            recommendations=[
                "Apply Service Control Policies (SCPs) to deny operations in all unapproved cloud regions.",
                "Terminate unauthorized instances and VPCs in that region.",
                "Investigate the user account or IAM identity that issued the provisioning calls."
            ]
        ),

        # =========================================================================
        # 7. INSIDER & OPERATIONAL RISK (INS-001 to INS-005)
        # =========================================================================
        Rule(
            id="INS-001",
            name="Mass File Deletion by Privileged User",
            category="Insider",
            threat="Mass Data Sabotage / Destruction",
            severity="CRITICAL",
            base_confidence=0.91,
            mitre_technique="T1485 - Data Destruction",
            conditions=[
                Condition(field="mass_file_deletion", operator="is_true", description="Thousands of production files or database tables dropped within minutes"),
            ],
            explanation_template="Rapid mass deletion of core operational files or database repositories strongly suggests intentional sabotage by an insider or compromised admin.",
            recommendations=[
                "Immediately suspend the administrative account's network access.",
                "Initiate emergency point-in-time snapshot restoration from immutable backups.",
                "Preserve forensic disk images and event logs for legal and compliance review."
            ]
        ),
        Rule(
            id="INS-002",
            name="Departing Employee Massive Sensitive Data Download",
            category="Insider",
            threat="Insider Threat / Intellectual Property Theft",
            severity="HIGH",
            base_confidence=0.87,
            mitre_technique="T1083 - File and Directory Discovery",
            conditions=[
                Condition(field="departing_employee_download", operator="is_true", description="Employee with pending resignation downloading abnormal volume of proprietary files"),
            ],
            explanation_template="High-volume downloads of trade secrets, customer CRM lists, or source code repositories by employees nearing termination date is classic insider exfiltration.",
            recommendations=[
                "Coordinate with HR and Legal to accelerate access revocation and conduct exit interview.",
                "Audit DLP and file server access logs for exact file manifests copied.",
                "Enforce endpoint DLP policies preventing file transfers to personal cloud storage."
            ]
        ),
        Rule(
            id="INS-003",
            name="Unauthorized Removable Storage (USB) Exfiltration",
            category="Insider",
            threat="Physical / USB Data Exfiltration",
            severity="HIGH",
            base_confidence=0.86,
            mitre_technique="T1052.001 - Exfiltration over USB",
            conditions=[
                Condition(field="usb_data_transfer", operator="is_true", description="Mass file copy to newly attached unencrypted mass storage device"),
            ],
            explanation_template="Direct transfer of sensitive files to unapproved USB flash drives bypasses network egress inspection and exposes data to loss or theft.",
            recommendations=[
                "Enforce Group Policy / MDM blocking write access to unauthorized removable media.",
                "Inspect Windows Event ID 20001 / 20003 and EDR device control logs.",
                "Request immediate surrender and forensic imaging of the storage device."
            ]
        ),
        Rule(
            id="INS-004",
            name="Security Audit Log Clearing / Tampering",
            category="System",
            threat="Audit Log Tampering / Evidence Destruction",
            severity="CRITICAL",
            base_confidence=0.96,
            mitre_technique="T1070.001 - Clear Windows Event Logs",
            conditions=[
                Condition(field="audit_log_cleared", operator="is_true", description="Security log cleared (Event ID 1102 / 'wevtutil cl Security')"),
            ],
            explanation_template="Explicit clearing of security audit logs is a direct attempt to erase investigative evidence and conceal unauthorized activity.",
            recommendations=[
                "Isolate the host immediately; clearing logs indicates malicious actor attempting to cover tracks.",
                "Cross-reference forwarded logs in central SIEM / syslog collector which preserves tamper-proof records.",
                "Investigate the user identity and process that invoked the clearing utility."
            ]
        ),
        Rule(
            id="INS-005",
            name="Rogue Unauthorized Device on Corporate LAN",
            category="Network",
            threat="Rogue Hardware on Enterprise Network",
            severity="MEDIUM",
            base_confidence=0.82,
            mitre_technique="T1200 - Hardware Additions",
            conditions=[
                Condition(field="rogue_device_detected", operator="is_true", description="New MAC address with unknown OUI requesting DHCP on internal corporate VLAN"),
            ],
            explanation_template="Physical devices attached to wired switchports without 802.1X certificate authentication could be rogue dropboxes or unmanaged personal hardware.",
            recommendations=[
                "Disable switch port administratively and trace physical wall jack location.",
                "Enforce 802.1X network access control (NAC) with certificate-based machine authentication.",
                "Scan the device from a secure bastion to profile open ports and services."
            ]
        )
    ]
    return rules
