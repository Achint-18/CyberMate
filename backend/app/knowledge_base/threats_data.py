"""Threat Library knowledge base for CyberMate.
Structured defensive definitions, MITRE ATT&CK references, common indicators,
and defensive remediation strategies for each known threat profile.
"""
from typing import List, Optional
from pydantic import BaseModel


class ThreatProfile(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    mitre_technique: Optional[str] = None
    summary: str
    detailed_description: str
    common_indicators: List[str]
    rule_ids: List[str]
    defensive_actions: List[str]
    detection_strategies: List[str]


def get_all_threat_profiles() -> List[ThreatProfile]:
    """Returns the comprehensive threat catalog for the Threat Library."""
    return [
        ThreatProfile(
            id="THREAT-BRUTE-FORCE",
            name="Brute Force Attack",
            category="Authentication",
            severity="HIGH",
            mitre_technique="T1110.001 - Password Guessing",
            summary="Automated trial-and-error attempts to guess passwords or cryptographic keys.",
            detailed_description="Brute force attacks involve automated scripts submitting numerous password combinations against authentication interfaces. If successful, adversaries gain legitimate access without triggering code vulnerabilities.",
            common_indicators=[
                "Multiple failed login attempts within short time intervals",
                "Repeated 401/403 HTTP status codes on authentication endpoints",
                "Lockout events registered in Active Directory / IAM audit logs"
            ],
            rule_ids=["AUTH-001"],
            defensive_actions=[
                "Implement progressive IP rate limiting and account lockout delays",
                "Enforce multi-factor authentication (MFA) across all identity providers",
                "Deploy CAPTCHA or cryptographic client challenges on repeated failures",
                "Monitor for single IP querying diverse usernames"
            ],
            detection_strategies=[
                "Audit Windows Security Event 4625 (An account failed to log on)",
                "Track authentication failure spikes in SIEM / OpenSearch dashboards",
                "Analyze web access logs for high-frequency POST requests to /login"
            ]
        ),
        ThreatProfile(
            id="THREAT-ACCOUNT-TAKEOVER",
            name="Account Takeover (ATO)",
            category="Authentication",
            severity="CRITICAL",
            mitre_technique="T1110 - Brute Force / Account Access",
            summary="Adversary successfully acquires and uses legitimate user credentials to access enterprise systems.",
            detailed_description="Account Takeover occurs when an external attacker successfully logs in as a legitimate user, typically after credential harvesting, brute forcing, or session token theft. Once inside, they can modify MFA methods, export sensitive messages, or escalate privileges.",
            common_indicators=[
                "Multiple failed logins immediately followed by a successful authentication",
                "Successful sign-in from an unknown IP address or new geographic region",
                "Immediate password change or MFA device alteration after login",
                "Novel device fingerprint accessing sensitive internal portals"
            ],
            rule_ids=["AUTH-002", "AUTH-009"],
            defensive_actions=[
                "Immediately terminate all active sessions and revoke OAuth refresh tokens",
                "Force an out-of-band password reset via verified voice confirmation",
                "Review identity audit logs for modifications to recovery emails or MFA devices",
                "Place the identity in restricted containment status until verified"
            ],
            detection_strategies=[
                "Correlate failed authentication events with subsequent success within 10 minutes",
                "Alert on impossible travel anomalies between consecutive user sessions",
                "Monitor Entra ID / Okta Risky Sign-ins and High-Risk User alerts"
            ]
        ),
        ThreatProfile(
            id="THREAT-CREDENTIAL-STUFFING",
            name="Credential Stuffing",
            category="Authentication",
            severity="HIGH",
            mitre_technique="T1110.004 - Credential Stuffing",
            summary="Automated testing of breached credential pairs across multiple websites and services.",
            detailed_description="Because users frequently reuse passwords, adversaries take leaked credential databases from public breaches and systematically run automated botnets against login endpoints to identify valid accounts.",
            common_indicators=[
                "High baseline of login failures spread across thousands of distinct usernames",
                "Authentication requests originating from large pools of residential proxy IPs",
                "High failure rates (80-99%) typical of blind stuffing tools"
            ],
            rule_ids=["AUTH-003"],
            defensive_actions=[
                "Deploy bot management with device fingerprinting and behavioral challenge",
                "Check user passwords against leaked database services like HaveIBeenPwned",
                "Implement WebAuthn / Passkeys to eliminate password dependency",
                "Enforce tenant-wide password complexity and ban common dictionary terms"
            ],
            detection_strategies=[
                "Calculate ratio of failed logins to successful logins tenant-wide",
                "Analyze user-agent distribution for headless browser signatures (Puppeteer, curl)",
                "Inspect WAF telemetry for distributed IP clusters hitting /api/auth"
            ]
        ),
        ThreatProfile(
            id="THREAT-MFA-FATIGUE",
            name="MFA Fatigue / Push Bombing",
            category="Authentication",
            severity="CRITICAL",
            mitre_technique="T1621 - Multi-Factor Authentication Request Generation",
            summary="Bombarding an authenticated target with incessant mobile push notifications to coerce an accidental approval.",
            detailed_description="Adversaries who possess valid primary credentials generate dozens of continuous MFA push prompts, often late at night or paired with social engineering phone calls, until the exasperated user taps 'Approve' to silence the alerts.",
            common_indicators=[
                "Rapid sequence of MFA push requests generated in rapid succession",
                "MFA request approved at anomalous hours or after multiple prior denials",
                "Sign-in IP geolocated far from user's physical presence"
            ],
            rule_ids=["AUTH-005"],
            defensive_actions=[
                "Migrate identity policies from simple 1-tap push notifications to Number Matching",
                "Enforce rate limiting on MFA push dispatch (e.g., maximum 3 per 15 minutes)",
                "Switch to phishing-resistant FIDO2 hardware keys (YubiKey) for high-risk roles",
                "Educate users to immediately report unsolicited push alerts to the SOC"
            ],
            detection_strategies=[
                "Alert when more than 3 MFA prompts are generated within a 5-minute window for a single identity",
                "Flag authentications where multiple MFA rejections are followed by a quick acceptance"
            ]
        ),
        ThreatProfile(
            id="THREAT-DNS-TUNNELING",
            name="DNS Tunneling Data Exfiltration",
            category="Network",
            threat="Data Exfiltration via DNS Tunneling",
            severity="HIGH",
            mitre_technique="T1071.004 - DNS",
            summary="Encoding unauthorized data or C2 messages within standard DNS query requests.",
            detailed_description="DNS traffic is commonly allowed through enterprise firewalls without deep payload inspection. Attackers abuse this by encoding arbitrary binary data or commands in subdomains queried to an authoritative nameserver they control.",
            common_indicators=[
                "Excessive volume of DNS queries for long subdomains (>50 characters)",
                "High entropy (randomized base32/base64 strings) in requested hostnames",
                "Abnormal volume of TXT, NULL, or CNAME query types"
            ],
            rule_ids=["NET-001"],
            defensive_actions=[
                "Sinkhole malicious apex domains at enterprise recursive DNS servers",
                "Enforce DNS inspection firewalls to inspect domain length and entropy",
                "Block internal endpoints from directly querying public DNS servers (8.8.8.8, 1.1.1.1); force internal DNS resolver"
            ],
            detection_strategies=[
                "Calculate Shannon entropy of subdomains in DNS request logs",
                "Detect outlier client machines sending >10x baseline DNS request volume"
            ]
        ),
        ThreatProfile(
            id="THREAT-DATA-EXFILTRATION",
            name="High-Volume Data Exfiltration",
            category="Network",
            severity="CRITICAL",
            mitre_technique="T1048 - Exfiltration Over Alternative Protocol",
            summary="Unauthorized mass transmission of sensitive data to an external destination.",
            detailed_description="Once an attacker locates valuable intellectual property, customer databases, or financial records, they compress and encrypt the files before transmitting them to external cloud storage, VPS instances, or attacker-controlled servers.",
            common_indicators=[
                "Unusual gigabyte-scale outbound network egress to unclassified external IPs",
                "Outbound data transfers occurring during off-hours (nights and weekends)",
                "Sudden large archive creations (.zip, .7z) in staging directories"
            ],
            rule_ids=["NET-002"],
            defensive_actions=[
                "Sever network connectivity for the transmitting endpoint immediately",
                "Inspect firewall and netflow logs to identify external destination IP and ASN",
                "Review endpoint file activity to inventory exactly which documents were accessed",
                "Enforce strict egress filtering restricting direct outbound connections"
            ],
            detection_strategies=[
                "Alert on egress bandwidth spikes exceeding 3 standard deviations from host baseline",
                "Monitor endpoint archive utilities (7z.exe, rar.exe) run with password arguments"
            ]
        ),
        ThreatProfile(
            id="THREAT-RANSOMWARE",
            name="Ransomware Infection & Encryption",
            category="System",
            severity="CRITICAL",
            mitre_technique="T1486 - Data Encrypted for Impact",
            summary="Malicious software encrypting storage volumes to extort ransom payments.",
            detailed_description="Ransomware operators gain an initial foothold, escalate privileges, discover network shares, delete volume shadow copies to prevent rollback, and then execute rapid cryptographic encryption across all accessible files, appending custom file extensions and dropping ransom notes.",
            common_indicators=[
                "High-frequency file renames and writes replacing headers with encrypted blobs",
                "Execution of 'vssadmin delete shadows' or 'wmic shadowcopy delete'",
                "Security tools or backup services forcibly terminated",
                "High CPU utilization driven by continuous AES/RSA cryptographic operations"
            ],
            rule_ids=["SYS-001", "SYS-006"],
            defensive_actions=[
                "Physically and logically disconnect infected endpoints from LAN immediately",
                "Preserve volatile RAM memory for possible key extraction before power cycling",
                "Verify integrity of offline immutable/air-gapped backups before attempting restores",
                "Engage incident response specialists and notify legal/regulatory stakeholders"
            ],
            detection_strategies=[
                "FSRM file screening for known ransomware extension patterns (.locked, .crypted)",
                "Sysmon Event ID 1 monitoring command lines invoking vssadmin, bcdedit, or wbadmin",
                "EDR behavioral honeypots monitoring canary files in user document folders"
            ]
        ),
        ThreatProfile(
            id="THREAT-DEFENSE-EVASION",
            name="Defense Evasion / Antivirus Tampering",
            category="Endpoint",
            severity="CRITICAL",
            mitre_technique="T1562.001 - Disable or Modify Tools",
            summary="Adversary attempts to neutralize or blind security sensors, antivirus, or EDR agents.",
            detailed_description="To avoid detection during lateral movement or payload execution, attackers leverage administrative access or kernel drivers to stop services, kill agent processes, modify firewall rules, or exclude malicious directories from scanning.",
            common_indicators=[
                "Antivirus or EDR agent service reported stopped or crashed",
                "Add-MpPreference -ExclusionPath executed in PowerShell",
                "Security event logging disabled or audit logs cleared"
            ],
            rule_ids=["SYS-002", "INS-004"],
            defensive_actions=[
                "Re-enable endpoint sensor immediately via central management platform",
                "Isolate the endpoint to prevent unmonitored lateral propagation",
                "Enable tamper protection on all endpoint security clients to prevent local admin stopping",
                "Investigate preceding command history and processes that terminated the service"
            ],
            detection_strategies=[
                "Alert on Windows Event ID 7036 (service entered the stopped state) for security agents",
                "Central SIEM heartbeat loss for active endpoints within 5 minutes"
            ]
        ),
        ThreatProfile(
            id="THREAT-SQL-INJECTION",
            name="SQL Injection (SQLi)",
            category="Application",
            severity="HIGH",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            summary="Manipulation of backend database queries through untrusted user-supplied input.",
            detailed_description="When web applications concatenate user input directly into SQL statements without parameterization, attackers can inject SQL commands (such as UNION SELECT, OR 1=1, or DROP TABLE) to bypass authentication, read confidential tables, or execute database server commands.",
            common_indicators=[
                "Web parameters containing SQL keywords: SELECT, UNION, INSERT, SLEEP, WAITFOR",
                "Database error messages exposed in HTTP response bodies (syntax error, unclosed quotation)",
                "Abnormal query execution times caused by time-based blind SQLi probes"
            ],
            rule_ids=["APP-001"],
            defensive_actions=[
                "Refactor vulnerable queries to use parameterized prepared statements or ORMs",
                "Activate Web Application Firewall (WAF) core rule set for SQLi inspection",
                "Enforce database account least-privilege (revoke DROP, ALTER, and xp_cmdshell)",
                "Sanitize and validate all incoming inputs against strict whitelists"
            ],
            detection_strategies=[
                "Inspect WAF and web server access logs for SQL metacharacter sequences",
                "Alert on database error rate spikes in application performance monitoring (APM)"
            ]
        ),
        ThreatProfile(
            id="THREAT-PHISHING",
            name="Phishing & Social Engineering",
            category="Email",
            severity="HIGH",
            mitre_technique="T1566 - Phishing",
            summary="Deceptive communications masquerading as trustworthy entities to harvest credentials or deliver malware.",
            detailed_description="Phishing messages employ social engineering tactics (urgency, authority, fear of loss) to entice users to click malicious hyperlinks leading to credential harvesting portals or open weaponized attachments containing macros or loaders.",
            common_indicators=[
                "Deceptive display names combined with mismatched external email addresses",
                "Typosquatted domains (e.g. micr0soft-security[.]com)",
                "Attachments containing macros, ISO/VHD images, or password-protected archives",
                "Links directing to recently registered external domains with fake login portals"
            ],
            rule_ids=["EMAIL-001", "EMAIL-002"],
            defensive_actions=[
                "Purge malicious message copies tenant-wide across all employee mailboxes",
                "Block malicious sender domain, IP, and URLs at email gateway and web proxies",
                "Force credential resets for any users who submitted credentials to the phishing portal",
                "Enforce DMARC (p=reject), DKIM, and SPF domain authentication"
            ],
            detection_strategies=[
                "Analyze email authentication headers (Authentication-Results, SPF, DKIM pass/fail)",
                "Correlate URL click logs in EDR / proxy with known malicious reputation lists"
            ]
        ),
        ThreatProfile(
            id="THREAT-CLOUD-EXPOSURE",
            name="Cloud Storage Public Exposure",
            category="Cloud",
            severity="CRITICAL",
            mitre_technique="T1530 - Data from Cloud Storage Object",
            summary="Misconfiguration of cloud object storage permitting anonymous internet access to sensitive files.",
            detailed_description="Permissive bucket policies or ACL misconfigurations in AWS S3, Google Cloud Storage, or Azure Blob Storage allow unauthorized actors or automated internet-wide scanners to enumerate and download proprietary company data, backups, or source code.",
            common_indicators=[
                "Cloud storage bucket policy contains Principal: '*' with Action: 's3:GetObject'",
                "High volume of unauthenticated read requests originating from diverse global IPs",
                "Cloud security posture management (CSPM) alert indicating public resource"
            ],
            rule_ids=["CLOUD-002"],
            defensive_actions=[
                "Enable 'Block Public Access' at cloud organization / root account level immediately",
                "Revert bucket ACLs to private and restrict access via IAM role-based policies",
                "Audit S3 access logs and CloudTrail to determine if unauthorized IP downloaded data",
                "Initiate data breach assessment if personally identifiable information (PII) was exposed"
            ],
            detection_strategies=[
                "Deploy automated CSPM tooling (AWS Security Hub, GuardDuty) for continuous posture scanning",
                "Alert on CloudTrail events: PutBucketPolicy, PutBucketAcl with public grants"
            ]
        ),
        ThreatProfile(
            id="THREAT-INSIDER",
            name="Insider Threat / Data Theft",
            category="Insider",
            severity="HIGH",
            mitre_technique="T1083 - File and Directory Discovery",
            summary="Authorized employees or contractors abusing legitimate access privileges to exfiltrate proprietary assets.",
            detailed_description="Insider threats involve trusted individuals using authorized credentials to copy intellectual property, customer databases, or financial records for personal gain, corporate espionage, or prior to joining a competitor.",
            common_indicators=[
                "Abnormal volume of proprietary file downloads by employees with pending departure dates",
                "Large data transfers to unauthorized removable USB drives or personal cloud storage",
                "Accessing departmental repositories outside the user's standard job scope or working hours"
            ],
            rule_ids=["INS-002", "INS-003"],
            defensive_actions=[
                "Coordinate with HR and Legal to accelerate access revocation upon resignation",
                "Enforce endpoint Data Loss Prevention (DLP) preventing copies to unapproved USB media",
                "Implement least-privilege role-based access control (RBAC) to restrict bulk document downloads",
                "Preserve forensic copies of the employee workstation upon departure"
            ],
            detection_strategies=[
                "Monitor DLP alerts for sensitive keyword matches transferred to external devices",
                "Analyze user and entity behavior analytics (UEBA) for abnormal volume spikes"
            ]
        )
    ]
