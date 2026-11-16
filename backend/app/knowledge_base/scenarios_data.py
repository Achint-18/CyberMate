"""Safe educational simulated attack scenarios for testing CyberMate's expert system.
These scenarios contain ONLY fictional security telemetry and defensive observations.
No offensive attack code or real-world exploitation mechanisms are included.
"""
from typing import Dict, List, Any
from pydantic import BaseModel


class AttackScenario(BaseModel):
    id: str
    title: str
    category: str
    difficulty: str  # "Beginner", "Intermediate", "Advanced"
    description: str
    background_story: str
    simulated_evidence: List[str]
    facts: Dict[str, Any]
    expected_threat: str
    educational_takeaway: str


def get_all_scenarios() -> List[AttackScenario]:
    """Returns the curated set of educational simulated defense scenarios."""
    return [
        AttackScenario(
            id="SCENARIO-ATO",
            title="High-Value Account Takeover Simulation",
            category="Authentication",
            difficulty="Intermediate",
            description="A corporate finance officer's account registers dozens of failed login attempts, followed by a sudden successful login from a foreign IP and an immediate password modification.",
            background_story="At 02:14 AM local time, SIEM sensors logged 24 sequential password guessing failures against 'finance_exec@corp.internal'. At 02:19 AM, a login succeeded from an unrecognized IP in an uncharacteristic region. Within 3 minutes, the user's password was changed and MFA was disabled.",
            simulated_evidence=[
                "Event 4625: 24 consecutive failed logon attempts within 5 minutes",
                "Event 4624: Type 10 (RemoteInteractive) successful logon from IP 198.51.100.44 (ASN: Unknown Hosting)",
                "Directory Audit: User password altered without IT Service Desk ticket",
                "MFA Log: Authenticator app unlinked from profile by current active session"
            ],
            facts={
                "failed_login_count": 24,
                "successful_login_after_failures": True,
                "login_from_unknown_ip": True,
                "login_from_unusual_location": True,
                "password_changed_unexpectedly": True,
                "mfa_disabled": True,
                "new_device_detected": True
            },
            expected_threat="Account Takeover",
            educational_takeaway="Attackers who guess or buy stolen credentials will swiftly consolidate control by neutralizing MFA and changing passwords before the victim awakens."
        ),
        AttackScenario(
            id="SCENARIO-BRUTE-FORCE",
            title="Distributed SSH / Web Brute Force Attempt",
            category="Authentication",
            difficulty="Beginner",
            description="An edge gateway detects 45 failed authentication attempts against single administrative accounts from unclassified external IP ranges.",
            background_story="During routine morning log reviews, SOC analysts observed an influx of SSH authentication failures targeting the root and admin accounts of an externally facing staging server.",
            simulated_evidence=[
                "sshd[19240]: Failed password for invalid user admin from 203.0.113.88 port 51234",
                "sshd[19242]: Failed password for root from 203.0.113.88 port 51236",
                "45 distinct connection attempts recorded within a 12-minute window",
                "Zero successful authentications recorded from source IP"
            ],
            facts={
                "failed_login_count": 45,
                "successful_login_after_failures": False,
                "login_from_unknown_ip": True,
                "multiple_accounts_targeted": False
            },
            expected_threat="Brute Force Attack",
            educational_takeaway="Automated dictionary attacks generate noticeable bursts of failed authentications. If no success follows, the immediate risk is contained, but rate limiting and IP blocking are critical."
        ),
        AttackScenario(
            id="SCENARIO-RANSOMWARE",
            title="Endpoint Ransomware Deployment Simulation",
            category="System",
            difficulty="Advanced",
            description="A developer workstation experiences sudden 100% CPU utilization, thousands of rapid file renames with new extensions, and deletion of volume shadow copies.",
            background_story="At 11:42 AM, an employee opened an unexpected invoice attachment. Within minutes, endpoint agents recorded process 'win_svchost_updater.exe' spawning command line 'vssadmin.exe delete shadows /all /quiet', followed by intense disk I/O altering file headers in user documents.",
            simulated_evidence=[
                "Sysmon ID 1: Process 'vssadmin.exe delete shadows /all /quiet' launched",
                "FSRM Alert: 1,420 files renamed to .enc extension in Documents folder",
                "Performance Monitor: CPU utilization sustained at 99.8% across 8 cores",
                "Security Agent: Windows Defender real-time protection toggled off"
            ],
            facts={
                "suspicious_file_activity": True,
                "shadow_copy_deleted": True,
                "high_cpu_usage": True,
                "antivirus_disabled": True,
                "unknown_process": True
            },
            expected_threat="Ransomware Indicators",
            educational_takeaway="The deletion of shadow copies combined with mass file modifications is the universal indicator of ransomware impact. Immediate network isolation is required to prevent cross-subnet propagation."
        ),
        AttackScenario(
            id="SCENARIO-PHISHING",
            title="Executive Spearphishing & Malicious Attachment",
            category="Email",
            difficulty="Beginner",
            description="Employees receive emails claiming to be from the CFO regarding urgent bonus statements, linking to a lookalike domain and containing macro-enabled spreadsheet.",
            background_story="An external email from 'cfo-announcements@micr0soft-update.corp' bypassed legacy spam filters. The message urged accounting staff to open 'Bonus_Q3_Review.xlsm' and enable macros to calculate their performance incentives.",
            simulated_evidence=[
                "Email Gateway: Inbound sender IP failed SPF/DKIM verification for claimed domain",
                "Message Analysis: Lookalike typosquatted domain 'micr0soft-update.corp'",
                "Attachment Scanner: 'Bonus_Q3_Review.xlsm' contains Auto_Open() VBA macro calling powershell.exe",
                "Multiple recipients reported identical phishing lure within 15 minutes"
            ],
            facts={
                "phishing_indicators": True,
                "suspicious_attachment": True,
                "mass_phishing_campaign": True
            },
            expected_threat="Malware Delivery via Attachment",
            educational_takeaway="Weaponized macro attachments rely on social engineering to trick users into bypassing built-in operating system security warnings."
        ),
        AttackScenario(
            id="SCENARIO-EXFIL",
            title="Stealth DNS Tunneling Data Exfiltration",
            category="Network",
            difficulty="Advanced",
            description="An internal database workstation is transmitting continuous streams of high-entropy TXT DNS queries to an external domain, bypassing firewall HTTP inspection.",
            background_story="Perimeter firewall logs showed zero outbound HTTP or HTTPS connections from the internal database server. However, internal DNS resolver logs revealed 18,000 queries per hour for subdomains like 'aXNkdGZqMzQ...corp-exfil.xyz', with base64 encoded chunks.",
            simulated_evidence=[
                "DNS Resolver Log: 18,400 queries to '*.corp-exfil.xyz' over 3 hours",
                "Entropy Analysis: Subdomain labels contain Shannon entropy of 4.88 (near-random base64)",
                "Host Network Netflow: Source host is classified as a Restricted PCI Database host",
                "Outbound egress bandwidth shows consistent periodic packet bursts"
            ],
            facts={
                "dns_tunneling_indicators": True,
                "unusual_outbound_traffic": True,
                "unknown_external_ip": True
            },
            expected_threat="Data Exfiltration via DNS Tunneling",
            educational_takeaway="When firewalls block direct outbound internet access, adversaries often leverage DNS as a covert egress channel because internal resolvers forward queries to the authoritative server."
        ),
        AttackScenario(
            id="SCENARIO-CLOUD",
            title="Cloud Storage Bucket Public Misconfiguration",
            category="Cloud",
            difficulty="Intermediate",
            description="An S3 backup repository containing customer database dumps has its access control policy switched to allow anonymous public read access.",
            background_story="During an emergency infrastructure migration, an engineer temporarily relaxed access control policies on 's3://corp-db-daily-backups' to test an external integration. CloudTrail recorded the bucket policy alteration, followed within hours by bulk downloads from unauthenticated external IPs.",
            simulated_evidence=[
                "CloudTrail Event: PutBucketPolicy with Principal '*' and Action 's3:GetObject'",
                "S3 Access Log: 45 distinct external IP addresses downloading .sql.gz archives",
                "CSPM Alert: High Severity Public Object Storage detected",
                "Data volume exceeded 120 GB outbound over a single weekend"
            ],
            facts={
                "public_bucket_exposure": True,
                "large_data_transfer": True,
                "unknown_external_ip": True
            },
            expected_threat="Cloud Data Exposure",
            educational_takeaway="Internet-wide port scanners continuously crawl public cloud IP ranges for unauthenticated buckets. Misconfigured cloud storage policies can lead to instant data exposure."
        )
    ]
