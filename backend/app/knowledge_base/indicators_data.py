"""Indicators catalog for CyberMate.
Structured indicators organized by domain category, providing UI metadata,
descriptions, default values, and fact mappings for the expert system.
"""
from typing import Dict, List, Any
from pydantic import BaseModel


class IndicatorMetadata(BaseModel):
    id: str
    name: str
    category: str
    data_type: str  # "boolean", "number", "string"
    default_value: Any
    description: str
    risk_weight: int  # 1 to 10


def get_all_indicators() -> List[IndicatorMetadata]:
    """Returns the full catalog of observable defensive indicators."""
    return [
        # --- Authentication & Identity ---
        IndicatorMetadata(
            id="failed_login_count",
            name="Failed Login Count",
            category="Authentication",
            data_type="number",
            default_value=0,
            description="Number of consecutive failed authentication attempts recorded for the identity or IP.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="successful_login_after_failures",
            name="Successful Login After Failures",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="A successful authentication event occurred immediately following a sequence of failures.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="login_from_unknown_ip",
            name="Login from Unknown IP",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="Access originated from an unclassified or non-allowlisted external IP address.",
            risk_weight=6
        ),
        IndicatorMetadata(
            id="login_from_unusual_location",
            name="Login from Unusual Location",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="Authentication request from an anomalous country, region, or foreign ASN.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="password_changed_unexpectedly",
            name="Password Changed Unexpectedly",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="User password altered without an authorized self-service or helpdesk ticket.",
            risk_weight=8
        ),
        IndicatorMetadata(
            id="mfa_disabled",
            name="MFA Disabled / Removed",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="Multi-factor authentication method deactivated or removed from user profile.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="new_device_detected",
            name="New Device Detected",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="First-time hardware UUID, unfamiliar browser fingerprint, or novel operating system agent.",
            risk_weight=5
        ),
        IndicatorMetadata(
            id="impossible_travel",
            name="Impossible Travel / Geo-velocity Anomaly",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="Sign-ins from locations separated by distances that cannot be physically crossed in the elapsed time.",
            risk_weight=8
        ),
        IndicatorMetadata(
            id="repeated_mfa_prompts",
            name="Repeated MFA Push Prompts (MFA Fatigue)",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="Rapid bombardment of push notifications sent to user authenticator device.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="multiple_accounts_targeted",
            name="Multiple Accounts Targeted",
            category="Authentication",
            data_type="boolean",
            default_value=False,
            description="Authentication failures spanning dozens of distinct usernames simultaneously.",
            risk_weight=8
        ),

        # --- Network & Perimeter ---
        IndicatorMetadata(
            id="unusual_outbound_traffic",
            name="Unusual Outbound Traffic",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Anomalous spikes or unfamiliar protocols in egress network traffic streams.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="unknown_external_ip",
            name="Connection to Unknown External IP",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Direct connection established to an unindexed, foreign, or suspicious external IP address.",
            risk_weight=6
        ),
        IndicatorMetadata(
            id="large_data_transfer",
            name="Large Outbound Data Transfer",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Massive data egress (gigabytes) to an external host outside regular backup windows.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="suspicious_port_activity",
            name="Suspicious Port Activity / Port Scan",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Rapid sequential SYN packets probing admin ports (22, 3389, 445, 8080) across hosts.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="c2_beaconing",
            name="C2 Periodic Heartbeat / Beaconing",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Repetitive outbound TCP/HTTPS connections at regular time intervals with fixed jitter.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="dns_tunneling_indicators",
            name="DNS Tunneling Signatures",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Bursts of high-entropy TXT or sub-domain DNS queries indicative of covert data channeling.",
            risk_weight=8
        ),
        IndicatorMetadata(
            id="tor_or_proxy_traffic",
            name="Tor / Anonymized Proxy Traffic",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Inbound or outbound network sessions matching known public Tor exit nodes.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="dos_traffic_spike",
            name="Volumetric Traffic Spike / Flood",
            category="Network",
            data_type="boolean",
            default_value=False,
            description="Sudden exponential jump in SYN requests or bandwidth saturating gateway capacity.",
            risk_weight=8
        ),

        # --- System & Endpoint ---
        IndicatorMetadata(
            id="unknown_process",
            name="Unknown / Unsigned Process",
            category="System",
            data_type="boolean",
            default_value=False,
            description="Executable running without valid digital signature or enterprise catalog approval.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="high_cpu_usage",
            name="Abnormal High CPU / GPU Usage",
            category="System",
            data_type="boolean",
            default_value=False,
            description="Persistent 90-100% CPU utilization driven by background or unauthorized binaries.",
            risk_weight=6
        ),
        IndicatorMetadata(
            id="unexpected_startup_program",
            name="Unexpected Startup / Scheduled Task",
            category="System",
            data_type="boolean",
            default_value=False,
            description="New service, registry run key, or cron task configured for automated execution.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="antivirus_disabled",
            name="Antivirus / EDR Protection Disabled",
            category="Endpoint",
            data_type="boolean",
            default_value=False,
            description="Real-time antivirus, EDR sensor, or Windows Defender service terminated or altered.",
            risk_weight=10
        ),
        IndicatorMetadata(
            id="suspicious_file_activity",
            name="Mass File Modification / Renaming",
            category="System",
            data_type="boolean",
            default_value=False,
            description="Extremely rapid file write, delete, and extension modifications typical of ransomware.",
            risk_weight=10
        ),
        IndicatorMetadata(
            id="shadow_copy_deleted",
            name="Volume Shadow Copies Cleared",
            category="System",
            data_type="boolean",
            default_value=False,
            description="Commands like 'vssadmin delete shadows' executed to obstruct disaster recovery.",
            risk_weight=10
        ),
        IndicatorMetadata(
            id="obfuscated_powershell",
            name="Obfuscated / Base64 Script Execution",
            category="System",
            data_type="boolean",
            default_value=False,
            description="PowerShell or shell scripts executed with encoded commands (-EncodedCommand).",
            risk_weight=8
        ),
        IndicatorMetadata(
            id="lotl_execution",
            name="Living-off-the-Land (LotL) Binary Abuse",
            category="System",
            data_type="boolean",
            default_value=False,
            description="Legitimate admin utilities (certutil, mshta, bitsadmin) invoked to download external files.",
            risk_weight=8
        ),

        # --- Account & Access ---
        IndicatorMetadata(
            id="unexpected_account_creation",
            name="Unexpected Account Creation",
            category="Account",
            data_type="boolean",
            default_value=False,
            description="New local or domain user account created outside scheduled provisioning changes.",
            risk_weight=8
        ),
        IndicatorMetadata(
            id="privilege_escalation",
            name="Privilege Escalation Observed",
            category="Account",
            data_type="boolean",
            default_value=False,
            description="Standard user account elevated to Administrators, Domain Admins, or root group.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="audit_log_cleared",
            name="Security Audit Log Cleared",
            category="Account",
            data_type="boolean",
            default_value=False,
            description="System security event log erased (Event ID 1102 / 'wevtutil cl Security').",
            risk_weight=10
        ),

        # --- Application & Web ---
        IndicatorMetadata(
            id="sqli_patterns_detected",
            name="SQL Injection Patterns in Requests",
            category="Application",
            data_type="boolean",
            default_value=False,
            description="Inbound web parameters containing UNION SELECT, OR 1=1, or SQL comment syntax.",
            risk_weight=8
        ),
        IndicatorMetadata(
            id="xss_patterns_detected",
            name="XSS Injection Patterns Detected",
            category="Application",
            data_type="boolean",
            default_value=False,
            description="Inbound user input containing script blocks, onerror handlers, or javascript: payloads.",
            risk_weight=6
        ),
        IndicatorMetadata(
            id="rce_probe_detected",
            name="Remote Code Execution (RCE) Probe",
            category="Application",
            data_type="boolean",
            default_value=False,
            description="HTTP payloads attempting shell metacharacter injection (; | & `) or deserialization.",
            risk_weight=10
        ),
        IndicatorMetadata(
            id="path_traversal_patterns",
            name="Directory / Path Traversal Patterns",
            category="Application",
            data_type="boolean",
            default_value=False,
            description="Inbound path parameters containing '../../' or attempts to read /etc/passwd.",
            risk_weight=8
        ),

        # --- Email & Social Engineering ---
        IndicatorMetadata(
            id="phishing_indicators",
            name="Phishing Indicators in Email",
            category="Email",
            data_type="boolean",
            default_value=False,
            description="Lookalike sender domain, deceptive hyperlinks, or artificial urgency in correspondence.",
            risk_weight=7
        ),
        IndicatorMetadata(
            id="suspicious_attachment",
            name="Suspicious Attachment with Macro/Container",
            category="Email",
            data_type="boolean",
            default_value=False,
            description="Inbound email carrying macro-enabled documents, ISO/VHD disk images, or executable formats.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="mailbox_forwarding_rule",
            name="Hidden External Forwarding Rule Added",
            category="Email",
            data_type="boolean",
            default_value=False,
            description="Inbox rule automatically forwarding company emails to an external third-party address.",
            risk_weight=8
        ),

        # --- Cloud & Insider ---
        IndicatorMetadata(
            id="public_bucket_exposure",
            name="Cloud Storage Bucket Made Public",
            category="Cloud",
            data_type="boolean",
            default_value=False,
            description="S3 bucket or cloud blob container permissions modified to permit anonymous public access.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="bulk_secret_access",
            name="Bulk Cloud Secrets Downloaded",
            category="Cloud",
            data_type="boolean",
            default_value=False,
            description="Rapid programmatic retrieval of numerous secrets from AWS Secrets Manager or HashiCorp Vault.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="mass_file_deletion",
            name="Mass File / Database Table Deletion",
            category="Insider",
            data_type="boolean",
            default_value=False,
            description="Sudden bulk deletion of production repositories or shared departmental file shares.",
            risk_weight=9
        ),
        IndicatorMetadata(
            id="usb_data_transfer",
            name="Mass File Copy to Removable USB Storage",
            category="Insider",
            data_type="boolean",
            default_value=False,
            description="High-volume copy of confidential files to newly connected unencrypted USB drive.",
            risk_weight=8
        )
    ]
