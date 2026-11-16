"""Deterministic Natural Language Security Indicator Extractor for CyberMate.
Translates unstructured security reports into structured facts for the rule engine.
Optionally integrates with LLMs (e.g. Gemini) if configured via environment variables,
with seamless fallback to deterministic semantic regex extraction.
"""
import os
import re
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("cybermate.nlp")


class NaturalLanguageExtractor:
    """Extracts cybersecurity indicators from natural language text."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")

    def extract_facts(self, text: str) -> Tuple[Dict[str, Any], List[str]]:
        """
        Extracts structured security facts from text.
        Returns:
            Tuple[Dict[str, Any], List[str]]: (facts_dict, extracted_indicator_descriptions)
        """
        # Always run deterministic extraction first (or as fallback)
        facts, extracted_descriptions = self._extract_deterministic(text)

        # If LLM API key is present and configured, we can optionally enhance extraction
        if self.api_key:
            try:
                llm_facts, llm_descs = self._extract_with_gemini(text)
                # Merge facts (rule engine remains final arbiter)
                for k, v in llm_facts.items():
                    if k not in facts or facts[k] is False or facts[k] == 0:
                        facts[k] = v
                for d in llm_descs:
                    if d not in extracted_descriptions:
                        extracted_descriptions.append(d)
            except Exception as e:
                logger.warning(f"Optional LLM extraction skipped: {e}")

        return facts, extracted_descriptions

    def _extract_deterministic(self, text: str) -> Tuple[Dict[str, Any], List[str]]:
        facts: Dict[str, Any] = {}
        descriptions: List[str] = []
        lower = text.lower()

        # 1. Failed Login Counts
        # Search for digits near "failed", "attempts", "tries", "times"
        login_count_matches = re.findall(
            r'(\d+)\s*(?:times|failed\s+attempts?|attempts?|tries|logins?)', lower
        )
        if login_count_matches:
            try:
                count = int(login_count_matches[0])
                facts["failed_login_count"] = count
                descriptions.append(f"Detected {count} repeated authentication attempts")
            except ValueError:
                pass
        elif any(phrase in lower for phrase in ["multiple failed", "repeated failed", "many login failures", "brute force", "repeatedly trying"]):
            facts["failed_login_count"] = 10
            descriptions.append("Multiple failed authentication attempts indicated")

        # 2. Successful Login After Failures
        if any(phrase in lower for phrase in [
            "then successfully logged in", "then logged in", "successful login after",
            "finally logged in", "logged in successfully", "eventually logged in",
            "managed to log in", "succeeded in logging in", "successful authentication"
        ]):
            facts["successful_login_after_failures"] = True
            descriptions.append("Successful authentication observed after failures")

        # 3. Unknown IP / Location
        if any(phrase in lower for phrase in ["unknown ip", "unrecognized ip", "foreign ip", "suspicious ip", "strange ip", "external ip"]):
            facts["login_from_unknown_ip"] = True
            facts["unknown_external_ip"] = True
            descriptions.append("Access originated from unknown/foreign IP address")

        if any(phrase in lower for phrase in ["unusual location", "foreign country", "impossible travel", "strange location", "abroad", "different country"]):
            facts["login_from_unusual_location"] = True
            descriptions.append("Authentication from unfamiliar geographical location")

        # 4. Password Changed
        if any(phrase in lower for phrase in ["password changed", "changed password", "password reset", "new password set", "reset credentials"]):
            facts["password_changed_unexpectedly"] = True
            descriptions.append("Unexpected password alteration detected")

        # 5. MFA Disabled / Push Bombing
        if any(phrase in lower for phrase in ["mfa disabled", "disabled mfa", "turned off 2fa", "removed 2fa", "2fa disabled", "disabled two-factor"]):
            facts["mfa_disabled"] = True
            descriptions.append("Multi-factor authentication (MFA/2FA) deactivated")

        if any(phrase in lower for phrase in ["mfa fatigue", "push spam", "push bombing", "repeated mfa", "incessant notifications", "spammed with mfa"]):
            facts["repeated_mfa_prompts"] = True
            descriptions.append("Repeated bombardment of MFA push notifications")

        # 6. Device Anomalies
        if any(phrase in lower for phrase in ["new device", "unknown device", "unrecognized device", "strange browser"]):
            facts["new_device_detected"] = True
            descriptions.append("Novel or unrecognized hardware device detected")

        # 7. Antivirus / EDR Disabled
        if any(phrase in lower for phrase in ["antivirus disabled", "defender disabled", "edr turned off", "antivirus turned off", "security tool disabled", "protection stopped"]):
            facts["antivirus_disabled"] = True
            descriptions.append("Endpoint security / antivirus protection disabled")

        # 8. Ransomware / File Activity
        if any(phrase in lower for phrase in ["ransomware", "files encrypted", "renamed with .locked", "files locked", "ransom note", "files being encrypted"]):
            facts["suspicious_file_activity"] = True
            descriptions.append("Mass file modification or encryption behavior observed")

        # 9. Shadow Copies Cleared
        if any(phrase in lower for phrase in ["shadow copy", "shadow copies", "vssadmin", "delete shadows"]):
            facts["shadow_copy_deleted"] = True
            descriptions.append("Volume shadow copy deletion command executed")

        # 10. Process Anomalies
        if any(phrase in lower for phrase in ["unknown process", "suspicious process", "strange executable", "unknown executable", "suspicious binary"]):
            facts["unknown_process"] = True
            facts["unknown_executable"] = True
            descriptions.append("Unverified or unrecognized process executing")

        if any(phrase in lower for phrase in ["high cpu", "100% cpu", "cpu usage high", "pegging cpu", "miner", "mining"]):
            facts["high_cpu_usage"] = True
            descriptions.append("Abnormal peak CPU or resource utilization")

        # 11. Obfuscated PowerShell / Scripts
        if any(phrase in lower for phrase in ["powershell", "encodedcommand", "base64 script", "obfuscated script"]):
            facts["obfuscated_powershell"] = True
            descriptions.append("Obfuscated or encoded script command execution")

        # 12. Network / Exfiltration / C2
        if any(phrase in lower for phrase in ["large data transfer", "huge outbound", "gigabytes sent", "data exfiltration", "mass data upload"]):
            facts["large_data_transfer"] = True
            facts["unusual_outbound_traffic"] = True
            descriptions.append("Large outbound data transfer observed")

        if any(phrase in lower for phrase in ["beaconing", "c2", "command and control", "heartbeat", "periodic outbound"]):
            facts["c2_beaconing"] = True
            descriptions.append("Command & Control periodic beaconing pattern")

        if any(phrase in lower for phrase in ["dns tunneling", "high-entropy dns", "covert dns", "txt query flood"]):
            facts["dns_tunneling_indicators"] = True
            descriptions.append("Covert DNS tunneling communication indicators")

        if any(phrase in lower for phrase in ["port scan", "port scanning", "syn flood", "syn packets"]):
            facts["suspicious_port_activity"] = True
            descriptions.append("Port scanning or sequential port probing")

        # 13. Web Attacks
        if any(phrase in lower for phrase in ["sql injection", "sqli", "union select", "or 1=1"]):
            facts["sqli_patterns_detected"] = True
            descriptions.append("SQL injection attack string observed")

        if any(phrase in lower for phrase in ["xss", "cross-site scripting", "<script>", "script injection"]):
            facts["xss_patterns_detected"] = True
            descriptions.append("Cross-site scripting (XSS) payload observed")

        if any(phrase in lower for phrase in ["rce", "remote code execution", "command injection"]):
            facts["rce_probe_detected"] = True
            descriptions.append("Remote code execution (RCE) payload signature")

        # 14. Email & Phishing
        if any(phrase in lower for phrase in ["phishing", "fake link", "typosquat", "lookalike domain", "suspicious email"]):
            facts["phishing_indicators"] = True
            descriptions.append("Phishing email or deceptive hyperlink indicators")

        if any(phrase in lower for phrase in ["malicious attachment", "macro", ".xlsm", ".iso attachment", "invoice attachment"]):
            facts["suspicious_attachment"] = True
            descriptions.append("Suspicious email attachment with macro or container payload")

        # 15. Cloud & Insider
        if any(phrase in lower for phrase in ["public bucket", "s3 bucket public", "blob public"]):
            facts["public_bucket_exposure"] = True
            descriptions.append("Cloud storage bucket configured with public anonymous permissions")

        if any(phrase in lower for phrase in ["audit log cleared", "cleared event log", "event log wiped", "wevtutil"]):
            facts["audit_log_cleared"] = True
            descriptions.append("Security event audit logs cleared or tampered")

        if any(phrase in lower for phrase in ["usb", "thumb drive", "removable drive"]):
            facts["usb_data_transfer"] = True
            descriptions.append("Mass file copy to removable USB storage")

        return facts, descriptions

    def _extract_with_gemini(self, text: str) -> Tuple[Dict[str, Any], List[str]]:
        """Optional future LLM extraction hook. Kept strictly deterministic-first."""
        # Prepared for google-genai or httpx integration if key is provided.
        # Fallback is always clean and non-blocking.
        return {}, []
