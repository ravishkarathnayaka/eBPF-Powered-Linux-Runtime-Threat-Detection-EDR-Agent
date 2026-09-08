"""
MITRE ATT&CK Enrichment Module for EDR Agent.

Enriches raw detection alerts with standardized MITRE ATT&CK Enterprise matrix
metadata, tactics, techniques, sub-techniques, descriptions, and reference links.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("edr_agent.mitre")

# Standard MITRE ATT&CK Knowledge Base for Linux Endpoint Detections
TACTICS_MAP: Dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

TECHNIQUES_MAP: Dict[str, Dict[str, Any]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "TA0002",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "TA0002",
        "description": "Adversaries may abuse Unix shell commands and scripting interpreters (bash, sh, zsh) to execute arbitrary commands.",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "TA0005",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "T1055.008": {
        "name": "Process Injection: Ptrace System Calls",
        "tactic": "TA0005",
        "description": "Adversaries may use ptrace system calls (e.g. PTRACE_ATTACH, PTRACE_POKETEXT) to modify memory and control execution of other running processes.",
        "url": "https://attack.mitre.org/techniques/T1055/008/",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "TA0004",
        "description": "Adversaries may exploit software vulnerabilities or misconfigurations in an attempt to elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "TA0004",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1548.001": {
        "name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "tactic": "TA0004",
        "description": "Adversaries may abuse setuid or setgid permissions on binaries to execute code with elevated privileges.",
        "url": "https://attack.mitre.org/techniques/T1548/001/",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "TA0004",
        "description": "Adversaries may abuse sudo authorizations or cached sudo credentials to gain elevated privileges.",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "TA0006",
        "description": "Adversaries may attempt to dump credentials from the operating system to obtain account secrets.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1003.008": {
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "TA0006",
        "description": "Adversaries may dump or access Linux password hashes from /etc/shadow or account mappings in /etc/passwd.",
        "url": "https://attack.mitre.org/techniques/T1003/008/",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "TA0011",
        "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "TA0011",
        "description": "Adversaries may use non-application layer protocols (raw TCP/UDP sockets) for interactive command and control communication.",
        "url": "https://attack.mitre.org/techniques/T1095/",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "TA0006",
        "description": "Adversaries may search compromised systems to find and collect unsecured credentials in files.",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1552.004": {
        "name": "Unsecured Credentials: Private Keys",
        "tactic": "TA0006",
        "description": "Adversaries may search for private key files (such as SSH keys under ~/.ssh) to gain unauthorized access.",
        "url": "https://attack.mitre.org/techniques/T1552/004/",
    },
}


class MitreEnricher:
    """
    Enriches alert metadata with ATT&CK information.
    """

    @classmethod
    def enrich(cls, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert dict in-place or return a copy with MITRE ATT&CK taxonomy.
        """
        enriched = dict(alert)
        mitre_meta = enriched.get("mitre_attack", {})
        
        # Support technique passed at root or within mitre_attack dict
        technique_id = mitre_meta.get("technique_id") or enriched.get("technique_id")
        tactic_id = mitre_meta.get("tactic_id") or enriched.get("tactic_id")

        if technique_id:
            tech_info = TECHNIQUES_MAP.get(technique_id, {})
            tech_name = tech_info.get("name", mitre_meta.get("technique_name", "Unknown Technique"))
            tech_desc = tech_info.get("description", mitre_meta.get("technique_description", ""))
            tech_url = tech_info.get("url", f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/")
            
            if not tactic_id:
                tactic_id = tech_info.get("tactic", "TA0002")

            tactic_name = TACTICS_MAP.get(tactic_id, mitre_meta.get("tactic_name", "Unknown Tactic"))

            enriched["mitre_attack"] = {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "technique_id": technique_id,
                "technique_name": tech_name,
                "technique_description": tech_desc,
                "reference_url": tech_url,
            }
        elif tactic_id:
            tactic_name = TACTICS_MAP.get(tactic_id, "Unknown Tactic")
            enriched["mitre_attack"] = {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "technique_id": "N/A",
                "technique_name": "N/A",
                "technique_description": "",
                "reference_url": f"https://attack.mitre.org/tactics/{tactic_id}/",
            }
        else:
            # Fallback if rule doesn't specify MITRE mapping
            enriched["mitre_attack"] = {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "technique_description": TECHNIQUES_MAP["T1059"]["description"],
                "reference_url": TECHNIQUES_MAP["T1059"]["url"],
            }

        return enriched
