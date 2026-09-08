"""
Unit tests for mitre_enricher.py.

Verifies MITRE ATT&CK taxonomy assignment, technique-to-tactic resolution,
and metadata enrichment.
"""

import pytest
from agent.detection.mitre_enricher import MitreEnricher, TECHNIQUES_MAP, TACTICS_MAP


class TestMitreEnricher:
    def test_enrich_known_technique_reverse_shell(self):
        """Verify enrichment of Unix Shell technique (T1059.004)."""
        alert = {
            "rule_id": "RULE-EDR-001",
            "rule_title": "Interactive Reverse Shell Execution",
            "mitre_attack": {
                "technique_id": "T1059.004",
            },
        }
        enriched = MitreEnricher.enrich(alert)
        mitre = enriched["mitre_attack"]

        assert mitre["technique_id"] == "T1059.004"
        assert "Unix Shell" in mitre["technique_name"]
        assert mitre["tactic_id"] == "TA0002"
        assert mitre["tactic_name"] == "Execution"
        assert "attack.mitre.org" in mitre["reference_url"]

    def test_enrich_known_technique_ptrace_injection(self):
        """Verify enrichment of Ptrace Injection technique (T1055.008)."""
        alert = {
            "rule_id": "RULE-EDR-002",
            "technique_id": "T1055.008",
        }
        enriched = MitreEnricher.enrich(alert)
        mitre = enriched["mitre_attack"]

        assert mitre["technique_id"] == "T1055.008"
        assert "Ptrace" in mitre["technique_name"]
        assert mitre["tactic_id"] == "TA0005"
        assert mitre["tactic_name"] == "Defense Evasion"

    def test_enrich_known_technique_privilege_escalation(self):
        """Verify enrichment of Privilege Escalation technique (T1068)."""
        alert = {
            "rule_id": "RULE-EDR-003",
            "mitre_attack": {
                "technique_id": "T1068",
            },
        }
        enriched = MitreEnricher.enrich(alert)
        mitre = enriched["mitre_attack"]

        assert mitre["technique_id"] == "T1068"
        assert mitre["tactic_id"] == "TA0004"
        assert mitre["tactic_name"] == "Privilege Escalation"

    def test_enrich_credential_dumping(self):
        """Verify enrichment of OS Credential Dumping (T1003.008)."""
        alert = {
            "rule_id": "RULE-EDR-004",
            "mitre_attack": {
                "technique_id": "T1003.008",
            },
        }
        enriched = MitreEnricher.enrich(alert)
        mitre = enriched["mitre_attack"]

        assert mitre["technique_id"] == "T1003.008"
        assert mitre["tactic_id"] == "TA0006"
        assert mitre["tactic_name"] == "Credential Access"

    def test_enrich_fallback_on_empty(self):
        """Verify fallback behavior when no MITRE information is specified."""
        alert = {"rule_id": "CUSTOM-001"}
        enriched = MitreEnricher.enrich(alert)
        mitre = enriched["mitre_attack"]

        assert mitre["tactic_id"] == "TA0002"
        assert mitre["technique_id"] == "T1059"
