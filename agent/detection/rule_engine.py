"""
Detection Rule Engine module for EDR Agent.

Parses YAML detection rules and evaluates incoming normalized telemetry events
against tree-structured logical conditions, regex patterns, and MITRE metadata.
"""

import dataclasses
import glob
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Union
import yaml

from .mitre_enricher import MitreEnricher

logger = logging.getLogger("edr_agent.rule_engine")


@dataclasses.dataclass
class DetectionAlert:
    """Represents a generated EDR detection alert."""
    alert_id: str
    timestamp_utc: str
    rule_id: str
    rule_title: str
    severity: str
    description: str
    mitre_attack: Dict[str, Any]
    event: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class RuleEngine:
    """
    Evaluates normalized EDR telemetry against YAML detection rules.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[Dict[str, Any]] = []
        if rules_dir:
            self.load_rules_from_dir(rules_dir)

    def load_rules_from_dir(self, directory: str) -> int:
        """
        Loads all YAML rule files from the specified directory.
        """
        if not os.path.isdir(directory):
            logger.warning(f"Rules directory not found: {directory}")
            return 0

        rule_files = glob.glob(os.path.join(directory, "*.yml")) + glob.glob(
            os.path.join(directory, "*.yaml")
        )

        loaded_count = 0
        for filepath in rule_files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    docs = yaml.safe_load_all(f)
                    for rule in docs:
                        if rule and isinstance(rule, dict) and "id" in rule:
                            self.rules.append(rule)
                            loaded_count += 1
            except Exception as e:
                logger.error(f"Failed to parse rule file {filepath}: {e}")

        logger.info(f"Loaded {loaded_count} detection rules from {directory}")
        return loaded_count

    def add_rule(self, rule_dict: Dict[str, Any]):
        """Directly register a rule dictionary."""
        self.rules.append(rule_dict)

    def clear_rules(self):
        """Clear all loaded rules."""
        self.rules.clear()

    @staticmethod
    def _get_field_value(event: Dict[str, Any], field_path: str) -> Any:
        """
        Extracts value from event using dot-notation or flat key lookup.
        """
        if field_path in event:
            return event[field_path]

        # Nested lookup
        parts = field_path.split(".")
        curr = event
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return None
        return curr

    @classmethod
    def _evaluate_condition(cls, cond: Union[Dict[str, Any], List[Any]], event: Dict[str, Any]) -> bool:
        """
        Recursively evaluates a condition node against the event telemetry.
        """
        if isinstance(cond, list):
            # Implicit AND for lists of conditions
            return all(cls._evaluate_condition(c, event) for c in cond)

        if not isinstance(cond, dict):
            return False

        # Logical Combinators: AND / ALL
        if "and" in cond or "all" in cond:
            sub = cond.get("and") or cond.get("all", [])
            if isinstance(sub, list):
                return all(cls._evaluate_condition(c, event) for c in sub)
            if isinstance(sub, dict):
                return cls._evaluate_condition(sub, event)

        # Logical Combinators: OR / ANY
        if "or" in cond or "any" in cond:
            sub = cond.get("or") or cond.get("any", [])
            if isinstance(sub, list):
                return any(cls._evaluate_condition(c, event) for c in sub)
            if isinstance(sub, dict):
                return cls._evaluate_condition(sub, event)

        # Logical Combinators: NOT
        if "not" in cond:
            return not cls._evaluate_condition(cond["not"], event)

        # Field-level condition
        field = cond.get("field")
        if not field:
            # Maybe map of field: value direct format (e.g. {comm: "bash", uid: 0})
            for k, v in cond.items():
                if k in ("and", "or", "not", "all", "any"):
                    continue
                actual = cls._get_field_value(event, k)
                if isinstance(v, dict):
                    if not cls._evaluate_operator_dict(actual, v):
                        return False
                elif actual != v:
                    return False
            return True

        val = cls._get_field_value(event, field)
        return cls._evaluate_operator_dict(val, cond)

    @classmethod
    def _evaluate_operator_dict(cls, val: Any, cond: Dict[str, Any]) -> bool:
        """Evaluates comparison operators on an extracted field value."""
        # Equality / Not-equal
        if "equals" in cond:
            if str(val).lower() != str(cond["equals"]).lower():
                return False
        if "eq" in cond:
            if val != cond["eq"] and str(val) != str(cond["eq"]):
                return False
        if "not_equals" in cond or "ne" in cond:
            target = cond.get("not_equals", cond.get("ne"))
            if val == target or str(val) == str(target):
                return False

        # Inclusion / Exclusion
        if "in" in cond:
            target_list = cond["in"]
            if isinstance(target_list, list):
                # Check for direct value match or case-insensitive string match
                matched = False
                for item in target_list:
                    if val == item or (isinstance(val, str) and isinstance(item, str) and val.lower() == item.lower()):
                        matched = True
                        break
                if not matched:
                    return False
            else:
                if val not in target_list:
                    return False

        if "not_in" in cond:
            target_list = cond["not_in"]
            if isinstance(target_list, list):
                for item in target_list:
                    if val == item or (isinstance(val, str) and isinstance(item, str) and val.lower() == item.lower()):
                        return False
            else:
                if val in target_list:
                    return False

        # Substring searches
        if "contains" in cond:
            target = str(cond["contains"])
            if not val or target.lower() not in str(val).lower():
                return False

        if "not_contains" in cond:
            target = str(cond["not_contains"])
            if val and target.lower() in str(val).lower():
                return False

        if "startswith" in cond:
            target = str(cond["startswith"])
            if not val or not str(val).startswith(target):
                return False

        if "endswith" in cond:
            target = str(cond["endswith"])
            if not val or not str(val).endswith(target):
                return False

        # Regular Expression
        if "regex_match" in cond or "matches" in cond:
            pattern = cond.get("regex_match", cond.get("matches"))
            if not val or not re.search(pattern, str(val), re.IGNORECASE):
                return False

        # Numeric Comparisons
        if "gt" in cond:
            if val is None or not (val > cond["gt"]):
                return False
        if "gte" in cond:
            if val is None or not (val >= cond["gte"]):
                return False
        if "lt" in cond:
            if val is None or not (val < cond["lt"]):
                return False
        if "lte" in cond:
            if val is None or not (val <= cond["lte"]):
                return False

        return True

    def evaluate(self, event: Dict[str, Any]) -> List[DetectionAlert]:
        """
        Evaluates a normalized event against all active rules and returns alerts.
        """
        alerts: List[DetectionAlert] = []
        if not event:
            return alerts

        event_type = event.get("event_type")

        for rule in self.rules:
            # Check event_type filter if specified by rule
            rule_event_type = rule.get("event_type")
            if rule_event_type:
                if isinstance(rule_event_type, list):
                    if event_type not in rule_event_type and "ALL" not in rule_event_type:
                        continue
                elif isinstance(rule_event_type, str):
                    if rule_event_type != "ALL" and rule_event_type != event_type:
                        continue

            condition = rule.get("condition")
            if not condition:
                continue

            try:
                matched = self._evaluate_condition(condition, event)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.get('id')}: {e}")
                matched = False

            if matched:
                alert_dict = {
                    "alert_id": str(uuid.uuid4()),
                    "timestamp_utc": event.get("timestamp_utc", ""),
                    "rule_id": rule.get("id", "RULE-UNKNOWN"),
                    "rule_title": rule.get("title", rule.get("name", "Unnamed Detection")),
                    "severity": rule.get("severity", "MEDIUM").upper(),
                    "description": rule.get("description", ""),
                    "mitre_attack": rule.get("mitre_attack", {}),
                    "event": event,
                }

                # Enrich with full MITRE taxonomy
                enriched = MitreEnricher.enrich(alert_dict)

                alerts.append(
                    DetectionAlert(
                        alert_id=enriched["alert_id"],
                        timestamp_utc=enriched["timestamp_utc"],
                        rule_id=enriched["rule_id"],
                        rule_title=enriched["rule_title"],
                        severity=enriched["severity"],
                        description=enriched["description"],
                        mitre_attack=enriched["mitre_attack"],
                        event=enriched["event"],
                    )
                )

        return alerts
