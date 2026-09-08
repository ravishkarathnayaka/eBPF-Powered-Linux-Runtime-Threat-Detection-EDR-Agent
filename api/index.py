"""
Vercel Serverless Function entrypoint for EDR Sensor API.
"""

from http.server import BaseHTTPRequestHandler
import json
import datetime


class handler(BaseHTTPRequestHandler):
    """Handles API requests on Vercel."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        payload = {
            "status": "operational",
            "service": "eBPF Linux EDR Threat Detection Sensor",
            "version": "1.0.0",
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "active_rules": [
                {
                    "id": "RULE-EDR-001",
                    "title": "Interactive Reverse Shell Execution",
                    "mitre": "T1059.004",
                    "severity": "CRITICAL",
                },
                {
                    "id": "RULE-EDR-002",
                    "title": "Process Memory Injection & PTRACE Abuse",
                    "mitre": "T1055.008",
                    "severity": "CRITICAL",
                },
                {
                    "id": "RULE-EDR-003",
                    "title": "Unexpected Root Privilege Escalation",
                    "mitre": "T1068",
                    "severity": "HIGH",
                },
                {
                    "id": "RULE-EDR-004",
                    "title": "Sensitive Credential File Access",
                    "mitre": "T1003.008",
                    "severity": "HIGH",
                },
            ],
        }

        self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))
