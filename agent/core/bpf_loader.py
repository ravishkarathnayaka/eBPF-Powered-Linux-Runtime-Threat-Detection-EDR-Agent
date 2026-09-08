"""
BPF Loader module for eBPF EDR Agent.

Loads and attaches BPF C probes to kernel tracepoints using BCC,
initializes perf ring buffers, and polls raw events into an internal processing queue.
"""

import logging
import os
import queue
import threading
import time
from typing import Any, Callable, List, Optional, Tuple

logger = logging.getLogger("edr_agent.bpf_loader")

# Optional BCC import to allow running in non-Linux or testing environments
try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    BPF = None
    HAS_BCC = False


class BPFLoader:
    """
    Manages the lifecycle of eBPF programs and perf ring buffers.
    """

    def __init__(
        self,
        bpf_dir: str,
        event_queue: queue.Queue,
        include_dir: Optional[str] = None,
        page_cnt: int = 64,
    ):
        self.bpf_dir = os.path.abspath(bpf_dir)
        self.include_dir = os.path.abspath(include_dir) if include_dir else os.path.join(self.bpf_dir, "include")
        self.event_queue = event_queue
        self.page_cnt = page_cnt

        self.bpf_instances: List[Any] = []
        self._is_running = False
        self._poll_threads: List[threading.Thread] = []

    def _load_probe_source(self, filename: str) -> str:
        """Read BPF C source file from disk."""
        filepath = os.path.join(self.bpf_dir, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"BPF probe source not found at: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()

    def _build_cflags(self) -> List[str]:
        """Generate compiler flags including search path for common.h."""
        return [f"-I{self.include_dir}"]

    def _perf_event_callback(self, cpu: int, data: bytes, size: int):
        """Callback invoked by BCC when a kernel perf event is received."""
        try:
            # Place raw bytes into event queue for async worker processing
            self.event_queue.put_nowait(bytes(data))
        except queue.Full:
            logger.warning("Event queue is full. Dropping incoming telemetry event.")
        except Exception as e:
            logger.error(f"Error handling perf event on CPU {cpu}: {e}")

    def load_all_probes(self) -> bool:
        """
        Compiles and loads all EDR BPF probes into the kernel.
        """
        if not HAS_BCC:
            logger.error(
                "BCC (bpfcc) library is not installed or unavailable on this system. "
                "Ensure you are running on Linux with kernel headers and python3-bpfcc installed, "
                "or run in Docker container."
            )
            return False

        probe_files = [
            "execve_monitor.bpf.c",
            "network_monitor.bpf.c",
            "ptrace_monitor.bpf.c",
            "openat_monitor.bpf.c",
        ]

        cflags = self._build_cflags()

        for probe_file in probe_files:
            file_path = os.path.join(self.bpf_dir, probe_file)
            if not os.path.exists(file_path):
                logger.warning(f"Probe file {probe_file} not found, skipping...")
                continue

            logger.info(f"Compiling and loading BPF probe: {probe_file}")
            try:
                src_code = self._load_probe_source(probe_file)
                bpf_obj = BPF(text=src_code, cflags=cflags)
                
                # Open perf ring buffer map 'events'
                if "events" in bpf_obj.tables:
                    bpf_obj["events"].open_perf_buffer(
                        self._perf_event_callback,
                        page_cnt=self.page_cnt
                    )
                    logger.info(f"Opened perf ring buffer for {probe_file}")
                
                self.bpf_instances.append((probe_file, bpf_obj))
            except Exception as e:
                logger.error(f"Failed to compile/attach BPF probe {probe_file}: {e}")
                self.unload_all()
                return False

        logger.info(f"Successfully loaded {len(self.bpf_instances)} BPF probes.")
        return True

    def _poll_worker(self, bpf_obj: Any, name: str):
        """Worker thread loop polling BCC perf buffer."""
        logger.info(f"Started polling worker for {name}")
        while self._is_running:
            try:
                bpf_obj.perf_buffer_poll(timeout=100)
            except Exception as e:
                if self._is_running:
                    logger.error(f"Error polling perf buffer {name}: {e}")
                    time.sleep(0.1)

    def start_polling(self):
        """Spawns polling threads for all loaded BPF instances."""
        if self._is_running:
            return

        self._is_running = True
        for name, bpf_obj in self.bpf_instances:
            t = threading.Thread(
                target=self._poll_worker,
                args=(bpf_obj, name),
                name=f"bpf-poll-{name}",
                daemon=True,
            )
            t.start()
            self._poll_threads.append(t)

        logger.info(f"Started {len(self._poll_threads)} BPF polling threads.")

    def stop_polling(self):
        """Stops all polling threads."""
        self._is_running = False
        for t in self._poll_threads:
            if t.is_alive():
                t.join(timeout=1.0)
        self._poll_threads.clear()
        logger.info("Stopped all BPF polling threads.")

    def unload_all(self):
        """Stops polling and safely detaches and unloads all BPF programs."""
        self.stop_polling()
        for name, bpf_obj in self.bpf_instances:
            try:
                bpf_obj.cleanup()
                logger.info(f"Detached and cleaned up probe: {name}")
            except Exception as e:
                logger.warning(f"Error during cleanup of {name}: {e}")
        self.bpf_instances.clear()
