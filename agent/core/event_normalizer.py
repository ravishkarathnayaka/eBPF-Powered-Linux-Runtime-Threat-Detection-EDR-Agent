"""
Event Normalizer module for eBPF EDR Agent.

Converts raw binary C-structures emitted by BPF perf ring buffers
into standardized, structured JSON/dict telemetry records.
"""

import ctypes
import datetime
import enum
import logging
import socket
import struct
from typing import Any, Dict, Optional, Union

logger = logging.getLogger("edr_agent.normalizer")

TASK_COMM_LEN = 16
MAX_FILENAME_LEN = 256
MAX_ARGS_LEN = 512
MAX_PATH_LEN = 256


class EventType(enum.IntEnum):
    UNKNOWN = 0
    EXECVE = 1
    CONNECT = 2
    PTRACE = 3
    OPENAT = 4


PTRACE_REQUEST_NAMES = {
    0: "PTRACE_TRACEME",
    1: "PTRACE_PEEKTEXT",
    2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSER",
    4: "PTRACE_POKETEXT",
    5: "PTRACE_POKEDATA",
    6: "PTRACE_POKEUSER",
    7: "PTRACE_CONT",
    8: "PTRACE_KILL",
    9: "PTRACE_SINGLESTEP",
    12: "PTRACE_GETREGS",
    13: "PTRACE_SETREGS",
    16: "PTRACE_ATTACH",
    17: "PTRACE_DETACH",
    0x4206: "PTRACE_SEIZE",
}

OPEN_FLAGS_MAP = {
    0: "O_RDONLY",
    1: "O_WRONLY",
    2: "O_RDWR",
    64: "O_CREAT",
    128: "O_EXCL",
    512: "O_TRUNC",
    1024: "O_APPEND",
}


# Ctypes structures mirroring bpf/include/common.h
class ExecPayload(ctypes.Structure):
    _fields_ = [
        ("filename", ctypes.c_char * MAX_FILENAME_LEN),
        ("args", ctypes.c_char * MAX_ARGS_LEN),
        ("retval", ctypes.c_int32),
    ]


class NetPayload(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("sport", ctypes.c_uint16),
        ("protocol", ctypes.c_uint16),
        ("daddr_v4", ctypes.c_uint32),
        ("saddr_v4", ctypes.c_uint32),
        ("daddr_v6", ctypes.c_uint8 * 16),
        ("saddr_v6", ctypes.c_uint8 * 16),
        ("sock_fd", ctypes.c_int32),
    ]


class PtracePayload(ctypes.Structure):
    _fields_ = [
        ("request", ctypes.c_int64),
        ("target_pid", ctypes.c_uint32),
        ("addr", ctypes.c_uint64),
        ("data", ctypes.c_uint64),
    ]


class OpenatPayload(ctypes.Structure):
    _fields_ = [
        ("filepath", ctypes.c_char * MAX_PATH_LEN),
        ("flags", ctypes.c_int32),
        ("dfd", ctypes.c_int32),
        ("retval", ctypes.c_int32),
    ]


class PayloadUnion(ctypes.Union):
    _fields_ = [
        ("exec", ExecPayload),
        ("net", NetPayload),
        ("ptrace", PtracePayload),
        ("openat", OpenatPayload),
    ]


class EDREventStruct(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("event_type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("payload", PayloadUnion),
    ]


class EventNormalizer:
    """
    Decodes and normalizes raw binary kernel structs into structured telemetry dictionaries.
    """

    @staticmethod
    def _clean_str(raw_bytes: bytes) -> str:
        """Extract null-terminated string and decode UTF-8 safely."""
        if not raw_bytes:
            return ""
        if isinstance(raw_bytes, str):
            return raw_bytes
        null_idx = raw_bytes.find(b"\x00")
        if null_idx != -1:
            raw_bytes = raw_bytes[:null_idx]
        return raw_bytes.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _format_ipv4(addr_int: int) -> str:
        """Convert a 32-bit integer in network byte order to an IPv4 string."""
        try:
            return socket.inet_ntoa(struct.pack("<I", addr_int))
        except Exception:
            return "0.0.0.0"

    @staticmethod
    def _format_ipv6(addr_bytes: Union[bytes, bytearray, ctypes.Array]) -> str:
        """Convert 16-byte buffer to an IPv6 string."""
        try:
            raw = bytes(addr_bytes)
            return socket.inet_ntop(socket.AF_INET6, raw)
        except Exception:
            return "::"

    @classmethod
    def decode_c_struct(cls, data: Union[bytes, bytearray, Any]) -> Optional[EDREventStruct]:
        """
        Converts raw bytes or BCC struct into an EDREventStruct instance.
        """
        if isinstance(data, EDREventStruct):
            return data
        if isinstance(data, (bytes, bytearray)):
            expected_size = ctypes.sizeof(EDREventStruct)
            if len(data) < expected_size:
                logger.warning(
                    f"Received truncated struct buffer: {len(data)} bytes, expected {expected_size}"
                )
                return None
            return EDREventStruct.from_buffer_copy(data[:expected_size])

        # BCC event object duck-typing
        try:
            raw_bytes = bytes(data)
            return EDREventStruct.from_buffer_copy(raw_bytes)
        except Exception as e:
            logger.error(f"Failed to cast object to EDREventStruct: {e}")
            return None

    @classmethod
    def normalize(cls, raw_data: Union[bytes, bytearray, EDREventStruct, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main entry point to normalize raw event input into a standard dictionary.
        Accepts raw bytes, ctypes structs, BCC event objects, or already formatted dicts.
        """
        if isinstance(raw_data, dict):
            # Synthetic event already in dictionary form
            return cls._normalize_dict(raw_data)

        event_struct = cls.decode_c_struct(raw_data)
        if not event_struct:
            return {}

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        comm = cls._clean_str(event_struct.comm)

        event_type_val = event_struct.event_type
        try:
            event_type_name = EventType(event_type_val).name
        except ValueError:
            event_type_name = "UNKNOWN"

        base_event: Dict[str, Any] = {
            "timestamp_ns": int(event_struct.timestamp_ns),
            "timestamp_utc": now_iso,
            "event_type": event_type_name,
            "pid": int(event_struct.pid),
            "tgid": int(event_struct.tgid),
            "ppid": int(event_struct.ppid),
            "uid": int(event_struct.uid),
            "gid": int(event_struct.gid),
            "comm": comm,
        }

        # Decode specific event payloads
        if event_type_val == EventType.EXECVE:
            exec_payload = event_struct.payload.exec
            filename = cls._clean_str(exec_payload.filename)
            args_str = cls._clean_str(exec_payload.args)
            base_event.update({
                "filename": filename,
                "exe": filename,
                "args": args_str,
                "cmdline": f"{filename} {args_str}".strip() if args_str else filename,
                "retval": int(exec_payload.retval),
            })

        elif event_type_val == EventType.CONNECT:
            net_payload = event_struct.payload.net
            family = "IPv4" if net_payload.family == 2 else ("IPv6" if net_payload.family == 10 else "UNKNOWN")
            dst_port = int(net_payload.dport)
            src_port = int(net_payload.sport)

            if net_payload.family == 2:
                dst_ip = cls._format_ipv4(net_payload.daddr_v4)
                src_ip = cls._format_ipv4(net_payload.saddr_v4)
            elif net_payload.family == 10:
                dst_ip = cls._format_ipv6(net_payload.daddr_v6)
                src_ip = cls._format_ipv6(net_payload.saddr_v6)
            else:
                dst_ip = "0.0.0.0"
                src_ip = "0.0.0.0"

            base_event.update({
                "family": family,
                "dest_ip": dst_ip,
                "dst_ip": dst_ip,
                "src_ip": src_ip,
                "dest_port": dst_port,
                "dst_port": dst_port,
                "src_port": src_port,
                "protocol": "TCP" if net_payload.protocol == 6 else "UDP",
                "sock_fd": int(net_payload.sock_fd),
            })

        elif event_type_val == EventType.PTRACE:
            ptrace_payload = event_struct.payload.ptrace
            req_code = int(ptrace_payload.request)
            req_name = PTRACE_REQUEST_NAMES.get(req_code, f"PTRACE_UNKNOWN({req_code})")
            base_event.update({
                "ptrace_request": req_name,
                "ptrace_request_code": req_code,
                "target_pid": int(ptrace_payload.target_pid),
                "addr": hex(ptrace_payload.addr),
                "data": hex(ptrace_payload.data),
            })

        elif event_type_val == EventType.OPENAT:
            openat_payload = event_struct.payload.openat
            filepath = cls._clean_str(openat_payload.filepath)
            flags = int(openat_payload.flags)
            flags_list = [name for bit, name in OPEN_FLAGS_MAP.items() if (flags & bit) == bit]
            base_event.update({
                "filepath": filepath,
                "file_path": filepath,
                "flags": flags,
                "flags_desc": " | ".join(flags_list) if flags_list else "O_RDONLY",
                "dfd": int(openat_payload.dfd),
                "retval": int(openat_payload.retval),
            })

        return base_event

    @classmethod
    def _normalize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize synthetic or partial dictionary inputs."""
        normalized = dict(data)
        if "timestamp_utc" not in normalized:
            normalized["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if "timestamp_ns" not in normalized:
            normalized["timestamp_ns"] = int(datetime.datetime.now().timestamp() * 1e9)

        # Aliases for consistent rule matching
        if "cmdline" not in normalized and "filename" in normalized:
            args = normalized.get("args", "")
            normalized["cmdline"] = f"{normalized['filename']} {args}".strip()
        if "dest_ip" in normalized and "dst_ip" not in normalized:
            normalized["dst_ip"] = normalized["dest_ip"]
        if "dest_port" in normalized and "dst_port" not in normalized:
            normalized["dst_port"] = normalized["dest_port"]
        if "filepath" in normalized and "file_path" not in normalized:
            normalized["file_path"] = normalized["filepath"]
        return normalized
