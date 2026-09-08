"""
Core telemetry collection and normalization module for EDR agent.
"""

from .event_normalizer import EventNormalizer, EventType
from .bpf_loader import BPFLoader

__all__ = ["EventNormalizer", "EventType", "BPFLoader"]
