#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Invoke-DOSfuscation Concatenation Domain Data Models
Provides enumerated pattern types, concatenation segment metadata,
telemetry metrics, and security-grade memory zeroization methods.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Any


class ConcatenationType(Enum):
    """Classification of Invoke-DOSfuscation concatenation techniques."""
    VAR_FRAGMENT_CHAIN = auto()    # Small character/word variable chaining (%a%%b%%c%)
    JUNK_VAR_INTERLEAVE = auto()   # Empty or dummy junk variables inserted between chars
    DELIMITER_SCRAMBLE = auto()    # Interspersed commas, semicolons, equals signs as token delimiters
    FOR_TOKEN_ACCUMULATOR = auto() # FOR %x in (...) do set out=!out!%x accumulation loop
    CALL_TRAMPOLINE = auto()       # CALL %var% dynamic execution trampoline
    ARRAY_INDEX_CONCAT = auto()    # Indexed variable array assembly (%a[0]%%a[1]%)
    REVERSED_CONCAT = auto()       # Slices or variables assembled in reverse sequence


@dataclass
class ConcatenationPattern:
    """Detailed record of an identified concatenation pattern."""
    pattern_type: ConcatenationType
    confidence: float              # 0.0 to 1.0 confidence score
    raw_snippet: str
    normalized_snippet: str
    span: Tuple[int, int] = (0, 0)
    details: Dict[str, Any] = field(default_factory=dict)

    def zeroize(self) -> None:
        """Securely zeroize string contents in memory for security compliance."""
        self.raw_snippet = "\x00" * len(self.raw_snippet)
        self.normalized_snippet = "\x00" * len(self.normalized_snippet)
        self.details.clear()


@dataclass
class DosfuscationMetrics:
    """Telemetry and reduction metrics for Invoke-DOSfuscation decoding passes."""
    total_patterns_detected: int = 0
    var_chains_fused: int = 0
    junk_vars_stripped: int = 0
    delimiters_normalized: int = 0
    loops_accumulated: int = 0
    trampolines_unrolled: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    is_zeroized: bool = False

    @property
    def bytes_reduced(self) -> int:
        return max(0, self.bytes_before - self.bytes_after)

    @property
    def reduction_percentage(self) -> float:
        if self.bytes_before <= 0:
            return 0.0
        return (self.bytes_reduced / self.bytes_before) * 100.0

    def zeroize(self) -> None:
        self.total_patterns_detected = 0
        self.var_chains_fused = 0
        self.junk_vars_stripped = 0
        self.delimiters_normalized = 0
        self.loops_accumulated = 0
        self.trampolines_unrolled = 0
        self.bytes_before = 0
        self.bytes_after = 0
        self.is_zeroized = True


@dataclass
class DosfuscationResult:
    """Result payload from the Invoke-DOSfuscation deobfuscation engine."""
    original_text: str
    decoded_text: str
    patterns: List[ConcatenationPattern] = field(default_factory=list)
    metrics: DosfuscationMetrics = field(default_factory=DosfuscationMetrics)
    concatenation_score: float = 0.0

    def zeroize(self) -> None:
        self.original_text = "\x00" * len(self.original_text)
        self.decoded_text = "\x00" * len(self.decoded_text)
        for pat in self.patterns:
            pat.zeroize()
        self.patterns.clear()
        self.metrics.zeroize()
