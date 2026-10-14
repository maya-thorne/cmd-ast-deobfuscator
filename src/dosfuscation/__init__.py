#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Invoke-DOSfuscation Concatenation Heuristic Engine
Domain package providing pattern detection, concatenation unmasking,
and AST transformation passes.
"""

from .models import (
    ConcatenationType,
    ConcatenationPattern,
    DosfuscationMetrics,
    DosfuscationResult,
)
from .concatenation import DosfuscationConcatenationDecoder
from .detector import DosfuscationDetector

__all__ = [
    "ConcatenationType",
    "ConcatenationPattern",
    "DosfuscationMetrics",
    "DosfuscationResult",
    "DosfuscationConcatenationDecoder",
    "DosfuscationDetector",
]
