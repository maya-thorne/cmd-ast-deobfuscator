"""
Reversal and Transposition Deobfuscation Domain Package.
Provides automaton models, pattern detectors, and simulation engines for
Somalifuscator-style reverse strings, pushdown stack automata, and dictionary transpositions.
"""

from .models import (
    ReversalPatternType,
    ReversalLoopSpec,
    TranspositionResult,
    ReversalMetrics,
)
from .automaton import StringReversalAutomaton
from .detector import ReversalPatternDetector

__all__ = [
    "ReversalPatternType",
    "ReversalLoopSpec",
    "TranspositionResult",
    "ReversalMetrics",
    "StringReversalAutomaton",
    "ReversalPatternDetector",
]
