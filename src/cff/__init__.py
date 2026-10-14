"""
Control Flow De-flattening (Anti-CFF) Package for Windows Batch Scripts.
Exports CFF analyzers, state machine models, decompiler linearizers, and metrics.
"""

from .models import (
    CFFPatternType,
    CFFTransition,
    CFFBlockInfo,
    CFFStateMachine,
    DeflatMetrics,
    DeflatResult,
)
from .analyzer import CFFAnalyzer
from .decompiler import CFFLinearizer

__all__ = [
    "CFFPatternType",
    "CFFTransition",
    "CFFBlockInfo",
    "CFFStateMachine",
    "DeflatMetrics",
    "DeflatResult",
    "CFFAnalyzer",
    "CFFLinearizer",
]
