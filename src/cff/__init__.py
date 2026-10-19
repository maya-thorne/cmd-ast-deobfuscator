"""
Control Flow De-flattening (Anti-CFF) Package for Windows Batch Scripts.
Exports CFF analyzers, state machine models, loop detectors, dispatcher unrollers,
decompilers, and telemetry structures.
"""

from .models import (
    CFFPatternType,
    CFFLoopType,
    UnrollMode,
    CFFTransition,
    CFFBlockInfo,
    CFFStateMachine,
    CFFLoopInfo,
    CFFUnrollConfig,
    DeflatMetrics,
    DeflatResult,
)
from .analyzer import CFFAnalyzer
from .loop_detector import CFFLoopDetector
from .unroller import CFFDispatcherUnroller
from .decompiler import CFFLinearizer, CFFDecompiler

__all__ = [
    "CFFPatternType",
    "CFFLoopType",
    "UnrollMode",
    "CFFTransition",
    "CFFBlockInfo",
    "CFFStateMachine",
    "CFFLoopInfo",
    "CFFUnrollConfig",
    "DeflatMetrics",
    "DeflatResult",
    "CFFAnalyzer",
    "CFFLoopDetector",
    "CFFDispatcherUnroller",
    "CFFLinearizer",
    "CFFDecompiler",
]
