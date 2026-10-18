"""
Batch Packer and Obfuscator Detection & Unpacking Package.
Exports signature detectors, multi-tier heuristic scanners, multi-stage recursive
unpackers, cryptographic provenance models, and comprehensive telemetry metrics.
"""

from .models import (
    PackerType,
    PackerSignature,
    PackerMetrics,
    PackerDetectionResult,
    LayerTransition,
    LayeredUnpackResult,
)
from .heuristics import PackerHeuristicDetector
from .detector import PackerSignatureDetector
from .engine import MultiStagePackerEngine, compute_shannon_entropy
from .unpacker import PackerUnpacker

__all__ = [
    "PackerType",
    "PackerSignature",
    "PackerMetrics",
    "PackerDetectionResult",
    "LayerTransition",
    "LayeredUnpackResult",
    "PackerHeuristicDetector",
    "PackerSignatureDetector",
    "MultiStagePackerEngine",
    "PackerUnpacker",
    "compute_shannon_entropy",
]
