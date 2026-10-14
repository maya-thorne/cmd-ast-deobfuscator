"""
Batch Packer and Obfuscator Detection & Unpacking Package.
Exports signature detectors, multi-layer unpackers, data models, and telemetry.
"""

from .models import (
    PackerType,
    PackerSignature,
    PackerMetrics,
    PackerDetectionResult,
)
from .detector import PackerSignatureDetector
from .unpacker import PackerUnpacker

__all__ = [
    "PackerType",
    "PackerSignature",
    "PackerMetrics",
    "PackerDetectionResult",
    "PackerSignatureDetector",
    "PackerUnpacker",
]
