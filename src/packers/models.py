"""
Data models, enumerations, and telemetry structures for batch packer detection.
Provides classification types, signature matches, and secure memory zeroization.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field


class PackerType(str, Enum):
    """Classification of batch packers, obfuscator engines, and wrapper stubs."""
    OXIDIZ3R = "0xidiz3r"
    SOMALIFUSCATOR = "somalifuscator"
    DOSFUSCATION_PACKER = "invoke_dosfuscation"
    CERTUTIL_BASE64 = "certutil_base64"
    CERTUTIL_HEX = "certutil_hex"
    BAT2EXE_STUB = "bat2exe_stub"
    VBS_DROP_STUB = "vbs_drop_stub"
    GENERIC_CFF_PACKER = "generic_cff"
    CLEAN_BATCH = "clean_batch"


@dataclass
class PackerSignature:
    """Represents an identified batch packer or obfuscator signature pattern."""
    packer_type: PackerType
    name: str
    confidence: float  # 0.0 to 1.0
    indicators: List[str] = field(default_factory=list)
    layer_depth: int = 1
    extracted_payload: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packer_type": self.packer_type.value,
            "name": self.name,
            "confidence": round(self.confidence, 4),
            "indicators": list(self.indicators),
            "layer_depth": self.layer_depth,
            "has_extracted_payload": self.extracted_payload is not None,
            "metadata": dict(self.metadata)
        }


@dataclass
class PackerMetrics:
    """Telemetry counters for packer detection and unpacking pipeline."""
    signatures_scanned: int = 0
    packers_detected: int = 0
    layers_unpacked: int = 0
    payload_bytes_recovered: int = 0
    noise_lines_stripped: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "signatures_scanned": self.signatures_scanned,
            "packers_detected": self.packers_detected,
            "layers_unpacked": self.layers_unpacked,
            "payload_bytes_recovered": self.payload_bytes_recovered,
            "noise_lines_stripped": self.noise_lines_stripped
        }

    def zeroize(self) -> None:
        """Wipes sensitive counters from memory."""
        self.signatures_scanned = 0
        self.packers_detected = 0
        self.layers_unpacked = 0
        self.payload_bytes_recovered = 0
        self.noise_lines_stripped = 0


@dataclass
class PackerDetectionResult:
    """Consolidated outcome of batch packer signature analysis and extraction."""
    primary_packer: PackerType = PackerType.CLEAN_BATCH
    detected_signatures: List[PackerSignature] = field(default_factory=list)
    is_packed: bool = False
    confidence: float = 0.0
    unpacked_source: Optional[str] = None
    metrics: PackerMetrics = field(default_factory=PackerMetrics)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_packer": self.primary_packer.value,
            "is_packed": self.is_packed,
            "confidence": round(self.confidence, 4),
            "signature_count": len(self.detected_signatures),
            "signatures": [s.to_dict() for s in self.detected_signatures],
            "has_unpacked_source": self.unpacked_source is not None,
            "metrics": self.metrics.to_dict()
        }

    def zeroize(self) -> None:
        """Securely clears internal buffers, decrypted payloads, and indicators."""
        if self.unpacked_source is not None:
            self.unpacked_source = "\x00" * len(self.unpacked_source)
            self.unpacked_source = None
        for sig in self.detected_signatures:
            if sig.extracted_payload is not None:
                sig.extracted_payload = "\x00" * len(sig.extracted_payload)
                sig.extracted_payload = None
            sig.indicators.clear()
            sig.metadata.clear()
        self.detected_signatures.clear()
        self.metrics.zeroize()
