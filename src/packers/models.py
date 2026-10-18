"""
Data models, enumerations, and telemetry structures for batch packer detection.
Provides classification types, signature matches, multi-stage transitions,
layered unpack results, and secure memory zeroization.
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
    # M21 Multi-Stage Packer & Advanced Wrapper Extensions
    POWERSHELL_BASE64 = "powershell_base64"
    POWERSHELL_DEFLATE = "powershell_deflate"
    ECHO_DROPPER = "echo_dropper"
    DYNAMIC_TRAMPOLINE = "dynamic_trampoline"
    CHAR_CODE_STUB = "char_code_stub"
    MULTI_LAYER_CONTAINER = "multi_layer_container"


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
    total_input_bytes: int = 0
    decompressed_bytes: int = 0
    entropy_reduction: float = 0.0
    cycles_halted: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signatures_scanned": self.signatures_scanned,
            "packers_detected": self.packers_detected,
            "layers_unpacked": self.layers_unpacked,
            "payload_bytes_recovered": self.payload_bytes_recovered,
            "noise_lines_stripped": self.noise_lines_stripped,
            "total_input_bytes": self.total_input_bytes,
            "decompressed_bytes": self.decompressed_bytes,
            "entropy_reduction": round(self.entropy_reduction, 4),
            "cycles_halted": self.cycles_halted,
        }

    def zeroize(self) -> None:
        """Wipes sensitive counters from memory."""
        self.signatures_scanned = 0
        self.packers_detected = 0
        self.layers_unpacked = 0
        self.payload_bytes_recovered = 0
        self.noise_lines_stripped = 0
        self.total_input_bytes = 0
        self.decompressed_bytes = 0
        self.entropy_reduction = 0.0
        self.cycles_halted = 0


@dataclass
class LayerTransition:
    """Telemetry and provenance record for an individual unpacking transition."""
    depth: int
    from_packer: PackerType
    to_packer: PackerType
    unpacker_strategy: str
    input_entropy: float
    output_entropy: float
    entropy_delta: float
    input_bytes: int
    output_bytes: int
    payload_sha256: str
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "depth": self.depth,
            "from_packer": self.from_packer.value,
            "to_packer": self.to_packer.value,
            "unpacker_strategy": self.unpacker_strategy,
            "input_entropy": round(self.input_entropy, 4),
            "output_entropy": round(self.output_entropy, 4),
            "entropy_delta": round(self.entropy_delta, 4),
            "input_bytes": self.input_bytes,
            "output_bytes": self.output_bytes,
            "payload_sha256": self.payload_sha256,
            "indicators": list(self.indicators),
            "metadata": dict(self.metadata),
        }

    def zeroize(self) -> None:
        """Wipes payload buffers, indicators, and metadata."""
        self.indicators.clear()
        self.metadata.clear()
        if self.payload_sha256:
            self.payload_sha256 = "\x00" * len(self.payload_sha256)
            self.payload_sha256 = ""
        self.input_bytes = 0
        self.output_bytes = 0
        self.input_entropy = 0.0
        self.output_entropy = 0.0
        self.entropy_delta = 0.0


@dataclass
class LayeredUnpackResult:
    """Consolidated outcome of multi-stage recursive unpacking."""
    root_source: str
    final_source: str
    layers_unpacked: int = 0
    transitions: List[LayerTransition] = field(default_factory=list)
    is_packed: bool = False
    primary_packer: PackerType = PackerType.CLEAN_BATCH
    overall_confidence: float = 0.0
    cycle_detected: bool = False
    depth_limit_reached: bool = False
    metrics: PackerMetrics = field(default_factory=PackerMetrics)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_source_len": len(self.root_source),
            "final_source_len": len(self.final_source),
            "layers_unpacked": self.layers_unpacked,
            "transitions": [t.to_dict() for t in self.transitions],
            "is_packed": self.is_packed,
            "primary_packer": self.primary_packer.value,
            "overall_confidence": round(self.overall_confidence, 4),
            "cycle_detected": self.cycle_detected,
            "depth_limit_reached": self.depth_limit_reached,
            "metrics": self.metrics.to_dict(),
        }

    def zeroize(self) -> None:
        """Securely clears internal buffers, decrypted payloads, and indicators."""
        if self.root_source:
            self.root_source = "\x00" * len(self.root_source)
            self.root_source = ""
        if self.final_source:
            self.final_source = "\x00" * len(self.final_source)
            self.final_source = ""
        for t in self.transitions:
            t.zeroize()
        self.transitions.clear()
        self.metrics.zeroize()


@dataclass
class PackerDetectionResult:
    """Consolidated outcome of batch packer signature analysis and extraction."""
    primary_packer: PackerType = PackerType.CLEAN_BATCH
    detected_signatures: List[PackerSignature] = field(default_factory=list)
    is_packed: bool = False
    confidence: float = 0.0
    unpacked_source: Optional[str] = None
    metrics: PackerMetrics = field(default_factory=PackerMetrics)
    layered_result: Optional[LayeredUnpackResult] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "primary_packer": self.primary_packer.value,
            "is_packed": self.is_packed,
            "confidence": round(self.confidence, 4),
            "signature_count": len(self.detected_signatures),
            "signatures": [s.to_dict() for s in self.detected_signatures],
            "has_unpacked_source": self.unpacked_source is not None,
            "metrics": self.metrics.to_dict()
        }
        if self.layered_result:
            data["layered_result"] = self.layered_result.to_dict()
        return data

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
        if self.layered_result:
            self.layered_result.zeroize()
            self.layered_result = None
        self.metrics.zeroize()
