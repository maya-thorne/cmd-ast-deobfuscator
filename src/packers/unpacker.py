"""
Batch Packer Unpacker and Payload Extractor.
Wraps MultiStagePackerEngine to provide backward-compatible single-call unpacking,
multi-layer recursive unwrapping, and integration with PackerDetectionResult.
"""

from typing import Optional, List, Dict, Any
from .models import PackerType, PackerDetectionResult, PackerMetrics, LayeredUnpackResult
from .detector import PackerSignatureDetector
from .engine import MultiStagePackerEngine, MAX_UNPACK_LAYERS, MAX_PAYLOAD_SIZE


class PackerUnpacker:
    """
    Automated unpacker for batch packaging wrappers.
    Resolves self-extracting stubs, CertUtil encoding layers, PowerShell stubs,
    and multi-stage dropper cascades by delegating to MultiStagePackerEngine.
    """

    def __init__(
        self,
        detector: Optional[PackerSignatureDetector] = None,
        engine: Optional[MultiStagePackerEngine] = None
    ):
        self.detector = detector or PackerSignatureDetector()
        self.engine = engine or MultiStagePackerEngine(detector=self.detector)
        self.metrics = self.detector.metrics

    def unpack(self, source: str) -> PackerDetectionResult:
        """
        Executes multi-layer recursive unpacking on the source script.
        Returns PackerDetectionResult with the ultimate unpacked script in unpacked_source.
        """
        layered_res: LayeredUnpackResult = self.engine.unpack(source)

        # Detect signatures on final source
        detection = self.detector.detect(layered_res.final_source)
        detection.layered_result = layered_res

        if layered_res.layers_unpacked > 0:
            detection.is_packed = True
            detection.primary_packer = layered_res.primary_packer
            detection.unpacked_source = layered_res.final_source
        else:
            detection.unpacked_source = None

        return detection

    # Backward compatibility helper delegations
    def _extract_certutil_base64(self, source: str) -> Optional[str]:
        return self.engine._extract_certutil_base64(source)

    def _extract_certutil_hex(self, source: str) -> Optional[str]:
        return self.engine._extract_certutil_hex(source)

    def _clean_0xidiz3r_wrappers(self, source: str) -> str:
        return self.engine._clean_0xidiz3r(source)

    @staticmethod
    def _is_likely_batch(text: str) -> bool:
        return MultiStagePackerEngine._is_likely_batch_or_script(text)
