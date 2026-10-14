"""
Batch Packer Unpacker and Payload Extractor.
Extracts embedded base64/hex payloads from CertUtil stubs,
strips 0xidiz3r anti-debugging noise and metadata wrappers,
and unrolls multi-layer packing architectures.
"""

import base64
import binascii
import re
from typing import Optional, Tuple, List
from .models import PackerType, PackerDetectionResult, PackerMetrics
from .detector import PackerSignatureDetector

MAX_UNPACK_LAYERS = 5
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB DoS guard


class PackerUnpacker:
    """
    Automated unpacker for batch packaging wrappers.
    Resolves self-extracting stubs, CertUtil encoding layers, and noise banners.
    """

    RE_CERT_BLOCK = re.compile(
        r'-----BEGIN\s+(?:CERTIFICATE|MESSAGE)-----\s*[\r\n]+(.*?)\s*[\r\n]+-----END\s+(?:CERTIFICATE|MESSAGE)-----',
        re.DOTALL | re.IGNORECASE
    )
    RE_HEX_LINES = re.compile(r'^[0-9a-fA-F\s]{8,}$', re.MULTILINE)
    RE_0XIDIZ3R_STRIP_BANNER = re.compile(r'^\s*(?:::|rem)\s*(?:0xidiz3r|packed by|obfuscated with).*?$', re.MULTILINE | re.IGNORECASE)
    RE_ANTI_DEBUG_STUB = re.compile(r'^\s*if\s+(?:/i\s+)?["\']?%~nx0["\']?\s+neq\s+["\']?[^"\']+["\']?\s+(?:exit\s*/b|exit|goto\s+:eof)\s*$', re.MULTILINE | re.IGNORECASE)

    def __init__(self, detector: Optional[PackerSignatureDetector] = None):
        self.detector = detector or PackerSignatureDetector()
        self.metrics = self.detector.metrics

    def unpack(self, source: str) -> PackerDetectionResult:
        """
        Executes multi-layer recursive unpacking on the source script.
        Returns PackerDetectionResult with the ultimate unpacked script in unpacked_source.
        """
        current_source = source
        detection = self.detector.detect(current_source)
        layers = 0

        while layers < MAX_UNPACK_LAYERS:
            unpacked_layer = False

            # Check for Certutil Base64 extraction
            if any(s.packer_type == PackerType.CERTUTIL_BASE64 for s in detection.detected_signatures):
                payload = self._extract_certutil_base64(current_source)
                if payload and payload != current_source:
                    current_source = payload
                    self.metrics.layers_unpacked += 1
                    self.metrics.payload_bytes_recovered += len(payload)
                    unpacked_layer = True

            # Check for Certutil Hex extraction
            elif any(s.packer_type == PackerType.CERTUTIL_HEX for s in detection.detected_signatures):
                payload = self._extract_certutil_hex(current_source)
                if payload and payload != current_source:
                    current_source = payload
                    self.metrics.layers_unpacked += 1
                    self.metrics.payload_bytes_recovered += len(payload)
                    unpacked_layer = True

            # Check for 0xidiz3r noise stripping
            if any(s.packer_type == PackerType.OXIDIZ3R for s in detection.detected_signatures):
                cleaned = self._clean_0xidiz3r_wrappers(current_source)
                if cleaned != current_source:
                    current_source = cleaned
                    unpacked_layer = True

            if not unpacked_layer:
                break

            layers += 1
            # Re-detect on newly extracted layer
            detection = self.detector.detect(current_source)

        detection.unpacked_source = current_source if current_source != source else None
        return detection

    def _extract_certutil_base64(self, source: str) -> Optional[str]:
        """Extracts and decodes embedded PEM/base64 block."""
        match = self.RE_CERT_BLOCK.search(source)
        if match:
            raw_b64 = re.sub(r'\s+', '', match.group(1))
            try:
                decoded_bytes = base64.b64decode(raw_b64, validate=False)
                if len(decoded_bytes) > MAX_PAYLOAD_SIZE:
                    return None
                # Attempt UTF-8 then Latin-1 decoding
                for encoding in ('utf-8', 'latin-1', 'cp1252', 'cp437'):
                    try:
                        decoded_text = decoded_bytes.decode(encoding)
                        if self._is_likely_batch(decoded_text):
                            return decoded_text.strip()
                    except UnicodeDecodeError:
                        continue
            except (binascii.Error, ValueError):
                pass

        # Check for trailing base64 payload lines after exit or goto :eof
        lines = source.splitlines()
        payload_lines: List[str] = []
        in_payload = False
        for line in lines:
            stripped = line.strip()
            if not in_payload:
                if stripped.lower() in ('exit', 'exit /b', 'goto :eof', 'goto eof') or 'certutil' in stripped.lower():
                    in_payload = True
                continue
            if stripped and re.match(r'^[A-Za-z0-9+/=]{16,}$', stripped):
                payload_lines.append(stripped)

        if payload_lines:
            raw_b64 = "".join(payload_lines)
            try:
                decoded_bytes = base64.b64decode(raw_b64, validate=False)
                if len(decoded_bytes) <= MAX_PAYLOAD_SIZE:
                    for encoding in ('utf-8', 'latin-1', 'cp1252', 'cp437'):
                        try:
                            decoded_text = decoded_bytes.decode(encoding)
                            if self._is_likely_batch(decoded_text):
                                return decoded_text.strip()
                        except UnicodeDecodeError:
                            continue
            except (binascii.Error, ValueError):
                pass

        return None

    def _extract_certutil_hex(self, source: str) -> Optional[str]:
        """Extracts and decodes hex string blocks."""
        lines = source.splitlines()
        hex_lines: List[str] = []
        for line in lines:
            stripped = line.strip()
            if self.RE_HEX_LINES.match(stripped):
                clean_hex = re.sub(r'[^0-9a-fA-F]', '', stripped)
                if len(clean_hex) % 2 == 0:
                    hex_lines.append(clean_hex)

        if hex_lines:
            full_hex = "".join(hex_lines)
            try:
                decoded_bytes = binascii.unhexlify(full_hex)
                if len(decoded_bytes) <= MAX_PAYLOAD_SIZE:
                    for encoding in ('utf-8', 'latin-1', 'cp1252', 'cp437'):
                        try:
                            decoded_text = decoded_bytes.decode(encoding)
                            if self._is_likely_batch(decoded_text):
                                return decoded_text.strip()
                        except UnicodeDecodeError:
                            continue
            except (binascii.Error, ValueError):
                pass
        return None

    def _clean_0xidiz3r_wrappers(self, source: str) -> str:
        """Removes 0xidiz3r header banners and anti-debug name guards."""
        cleaned = self.RE_0XIDIZ3R_STRIP_BANNER.sub('', source)
        cleaned = self.RE_ANTI_DEBUG_STUB.sub('', cleaned)

        # Count stripped lines
        original_line_count = len(source.splitlines())
        cleaned_line_count = len(cleaned.splitlines())
        delta = original_line_count - cleaned_line_count
        if delta > 0:
            self.metrics.noise_lines_stripped += delta

        return cleaned.strip()

    @staticmethod
    def _is_likely_batch(text: str) -> bool:
        """Heuristic check whether unpacked text contains batch script primitives."""
        text_lower = text.lower()
        batch_tokens = (
            '@echo', 'set ', 'goto', 'call', 'if ', 'for ', 'rem', '::', 'pause',
            '%comspec%', 'cmd.exe', 'powershell', 'net ', 'dir', 'copy', 'del'
        )
        return any(tok in text_lower for tok in batch_tokens)
