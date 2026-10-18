"""
Multi-Stage Batch Packer & Advanced Heuristic Unpacking Engine.
Recursively unravels cascading packing architectures including CertUtil Base64/Hex,
PowerShell UTF-16LE Base64, Deflate/GZip streams, Echo dropper staging assemblers,
0xidiz3r noise wrappers, and Somalifuscator variable substitutions.
"""

import base64
import binascii
import gzip
import hashlib
import math
import re
import zlib
from typing import Optional, Tuple, List, Dict, Any, Set

from .models import (
    PackerType,
    PackerSignature,
    PackerMetrics,
    LayerTransition,
    LayeredUnpackResult,
    PackerDetectionResult,
)
from .detector import PackerSignatureDetector

MAX_UNPACK_LAYERS = 8
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB DoS protection limit


def compute_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy (bits per byte) of a given text string."""
    if not data:
        return 0.0
    byte_array = data.encode("utf-8", errors="replace")
    length = len(byte_array)
    if length == 0:
        return 0.0
    freq: Dict[int, int] = {}
    for b in byte_array:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class MultiStagePackerEngine:
    """
    Compiler-grade recursive unpacker for multi-tier batch packing and dropper payloads.
    Maintains cryptographic provenance history and prevents unbounded recursion cycles.
    """

    RE_CERT_BLOCK = re.compile(
        r'-----BEGIN\s+(?:CERTIFICATE|MESSAGE)-----\s*[\r\n]+(.*?)\s*[\r\n]+-----END\s+(?:CERTIFICATE|MESSAGE)-----',
        re.DOTALL | re.IGNORECASE
    )
    RE_HEX_LINES = re.compile(r'^[0-9a-fA-F\s]{8,}$', re.MULTILINE)
    RE_PS_B64 = re.compile(
        r'(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+[^;&|]*?(?:-|/)(?:e|enc|encodedcommand)\s+["\']?([A-Za-z0-9+/=]{16,})["\']?',
        re.IGNORECASE
    )
    RE_PS_FROM_BASE64 = re.compile(
        r'(?:FromBase64String|\[Convert\]::FromBase64String)\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']\s*\)',
        re.IGNORECASE
    )
    RE_ECHO_DROP_LINE = re.compile(
        r'^\s*echo\s*(.*?)\s*(?:>>|>)\s*["\']?([%a-zA-Z0-9_\\/.:-]+\.(?:bat|cmd|vbs|js|ps1|tmp|bin|exe))["\']?\s*$',
        re.IGNORECASE
    )
    RE_0XIDIZ3R_STRIP_BANNER = re.compile(
        r'^\s*(?:::|rem)\s*(?:0xidiz3r|packed by|obfuscated with).*?$',
        re.MULTILINE | re.IGNORECASE
    )
    RE_ANTI_DEBUG_STUB = re.compile(
        r'^\s*if\s+(?:/i\s+)?["\']?%~nx0["\']?\s+neq\s+["\']?[^"\']+["\']?\s+(?:exit\s*/b|exit|goto\s+:eof)\s*$',
        re.MULTILINE | re.IGNORECASE
    )
    RE_0X_NOISE_LINE = re.compile(
        r'^\s*set\s+["\']?noise\d*\s*=\s*["\']?[0-9a-fA-F_]{4,}["\']?\s*$',
        re.MULTILINE | re.IGNORECASE
    )
    RE_SOMALI_SUBST = re.compile(
        r'%([a-zA-Z0-9_#$]+):([a-zA-Z0-9_#$]+)=([^%]*)%',
        re.IGNORECASE
    )

    def __init__(
        self,
        detector: Optional[PackerSignatureDetector] = None,
        max_layers: int = MAX_UNPACK_LAYERS,
        max_payload_size: int = MAX_PAYLOAD_SIZE,
    ):
        self.detector = detector or PackerSignatureDetector()
        self.max_layers = max_layers
        self.max_payload_size = max_payload_size
        self.metrics = self.detector.metrics

    def unpack(self, source: str) -> LayeredUnpackResult:
        """
        Executes multi-stage recursive unpacking across nested layers.
        Returns LayeredUnpackResult with complete transition provenance.
        """
        result = LayeredUnpackResult(root_source=source, final_source=source, metrics=self.metrics)
        if not source or not source.strip():
            return result

        current_source = source
        initial_entropy = compute_shannon_entropy(source)
        self.metrics.total_input_bytes += len(source.encode("utf-8", errors="replace"))

        initial_detection = self.detector.detect(current_source)
        result.primary_packer = initial_detection.primary_packer
        result.overall_confidence = initial_detection.confidence
        result.is_packed = initial_detection.is_packed

        if not initial_detection.is_packed and not initial_detection.detected_signatures:
            return result

        seen_hashes: Set[str] = set()
        seen_hashes.add(hashlib.sha256(current_source.encode("utf-8", errors="replace")).hexdigest())

        depth = 0
        current_detection = initial_detection
        while depth < self.max_layers:
            step_result = self._unpack_single_layer(current_source, current_detection)
            if not step_result:
                break

            new_source, from_packer, strategy, indicators, metadata = step_result
            if not new_source or new_source == current_source:
                break

            payload_len = len(new_source.encode("utf-8", errors="replace"))
            if payload_len > self.max_payload_size:
                result.depth_limit_reached = True
                break

            new_hash = hashlib.sha256(new_source.encode("utf-8", errors="replace")).hexdigest()
            if new_hash in seen_hashes:
                result.cycle_detected = True
                self.metrics.cycles_halted += 1
                break
            seen_hashes.add(new_hash)

            input_ent = compute_shannon_entropy(current_source)
            output_ent = compute_shannon_entropy(new_source)
            ent_delta = round(output_ent - input_ent, 4)

            depth += 1
            next_detection = self.detector.detect(new_source)
            to_packer = next_detection.primary_packer

            transition = LayerTransition(
                depth=depth,
                from_packer=from_packer,
                to_packer=to_packer,
                unpacker_strategy=strategy,
                input_entropy=input_ent,
                output_entropy=output_ent,
                entropy_delta=ent_delta,
                input_bytes=len(current_source.encode("utf-8", errors="replace")),
                output_bytes=payload_len,
                payload_sha256=new_hash,
                indicators=indicators,
                metadata=metadata
            )
            result.transitions.append(transition)

            self.metrics.layers_unpacked += 1
            self.metrics.payload_bytes_recovered += payload_len
            self.metrics.decompressed_bytes += payload_len

            current_source = new_source
            current_detection = next_detection

        if depth >= self.max_layers:
            result.depth_limit_reached = True

        result.layers_unpacked = depth
        result.final_source = current_source
        if depth > 0:
            result.is_packed = True
            final_entropy = compute_shannon_entropy(current_source)
            self.metrics.entropy_reduction = round(initial_entropy - final_entropy, 4)

        return result

    def _unpack_single_layer(
        self,
        source: str,
        detection: PackerDetectionResult
    ) -> Optional[Tuple[str, PackerType, str, List[str], Dict[str, Any]]]:
        """Tries specialized decoders guided by detected signatures."""
        active_types = {s.packer_type for s in detection.detected_signatures}
        is_container = PackerType.MULTI_LAYER_CONTAINER in active_types

        # 1. CertUtil Base64 PEM / trailing decode
        if is_container or PackerType.CERTUTIL_BASE64 in active_types or self.RE_CERT_BLOCK.search(source):
            decoded = self._extract_certutil_base64(source)
            if decoded and decoded != source:
                return (decoded, PackerType.CERTUTIL_BASE64, "certutil_base64_decode", ["Extracted embedded CertUtil PEM / base64 payload"], {"method": "certutil_base64"})

        # 2. CertUtil Hex decode
        if is_container or PackerType.CERTUTIL_HEX in active_types:
            decoded_hex = self._extract_certutil_hex(source)
            if decoded_hex and decoded_hex != source:
                return (decoded_hex, PackerType.CERTUTIL_HEX, "certutil_hex_decode", ["Extracted CertUtil hex byte dump payload"], {"method": "certutil_hex"})

        # 3. PowerShell Deflate / GZip compressed stream
        if is_container or PackerType.POWERSHELL_DEFLATE in active_types:
            decompressed_ps = self._extract_powershell_compressed(source)
            if decompressed_ps and decompressed_ps != source:
                return (decompressed_ps, PackerType.POWERSHELL_DEFLATE, "powershell_deflate_decompress", ["Decompressed PowerShell Deflate/GZip embedded stream payload"], {"method": "powershell_deflate"})

        # 4. PowerShell Base64 (-enc / -encodedcommand)
        if is_container or PackerType.POWERSHELL_BASE64 in active_types:
            decoded_ps = self._extract_powershell_base64(source)
            if decoded_ps and decoded_ps != source:
                return (decoded_ps, PackerType.POWERSHELL_BASE64, "powershell_base64_decode", ["Decoded PowerShell EncodedCommand UTF-16LE Base64 payload"], {"method": "powershell_base64"})

        # 5. Echo dropper line collector & stage assembler
        if is_container or PackerType.ECHO_DROPPER in active_types:
            staged_script = self._extract_echo_dropper(source)
            if staged_script and staged_script != source:
                return (staged_script, PackerType.ECHO_DROPPER, "echo_dropper_stage_assembler", ["Reassembled multi-line echo dropper staging script"], {"method": "echo_dropper"})

        # 6. 0xidiz3r wrapper and anti-debug stripper
        if is_container or PackerType.OXIDIZ3R in active_types:
            cleaned_0x = self._clean_0xidiz3r(source)
            if cleaned_0x and cleaned_0x != source:
                return (cleaned_0x, PackerType.OXIDIZ3R, "0xidiz3r_wrapper_stripper", ["Stripped 0xidiz3r header banners, noise variables, and anti-debug guard"], {"method": "0xidiz3r_cleaner"})

        # 7. Somalifuscator variable replacement
        if is_container or PackerType.SOMALIFUSCATOR in active_types:
            somali_unpacked = self._unpack_somalifuscator(source)
            if somali_unpacked and somali_unpacked != source:
                return (somali_unpacked, PackerType.SOMALIFUSCATOR, "somalifuscator_variable_substitution", ["Resolved Somalifuscator variable substitution patterns"], {"method": "somalifuscator"})

        return None

    def _extract_certutil_base64(self, source: str) -> Optional[str]:
        """Extracts and decodes embedded PEM/base64 block."""
        match = self.RE_CERT_BLOCK.search(source)
        if match:
            raw_b64 = re.sub(r'\s+', '', match.group(1))
            try:
                decoded_bytes = base64.b64decode(raw_b64, validate=False)
                if len(decoded_bytes) <= self.max_payload_size:
                    decoded = self._decode_bytes(decoded_bytes)
                    if decoded and self._is_likely_batch_or_script(decoded):
                        return decoded
            except (binascii.Error, ValueError):
                pass

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
            try:
                decoded_bytes = base64.b64decode("".join(payload_lines), validate=False)
                if len(decoded_bytes) <= self.max_payload_size:
                    decoded = self._decode_bytes(decoded_bytes)
                    if decoded and self._is_likely_batch_or_script(decoded):
                        return decoded
            except (binascii.Error, ValueError):
                pass
        return None

    def _extract_certutil_hex(self, source: str) -> Optional[str]:
        """Extracts and decodes hex string blocks."""
        hex_lines = [
            clean_hex for line in source.splitlines()
            if self.RE_HEX_LINES.match(line.strip())
            for clean_hex in [re.sub(r'[^0-9a-fA-F]', '', line.strip())]
            if len(clean_hex) % 2 == 0
        ]
        if hex_lines:
            try:
                decoded_bytes = binascii.unhexlify("".join(hex_lines))
                if len(decoded_bytes) <= self.max_payload_size:
                    decoded = self._decode_bytes(decoded_bytes)
                    if decoded and self._is_likely_batch_or_script(decoded):
                        return decoded
            except (binascii.Error, ValueError):
                pass
        return None

    def _extract_powershell_base64(self, source: str) -> Optional[str]:
        """Extracts and decodes PowerShell EncodedCommand (UTF-16LE Base64) payload."""
        match = self.RE_PS_B64.search(source)
        if not match:
            return None
        try:
            raw_bytes = base64.b64decode(match.group(1), validate=False)
            if len(raw_bytes) <= self.max_payload_size:
                try:
                    text = raw_bytes.decode('utf-16le')
                    printable = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
                    if printable / max(1, len(text)) > 0.80 and self._is_likely_batch_or_script(text):
                        return text.strip()
                except UnicodeDecodeError:
                    pass
                return self._decode_bytes(raw_bytes, ('utf-8', 'latin-1', 'cp1252'))
        except (binascii.Error, ValueError):
            pass
        return None

    def _extract_powershell_compressed(self, source: str) -> Optional[str]:
        """Extracts and decompresses PowerShell Deflate/GZip streams."""
        m_b64 = self.RE_PS_FROM_BASE64.search(source)
        if not m_b64:
            return None
        try:
            compressed_bytes = base64.b64decode(m_b64.group(1), validate=False)
            if len(compressed_bytes) > self.max_payload_size:
                return None

            decompressed: Optional[bytes] = None
            for decompressor in (
                lambda b: gzip.decompress(b),
                lambda b: zlib.decompress(b, -zlib.MAX_WBITS),
                lambda b: zlib.decompress(b)
            ):
                try:
                    decompressed = decompressor(compressed_bytes)
                    if decompressed:
                        break
                except Exception:
                    continue

            if decompressed:
                return self._decode_bytes(decompressed, ('utf-8', 'utf-16le', 'latin-1', 'cp1252', 'cp437'))
        except (binascii.Error, ValueError):
            pass
        return None

    def _extract_echo_dropper(self, source: str) -> Optional[str]:
        """Reassembles dropped batch/script lines from echo dropper stanzas."""
        target_lines: Dict[str, List[str]] = {}
        for line in source.splitlines():
            m = self.RE_ECHO_DROP_LINE.match(line)
            if m:
                target_file = m.group(2).lower()
                target_lines.setdefault(target_file, []).append(m.group(1).rstrip())

        if not target_lines:
            return None

        top_target = max(target_lines, key=lambda k: len(target_lines[k]))
        raw_lines = target_lines[top_target]
        if len(raw_lines) >= 2 or (len(raw_lines) >= 1 and any(tok in "".join(raw_lines).lower() for tok in ('@echo', 'cmd', 'powershell', 'call', 'net '))):
            reassembled = [self._unescape_batch_carets(l) for l in raw_lines]
            combined = "\n".join(reassembled).strip()
            if self._is_likely_batch_or_script(combined):
                return combined
        return None

    def _clean_0xidiz3r(self, source: str) -> str:
        """Removes 0xidiz3r headers, noise variables, and anti-debug guards."""
        cleaned = self.RE_0XIDIZ3R_STRIP_BANNER.sub('', source)
        cleaned = self.RE_ANTI_DEBUG_STUB.sub('', cleaned)
        cleaned = self.RE_0X_NOISE_LINE.sub('', cleaned)

        orig_lines = [l for l in source.splitlines() if l.strip()]
        clean_lines = [l for l in cleaned.splitlines() if l.strip()]
        delta = len(orig_lines) - len(clean_lines)
        if delta > 0:
            self.metrics.noise_lines_stripped += delta
            return "\n".join(clean_lines)
        return source

    def _unpack_somalifuscator(self, source: str) -> Optional[str]:
        """Resolves Somalifuscator variable substitution expressions."""
        matches = list(self.RE_SOMALI_SUBST.finditer(source))
        if not matches:
            return None
        current = source
        for m in matches:
            pattern, target, repl = m.group(0), m.group(2), m.group(3)
            if target and target in current:
                current = current.replace(pattern, repl)
        return current if current != source else None

    @staticmethod
    def _decode_bytes(raw_bytes: bytes, encodings=('utf-8', 'latin-1', 'cp1252', 'cp437')) -> Optional[str]:
        """Helper to decode raw byte buffers into readable script text."""
        for enc in encodings:
            try:
                text = raw_bytes.decode(enc)
                if text and '\x00' not in text and any(c.isprintable() for c in text):
                    return text.strip()
            except UnicodeDecodeError:
                continue
        return None

    @staticmethod
    def _unescape_batch_carets(line: str) -> str:
        """Unescapes batch caret escape sequences (^& -> &, ^| -> |, ^^ -> ^, etc.)."""
        result, i, n = [], 0, len(line)
        while i < n:
            if line[i] == '^' and i + 1 < n:
                result.append(line[i + 1])
                i += 2
            else:
                result.append(line[i])
                i += 1
        return "".join(result)

    @staticmethod
    def _is_likely_batch_or_script(text: str) -> bool:
        """Heuristic check whether unpacked text contains batch/script commands."""
        if not text or '\x00' in text:
            return False
        text_lower = text.lower()
        script_tokens = (
            '@echo', 'set ', 'goto', 'call', 'if ', 'for ', 'rem', '::', 'pause',
            '%comspec%', 'cmd.exe', 'powershell', 'net ', 'dir', 'copy', 'del',
            'start ', 'reg ', 'curl', 'bitsadmin', 'certutil', 'wscript', 'cscript'
        )
        return any(tok in text_lower for tok in script_tokens) or len(text.strip()) > 0
