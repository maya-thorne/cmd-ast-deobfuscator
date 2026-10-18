"""
Multi-tier heuristic detection rules for advanced batch packers and wrappers.
Identifies PowerShell encoded stubs, compressed stream wrappers, echo droppers,
dynamic trampolines, and character code reconstruction patterns.
"""

import re
from typing import List, Optional, Tuple, Dict, Any, Set
from .models import PackerType, PackerSignature


class PackerHeuristicDetector:
    """
    Heuristic rule engine for modern and multi-stage batch packer mechanisms.
    Analyzes raw script source and line sequences to extract structural indicators.
    """

    # PowerShell Base64 EncodedCommand patterns (-e, -enc, -encodedcommand, /e, etc.)
    RE_PS_B64 = re.compile(
        r'(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+[^;&|]*?(?:-|/)(?:e|enc|encodedcommand)\s+["\']?([A-Za-z0-9+/=]{16,})["\']?',
        re.IGNORECASE
    )

    # PowerShell Deflate/GZip stream decompression stubs
    RE_PS_DEFLATE_STREAM = re.compile(
        r'\[(?:System\.)?IO\.Compression\.DeflateStream\]|\[(?:System\.)?IO\.Compression\.GZipStream\]',
        re.IGNORECASE
    )
    RE_PS_COMPRESSION_MODE = re.compile(
        r'\[(?:System\.)?IO\.Compression\.CompressionMode\]::Decompress',
        re.IGNORECASE
    )
    RE_PS_FROM_BASE64 = re.compile(
        r'\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*["\']?([A-Za-z0-9+/=]{20,})["\']?\s*\)',
        re.IGNORECASE
    )

    # Echo dropper patterns: echo <payload> >> destination.bat
    RE_ECHO_DROP_LINE = re.compile(
        r'^\s*echo\s*(.*?)\s*(?:>>|>)\s*["\']?([%a-zA-Z0-9_\\/.:-]+\.(?:bat|cmd|vbs|js|ps1|tmp|bin|exe))["\']?\s*$',
        re.IGNORECASE
    )

    # Dynamic trampoline patterns: cmd /c %VAR% or call %VAR% / call !VAR!
    RE_CMD_TRAMPOLINE = re.compile(
        r'(?:cmd(?:\.exe)?\s*/c\s*|call\s+)["\']?[%!]([a-zA-Z0-9_]{1,64})[!%]["\']?',
        re.IGNORECASE
    )
    RE_DYNAMIC_SET = re.compile(
        r'^\s*set\s+["\']?([a-zA-Z0-9_]{1,64})\s*=\s*(.*?)\s*$',
        re.IGNORECASE
    )

    # Character code reconstruction patterns: [char]0x41, [char]65, chr(65), etc.
    RE_CHAR_CODE = re.compile(
        r'(?:\[char\]\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})|chr\s*\(\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\))',
        re.IGNORECASE
    )

    def scan(self, lines: List[str], source: str) -> List[PackerSignature]:
        """Runs all heuristic detector rules across lines and returns identified signatures."""
        signatures: List[PackerSignature] = []

        sig_ps_b64 = self.detect_powershell_base64(lines, source)
        if sig_ps_b64:
            signatures.append(sig_ps_b64)

        sig_ps_deflate = self.detect_powershell_deflate(lines, source)
        if sig_ps_deflate:
            signatures.append(sig_ps_deflate)

        sig_dropper = self.detect_echo_dropper(lines, source)
        if sig_dropper:
            signatures.append(sig_dropper)

        sig_trampoline = self.detect_dynamic_trampoline(lines, source)
        if sig_trampoline:
            signatures.append(sig_trampoline)

        sig_char = self.detect_char_code_stub(lines, source)
        if sig_char:
            signatures.append(sig_char)

        return signatures

    def detect_powershell_base64(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        """Detects PowerShell -EncodedCommand / -enc Base64 stubs."""
        match = self.RE_PS_B64.search(source)
        if match:
            b64_payload = match.group(1)
            indicators = [
                f"PowerShell EncodedCommand invocation detected: {match.group(0)[:60]}...",
                f"Base64 payload length: {len(b64_payload)} characters"
            ]
            confidence = 0.95 if len(b64_payload) >= 32 else 0.80
            return PackerSignature(
                packer_type=PackerType.POWERSHELL_BASE64,
                name="PowerShell EncodedCommand Base64 Stub",
                confidence=confidence,
                indicators=indicators,
                extracted_payload=b64_payload,
                metadata={"payload_length": len(b64_payload)}
            )
        return None

    def detect_powershell_deflate(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        """Detects PowerShell DeflateStream or GZipStream compressed payload streams."""
        has_stream = bool(self.RE_PS_DEFLATE_STREAM.search(source))
        has_mode = bool(self.RE_PS_COMPRESSION_MODE.search(source))
        m_b64 = self.RE_PS_FROM_BASE64.search(source)

        score = 0.0
        indicators: List[str] = []

        if has_stream:
            indicators.append("PowerShell Compression stream object (Deflate/GZip) instantiated")
            score += 0.50
        if has_mode:
            indicators.append("CompressionMode::Decompress flag referenced")
            score += 0.25
        if m_b64:
            indicators.append(f"FromBase64String payload stream embedded ({len(m_b64.group(1))} chars)")
            score += 0.35

        if score >= 0.50 and indicators:
            conf = min(0.99, score)
            extracted = m_b64.group(1) if m_b64 else None
            return PackerSignature(
                packer_type=PackerType.POWERSHELL_DEFLATE,
                name="PowerShell Compressed Stream Stub (Deflate/Gzip)",
                confidence=conf,
                indicators=indicators,
                extracted_payload=extracted,
                metadata={"has_stream": has_stream, "has_mode": has_mode, "has_base64": m_b64 is not None}
            )
        return None

    def detect_echo_dropper(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        """Detects repeated echo payload redirection into stage files (echo ... >> %temp%\\stage.bat)."""
        target_counts: Dict[str, int] = {}
        target_lines: Dict[str, List[str]] = {}

        for line in lines:
            m = self.RE_ECHO_DROP_LINE.match(line)
            if m:
                payload_part = m.group(1)
                target_file = m.group(2).lower()
                target_counts[target_file] = target_counts.get(target_file, 0) + 1
                if target_file not in target_lines:
                    target_lines[target_file] = []
                target_lines[target_file].append(payload_part)

        if not target_counts:
            return None

        # Find target file with highest count
        top_target = max(target_counts, key=lambda k: target_counts[k])
        count = target_counts[top_target]

        if count >= 2 or (count >= 1 and ("%temp%" in top_target or "stage" in top_target)):
            indicators = [
                f"Echo dropper sequence targeting '{top_target}' (dropped lines: {count})",
                "Intermediate payload file staging pattern"
            ]
            confidence = min(0.95, 0.40 + 0.15 * count)
            combined_payload = "\n".join(target_lines[top_target])
            return PackerSignature(
                packer_type=PackerType.ECHO_DROPPER,
                name="Batch Echo Dropper Staging Block",
                confidence=confidence,
                indicators=indicators,
                extracted_payload=combined_payload,
                metadata={"target_file": top_target, "line_count": count}
            )
        return None

    def detect_dynamic_trampoline(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        """Detects dynamic trampoline executions (cmd /c %VAR% or call %VAR%)."""
        trampolines = self.RE_CMD_TRAMPOLINE.findall(source)
        if not trampolines:
            return None

        # Look for preceding set variable assignments
        set_vars: Set[str] = set()
        for line in lines:
            m = self.RE_DYNAMIC_SET.match(line)
            if m:
                set_vars.add(m.group(1).lower())

        valid_targets = [v for v in trampolines if v.lower() in set_vars or len(v) >= 4]
        if valid_targets:
            indicators = [
                f"Dynamic trampoline dispatcher: cmd /c or call with variable target ({', '.join(valid_targets[:3])})",
                "Runtime indirect instruction dispatch pattern"
            ]
            confidence = min(0.85, 0.50 + 0.10 * len(valid_targets))
            return PackerSignature(
                packer_type=PackerType.DYNAMIC_TRAMPOLINE,
                name="Dynamic Trampoline Execution Chain",
                confidence=confidence,
                indicators=indicators,
                metadata={"targets": valid_targets}
            )
        return None

    def detect_char_code_stub(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        """Detects character code reconstruction arrays ([char]0x41 / chr(65))."""
        matches = self.RE_CHAR_CODE.findall(source)
        if len(matches) >= 3:
            indicators = [
                f"Character code array reconstruction pattern (count: {len(matches)} tokens)",
                "Dynamic string reconstruction via integer character codes"
            ]
            confidence = min(0.92, 0.45 + 0.08 * len(matches))
            return PackerSignature(
                packer_type=PackerType.CHAR_CODE_STUB,
                name="Character Code Reconstruction Stub",
                confidence=confidence,
                indicators=indicators,
                metadata={"token_count": len(matches)}
            )
        return None
