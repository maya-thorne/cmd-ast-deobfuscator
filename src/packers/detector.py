"""
Batch Packer and Obfuscator Signature Detector.
Scans batch script source lines and AST nodes to identify 0xidiz3r, Somalifuscator,
Certutil self-extracting stubs, Bat2Exe drop scripts, and generic CFF packers.
"""

import re
from typing import List, Dict, Optional, Tuple, Set
from .models import PackerType, PackerSignature, PackerDetectionResult, PackerMetrics

# Maximum source lines to inspect for signature detection (DoS defense)
MAX_SCAN_LINES = 10000


class PackerSignatureDetector:
    """
    Multi-rule heuristic and signature scanner for batch packaging mechanisms.
    Computes confidence metrics based on weighted indicator matching.
    """

    # 0xidiz3r signature patterns
    RE_0XIDIZ3R_BANNER = re.compile(r'(?:0xidiz3r|packed by 0x|obfuscated with 0x|github\.com/.*/0xidiz3r)', re.IGNORECASE)
    RE_0XIDIZ3R_VARS = re.compile(r'set\s+["\']?(?:__)?0x[0-9a-fA-F_]{2,16}\s*=', re.IGNORECASE)
    RE_0XIDIZ3R_NOISE = re.compile(r'set\s+["\']?noise\d*\s*=\s*["\']?[0-9a-fA-F_]{4,}', re.IGNORECASE)
    RE_0XIDIZ3R_TOKEN_MAP = re.compile(r'set\s+["\']?0x[0-9a-fA-F]{2}\s*=\s*.', re.IGNORECASE)

    # Certutil self-extracting payload patterns
    RE_CERTUTIL_DECODE = re.compile(r'certutil(?:\.exe)?\s+(?:-[a-zA-Z0-9_-]+\s+)*-(?:decode|f\s+-decode)\s+([^\s&|]+)\s+([^\s&|]+)', re.IGNORECASE)
    RE_CERTUTIL_HEX = re.compile(r'certutil(?:\.exe)?\s+(?:-[a-zA-Z0-9_-]+\s+)*-(?:decodehex|f\s+-decodehex)\s+([^\s&|]+)\s+([^\s&|]+)', re.IGNORECASE)
    RE_CERT_BEGIN = re.compile(r'-----BEGIN\s+(?:CERTIFICATE|MESSAGE)-----', re.IGNORECASE)
    RE_CERT_END = re.compile(r'-----END\s+(?:CERTIFICATE|MESSAGE)-----', re.IGNORECASE)

    # Somalifuscator patterns
    RE_SOMALI_BANNER = re.compile(r'(?:somalifuscator|somali\s+batch)', re.IGNORECASE)
    RE_SOMALI_SUBST = re.compile(r'%[a-zA-Z0-9_#$]+:[a-zA-Z0-9_#$]{3,8}=%', re.IGNORECASE)

    # VBS / Script drop stubs
    RE_VBS_DROP = re.compile(r'(?:echo\s+.*?>>?\s*["\']?.*?\.(?:vbs|js|ps1)["\']?.*?(?:cscript|wscript|powershell))', re.IGNORECASE)
    RE_TEMP_EXE_DROP = re.compile(r'(?:copy|type|certutil|bitsadmin).*?%temp%\\.*?\.(?:exe|bat|cmd|vbs)', re.IGNORECASE)

    # CFF dispatcher indicators
    RE_STATE_GOTO = re.compile(r'if\s+(?:/i\s+)?["\']?[!%]([a-zA-Z0-9_]+)[!%]["\']?\s*(?:==|equ)\s*["\']?([^"\'\s]+)["\']?\s+goto\s+:([a-zA-Z0-9_]+)', re.IGNORECASE)
    RE_COMPUTED_GOTO = re.compile(r'goto\s+:([a-zA-Z0-9_]*[!%][a-zA-Z0-9_]+[!%][a-zA-Z0-9_]*)', re.IGNORECASE)

    def __init__(self):
        self.metrics = PackerMetrics()

    def detect(self, source: str) -> PackerDetectionResult:
        """
        Analyzes batch script source text and returns a consolidated PackerDetectionResult.
        """
        result = PackerDetectionResult(metrics=self.metrics)
        if not source or not source.strip():
            return result

        lines = [line.strip() for line in source.splitlines()][:MAX_SCAN_LINES]
        self.metrics.signatures_scanned += len(lines)

        signatures: List[PackerSignature] = []

        # 1. Check for 0xidiz3r signatures
        sig_0x = self._check_0xidiz3r(lines, source)
        if sig_0x:
            signatures.append(sig_0x)

        # 2. Check for Certutil extraction stubs
        sig_cert_b64, sig_cert_hex = self._check_certutil(lines, source)
        if sig_cert_b64:
            signatures.append(sig_cert_b64)
        if sig_cert_hex:
            signatures.append(sig_cert_hex)

        # 3. Check for Somalifuscator signatures
        sig_somali = self._check_somalifuscator(lines, source)
        if sig_somali:
            signatures.append(sig_somali)

        # 4. Check for Drop Stubs
        sig_drop = self._check_drop_stubs(lines, source)
        if sig_drop:
            signatures.append(sig_drop)

        # 5. Check for Generic CFF Dispatchers
        sig_cff = self._check_generic_cff(lines)
        if sig_cff and not any(s.packer_type == PackerType.OXIDIZ3R for s in signatures):
            signatures.append(sig_cff)

        if signatures:
            # Sort signatures by confidence descending
            signatures.sort(key=lambda s: s.confidence, reverse=True)
            result.primary_packer = signatures[0].packer_type
            result.is_packed = True
            result.confidence = signatures[0].confidence
            result.detected_signatures = signatures
            self.metrics.packers_detected += len(signatures)
        else:
            result.primary_packer = PackerType.CLEAN_BATCH
            result.is_packed = False
            result.confidence = 0.0

        return result

    def _check_0xidiz3r(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        indicators: List[str] = []
        score = 0.0

        # Direct banner/header
        if self.RE_0XIDIZ3R_BANNER.search(source):
            indicators.append("0xidiz3r banner / metadata marker")
            score += 0.55

        # Hex variable names
        hex_vars = self.RE_0XIDIZ3R_VARS.findall(source)
        if len(hex_vars) >= 3:
            indicators.append(f"0x-prefixed hex variable cluster (count: {len(hex_vars)})")
            score += min(0.35, 0.05 * len(hex_vars))

        # Noise variable interleaving
        noise_vars = self.RE_0XIDIZ3R_NOISE.findall(source)
        if len(noise_vars) >= 2:
            indicators.append(f"0xidiz3r noise variable declarations (count: {len(noise_vars)})")
            score += 0.25

        # Token map lookup
        token_maps = self.RE_0XIDIZ3R_TOKEN_MAP.findall(source)
        if len(token_maps) >= 4:
            indicators.append(f"Hex character substitution map (count: {len(token_maps)})")
            score += 0.30

        # CFF state machine pattern common to 0xidiz3r
        state_gotos = self.RE_STATE_GOTO.findall(source)
        if len(state_gotos) >= 3:
            indicators.append(f"CFF state-dispatcher switch cases (count: {len(state_gotos)})")
            score += 0.25

        if score >= 0.40 and indicators:
            conf = min(0.99, score)
            return PackerSignature(
                packer_type=PackerType.OXIDIZ3R,
                name="0xidiz3r Batch Obfuscator / CFF Packer",
                confidence=conf,
                indicators=indicators,
                metadata={"hex_vars": len(hex_vars), "state_gotos": len(state_gotos)}
            )
        return None

    def _check_certutil(self, lines: List[str], source: str) -> Tuple[Optional[PackerSignature], Optional[PackerSignature]]:
        sig_b64 = None
        sig_hex = None

        # Certutil base64 decode
        m_b64 = self.RE_CERTUTIL_DECODE.search(source)
        has_cert_markers = bool(self.RE_CERT_BEGIN.search(source) and self.RE_CERT_END.search(source))
        if m_b64 or has_cert_markers:
            indicators = []
            score = 0.50
            if m_b64:
                indicators.append(f"certutil -decode command: {m_b64.group(0)}")
                score += 0.30
            if has_cert_markers:
                indicators.append("Embedded PEM certificate base64 boundary markers")
                score += 0.30

            sig_b64 = PackerSignature(
                packer_type=PackerType.CERTUTIL_BASE64,
                name="CertUtil Base64 Self-Extracting Payload Stub",
                confidence=min(0.99, score),
                indicators=indicators,
                metadata={"source_file": m_b64.group(1) if m_b64 else "", "dest_file": m_b64.group(2) if m_b64 else ""}
            )

        # Certutil decodehex
        m_hex = self.RE_CERTUTIL_HEX.search(source)
        if m_hex:
            indicators = [f"certutil -decodehex command: {m_hex.group(0)}"]
            sig_hex = PackerSignature(
                packer_type=PackerType.CERTUTIL_HEX,
                name="CertUtil Hex Self-Extracting Payload Stub",
                confidence=0.90,
                indicators=indicators,
                metadata={"source_file": m_hex.group(1), "dest_file": m_hex.group(2)}
            )

        return sig_b64, sig_hex

    def _check_somalifuscator(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        indicators = []
        score = 0.0

        if self.RE_SOMALI_BANNER.search(source):
            indicators.append("Somalifuscator banner / marker")
            score += 0.60

        subst_matches = self.RE_SOMALI_SUBST.findall(source)
        if len(subst_matches) >= 3:
            indicators.append(f"Cipher substitution elimination patterns (count: {len(subst_matches)})")
            score += 0.35

        if score >= 0.40:
            return PackerSignature(
                packer_type=PackerType.SOMALIFUSCATOR,
                name="Somalifuscator Substring / Reversal Engine",
                confidence=min(0.95, score),
                indicators=indicators,
                metadata={"subst_count": len(subst_matches)}
            )
        return None

    def _check_drop_stubs(self, lines: List[str], source: str) -> Optional[PackerSignature]:
        vbs_match = self.RE_VBS_DROP.search(source)
        temp_match = self.RE_TEMP_EXE_DROP.search(source)

        if vbs_match or temp_match:
            indicators = []
            if vbs_match:
                indicators.append("VBS/JS payload drop and execute sequence")
            if temp_match:
                indicators.append("Dynamic binary staging in temporary directory (%TEMP%)")

            return PackerSignature(
                packer_type=PackerType.VBS_DROP_STUB if vbs_match else PackerType.BAT2EXE_STUB,
                name="Script/Executable Staging & Drop Stub",
                confidence=0.75,
                indicators=indicators,
                metadata={}
            )
        return None

    def _check_generic_cff(self, lines: List[str]) -> Optional[PackerSignature]:
        source = "\n".join(lines)
        state_gotos = self.RE_STATE_GOTO.findall(source)
        computed_gotos = self.RE_COMPUTED_GOTO.findall(source)

        total_dispatch_targets = len(state_gotos) + len(computed_gotos)
        if total_dispatch_targets >= 3:
            # Check for multiple labels targeted
            targets: Set[str] = set()
            for _, _, target in state_gotos:
                targets.add(target.lower())
            for target in computed_gotos:
                targets.add(target.lower())

            if len(targets) >= 2:
                indicators = [
                    f"Central state dispatcher loop identified with {len(targets)} distinct branch targets",
                    f"State-based GOTO transitions (count: {total_dispatch_targets})"
                ]
                return PackerSignature(
                    packer_type=PackerType.GENERIC_CFF_PACKER,
                    name="Generic Control Flow Flattening (CFF) Dispatcher",
                    confidence=min(0.92, 0.40 + 0.10 * len(targets)),
                    indicators=indicators,
                    metadata={"target_count": len(targets), "total_transitions": total_dispatch_targets}
                )
        return None
