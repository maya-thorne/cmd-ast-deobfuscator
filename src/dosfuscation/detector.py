#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Invoke-DOSfuscation Concatenation Pattern Detector
Provides static heuristic detection and scoring for Invoke-DOSfuscation levels:
- Level 1: Basic Environment Variable Concatenation
- Level 2: Array / Indexed Slicing Concatenation
- Level 3: Interleaved Junk / Empty Variable Obfuscation
- Level 4: Scrambled Parameter Delimiters (, ; =)
- Level 5: Compound Multi-Layered Trampolines & Accumulators
"""

import re
import math
from typing import Dict, List, Optional, Tuple, Any
from .models import ConcatenationType


class DosfuscationDetector:
    """
    Heuristic analyzer that scores scripts based on Invoke-DOSfuscation
    concatenation signatures, token fragmentation, and syntax scrambling.
    """

    def __init__(self):
        pass

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon entropy of text."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        freq: Dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def analyze_script(self, script_content: str) -> Dict[str, Any]:
        """
        Computes fragmentation metrics, delimiter scrambling metrics,
        and an overall DOSfuscation concatenation confidence score.
        """
        lines = script_content.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return {
                "dosfuscation_score": 0.0,
                "is_dosfuscated": False,
                "detected_levels": [],
                "metrics": {}
            }

        var_pattern = re.compile(r'[%!][a-zA-Z0-9_\-\.\$\[\]\:\~,]+[%!]')
        delim_pattern = re.compile(r'[,;]{2,}|(?:[,;]\s*[,;])')
        empty_var_pattern = re.compile(r'set\s+(?:")?[a-zA-Z0-9_\-\.\$]+=(?:")?\s*(?:&|$)', re.IGNORECASE)
        for_accum_pattern = re.compile(
            r'for\s+(?:%|%%)[a-zA-Z0-9_]\s+in\s*\([^)]+\)\s+do\s+set\s+(?:")?[a-zA-Z0-9_\-\.\$]+=[%!]',
            re.IGNORECASE
        )
        call_trampoline_pattern = re.compile(r'call\s+[%!][a-zA-Z0-9_\-\.\$]+[%!]', re.IGNORECASE)

        total_vars = 0
        total_chars = len(script_content)
        total_delims = 0
        empty_var_count = 0
        for_accum_count = 0
        call_trampoline_count = 0
        short_var_assignments = 0

        # Scan for SET statements with small values (<= 3 chars)
        set_assign_pattern = re.compile(
            r'set\s+(?:/a\s+|/p\s+)?(?:")?[a-zA-Z0-9_\-\.\$]+=(?P<val>[^"&\r\n]{1,3})(?:")?\s*(?:&|$)',
            re.IGNORECASE
        )

        for line in lines:
            vars_found = var_pattern.findall(line)
            total_vars += len(vars_found)

            delims_found = delim_pattern.findall(line)
            total_delims += len(delims_found)

            if empty_var_pattern.search(line):
                empty_var_count += 1

            if for_accum_pattern.search(line):
                for_accum_count += 1

            if call_trampoline_pattern.search(line):
                call_trampoline_count += 1

            matches = set_assign_pattern.findall(line)
            short_var_assignments += len(matches)

        var_density = total_vars / max(1, total_lines)
        short_var_ratio = short_var_assignments / max(1, total_lines)

        detected_levels: List[str] = []

        # Level 1: Basic variable chaining
        if total_vars >= 4 and short_var_assignments >= 2:
            detected_levels.append("Level 1: Basic Variable Concatenation")

        # Level 2: Array / slice concatenation
        if re.search(r'\[\d+\]', script_content) or re.search(r':~-?\d+,\d+', script_content):
            if total_vars >= 3:
                detected_levels.append("Level 2: Indexed Array / Slice Concatenation")

        # Level 3: Junk / empty variable interleaving
        if empty_var_count > 0 or re.search(r':~,0|:~0,0', script_content):
            detected_levels.append("Level 3: Interleaved Junk Variable Obfuscation")

        # Level 4: Delimiter scrambling
        if total_delims >= 1 or re.search(r'[a-zA-Z0-9_]+[,;=]+[a-zA-Z0-9_]+', script_content):
            detected_levels.append("Level 4: Scrambled Delimiter Injection")

        # Level 5: Compound accumulator or trampoline
        if for_accum_count > 0 or call_trampoline_count > 0:
            detected_levels.append("Level 5: Dynamic Trampoline & Loop Accumulator")

        # Calculate composite score (0.0 to 1.0)
        score = 0.0
        score += min(0.35, var_density * 0.1)
        score += min(0.25, short_var_ratio * 0.15)
        score += min(0.20, (total_delims > 0) * 0.20)
        score += min(0.15, (empty_var_count > 0) * 0.15)
        score += min(0.25, (for_accum_count > 0) * 0.25)
        score += min(0.15, (call_trampoline_count > 0) * 0.15)

        normalized_score = min(1.0, round(score, 3))
        is_dosf = normalized_score >= 0.30 or len(detected_levels) >= 1

        return {
            "dosfuscation_score": normalized_score,
            "is_dosfuscated": is_dosf,
            "detected_levels": detected_levels,
            "metrics": {
                "total_vars": total_vars,
                "short_var_assignments": short_var_assignments,
                "total_delims": total_delims,
                "empty_var_count": empty_var_count,
                "for_accum_count": for_accum_count,
                "call_trampoline_count": call_trampoline_count,
                "entropy": round(self.calculate_entropy(script_content), 3)
            }
        }

    def is_dosfuscated(self, script_content: str, threshold: float = 0.30) -> bool:
        """Returns True if the script is assessed as Invoke-DOSfuscated."""
        analysis = self.analyze_script(script_content)
        return analysis["dosfuscation_score"] >= threshold or len(analysis["detected_levels"]) >= 1
