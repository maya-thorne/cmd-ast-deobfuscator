"""
Sigma Rule Synthesizer for Automated SIEM Detection Rule Generation.
"""

from typing import Any, Dict, List, Optional
import uuid

from src.sigma.models import (
    ObfuscationPrimitive,
    ObfuscationPrimitiveType,
    PrimitiveSeverity,
    SigmaAnalysisResult,
    SigmaRule,
)


class SigmaRuleGenerator:
    """Synthesizes compliant Sigma v2.0 YAML rules from detected obfuscation primitives."""

    def __init__(self, author: str = "cmd-ast-deobfuscator", default_level: str = "high"):
        self.author = author
        self.default_level = default_level

    def generate_rules(
        self,
        analysis_result: SigmaAnalysisResult,
        custom_title: Optional[str] = None,
        custom_rule_id: Optional[str] = None,
    ) -> List[SigmaRule]:
        """Generates both generic behavioral and sample-specific Sigma rules from analysis."""
        rules: List[SigmaRule] = []

        if not analysis_result.primitives:
            return rules

        # 1. Behavioral rule covering detected primitive categories
        behavioral_rule = self.generate_behavioral_rule(
            analysis_result.primitives,
            custom_title=custom_title,
            custom_rule_id=custom_rule_id,
        )
        if behavioral_rule:
            rules.append(behavioral_rule)

        # 2. Targeted rule if high-confidence critical primitives exist (e.g. stubs, heavy concatenation)
        critical_primitives = [
            p for p in analysis_result.primitives
            if p.severity in (PrimitiveSeverity.HIGH, PrimitiveSeverity.CRITICAL)
        ]
        if critical_primitives:
            targeted_rule = self.generate_targeted_rule(critical_primitives)
            if targeted_rule:
                rules.append(targeted_rule)

        # Attach to result
        analysis_result.rules = rules
        return rules

    def generate_behavioral_rule(
        self,
        primitives: List[ObfuscationPrimitive],
        custom_title: Optional[str] = None,
        custom_rule_id: Optional[str] = None,
    ) -> Optional[SigmaRule]:
        """Synthesizes a generic behavioral process_creation detection rule."""
        if not primitives:
            return None

        # Gather tags from MITRE mappings
        tags: List[str] = ["attack.defense_evasion", "attack.execution", "attack.t1059.003"]
        for p in primitives:
            if p.mitre_attack and p.mitre_attack.technique_id:
                tid = p.mitre_attack.technique_id.lower()
                tag_entry = f"attack.{tid}"
                if tag_entry not in tags:
                    tags.append(tag_entry)

        # Build detection logic based on present primitives
        detection: Dict[str, Any] = {}
        selection_keys: List[str] = []

        # Check for carets
        has_carets = any(p.primitive_type == ObfuscationPrimitiveType.CARET_INSERTION for p in primitives)
        if has_carets:
            detection["selection_carets"] = {
                "CommandLine|contains": ["^c^", "^m^", "^d^", "^p^", "^o^", "^w^", "^e^", "^r^", "^^^"]
            }
            selection_keys.append("selection_carets")

        # Check for quote interleaving
        has_quotes = any(p.primitive_type == ObfuscationPrimitiveType.QUOTE_INTERLEAVING for p in primitives)
        if has_quotes:
            detection["selection_quotes"] = {
                "CommandLine|contains": ['"c"m"d"', '""p""', '""whoami""', '""powershell""', '""cmd""']
            }
            selection_keys.append("selection_quotes")

        # Check for substring slicing
        has_slices = any(
            p.primitive_type in (ObfuscationPrimitiveType.SUBSTRING_SLICING, ObfuscationPrimitiveType.REVERSE_SLICING)
            for p in primitives
        )
        if has_slices:
            detection["selection_slices"] = {
                "CommandLine|contains": [":~0,1", ":~1,1", ":~2,1", ":~-1", ":~-2"]
            }
            selection_keys.append("selection_slices")

        # Check for delimiter scrambling
        has_delims = any(p.primitive_type == ObfuscationPrimitiveType.DELIMITER_SCRAMBLING for p in primitives)
        if has_delims:
            detection["selection_delimiters"] = {
                "CommandLine|contains": ["cmd.exe,", "cmd.exe;", "cmd.exe=", "cmd,/", "cmd;/"]
            }
            selection_keys.append("selection_delimiters")

        # Check for script dropper stubs
        has_droppers = any(p.primitive_type == ObfuscationPrimitiveType.SCRIPT_STUB_DROPPING for p in primitives)
        if has_droppers:
            detection["selection_droppers"] = {
                "CommandLine|contains": ["-enc", "-EncodedCommand", "certutil", "-decode", "-decodehex"]
            }
            selection_keys.append("selection_droppers")

        # Check for dynamic trampolines
        has_trampolines = any(p.primitive_type == ObfuscationPrimitiveType.DYNAMIC_CALL_TRAMPOLINE for p in primitives)
        if has_trampolines:
            detection["selection_trampoline"] = {
                "CommandLine|contains": ["call :%", "call !"]
            }
            selection_keys.append("selection_trampoline")

        if not selection_keys:
            # Fallback to general cmdline pattern
            detection["selection_generic"] = {
                "CommandLine|contains": ["cmd", "powershell"]
            }
            selection_keys.append("selection_generic")

        # Condition logic
        if len(selection_keys) == 1:
            detection["condition"] = selection_keys[0]
        else:
            detection["condition"] = "1 of selection_*"

        rule_id = custom_rule_id or str(uuid.uuid4())
        title = custom_title or "Suspicious Batch Command Line Obfuscation Primitives"

        # Determine level based on highest severity
        max_sev = max(
            (p.severity for p in primitives),
            key=lambda s: ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s.value),
        )
        level_map = {
            PrimitiveSeverity.INFORMATIONAL: "low",
            PrimitiveSeverity.LOW: "low",
            PrimitiveSeverity.MEDIUM: "medium",
            PrimitiveSeverity.HIGH: "high",
            PrimitiveSeverity.CRITICAL: "critical",
        }
        level = level_map.get(max_sev, self.default_level)

        return SigmaRule(
            title=title,
            rule_id=rule_id,
            status="experimental",
            description=(
                "Detects the execution of Windows command-line scripts employing "
                "adversarial obfuscation primitives such as character-level caret escaping, "
                "quote interleaving, substring slicing, and delimiter scrambling."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1027/010/",
                "https://github.com/danielbohannon/Invoke-DOSfuscation",
            ],
            author=self.author,
            tags=tags,
            logsource={"category": "process_creation", "product": "windows"},
            detection=detection,
            level=level,
        )

    def generate_targeted_rule(self, primitives: List[ObfuscationPrimitive]) -> Optional[SigmaRule]:
        """Synthesizes a targeted detection rule matching specific matched token signatures."""
        if not primitives:
            return None

        tokens: List[str] = []
        for p in primitives:
            if p.matched_token and len(p.matched_token) > 2:
                # Defang / clean token for inclusion
                tok = p.matched_token.strip()
                if tok not in tokens:
                    tokens.append(tok)

        if not tokens:
            return None

        detection: Dict[str, Any] = {
            "selection": {
                "CommandLine|contains": tokens[:10]  # Limit to top 10 signatures
            },
            "condition": "selection",
        }

        tags = ["attack.defense_evasion", "attack.t1027", "attack.execution", "attack.t1059.003"]

        return SigmaRule(
            title="Targeted Batch Script Obfuscation Signatures",
            rule_id=str(uuid.uuid4()),
            status="experimental",
            description="Detects specific command-line strings and tokens associated with obfuscated batch execution.",
            references=["https://attack.mitre.org/techniques/T1027/"],
            author=self.author,
            tags=tags,
            logsource={"category": "process_creation", "product": "windows"},
            detection=detection,
            level="high",
        )
