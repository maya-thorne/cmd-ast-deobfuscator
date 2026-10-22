"""
Data models, enumerations, telemetry metrics, and zeroization protocols for
Enterprise SIEM & Sigma Rule Obfuscation Primitive Detection.
"""

from dataclasses import dataclass, field
from enum import Enum
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Set

from src.ioc.models import MitreAttackMapping, MitreTactic


class ObfuscationPrimitiveType(str, Enum):
    """Classification of batch command-line obfuscation primitives."""
    CARET_INSERTION = "caret_insertion"
    QUOTE_INTERLEAVING = "quote_interleaving"
    SUBSTRING_SLICING = "substring_slicing"
    ENV_CONCATENATION = "env_concatenation"
    DELIMITER_SCRAMBLING = "delimiter_scrambling"
    ARITHMETIC_ENCODING = "arithmetic_encoding"
    STRING_REVERSAL = "string_reversal"
    DYNAMIC_CALL_TRAMPOLINE = "dynamic_call_trampoline"
    IO_STEALTH_REDIRECTION = "io_stealth_redirection"
    CFF_DISPATCHER = "cff_dispatcher"
    DEAD_STORE_BLOAT = "dead_store_bloat"
    SCRIPT_STUB_DROPPING = "script_stub_dropping"
    REVERSE_SLICING = "reverse_slicing"


class PrimitiveSeverity(str, Enum):
    """Threat severity levels for detected obfuscation primitives."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SIEMTarget(str, Enum):
    """Supported SIEM and detection rule target dialects."""
    YAML = "yaml"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"
    QRADAR = "qradar"
    JSON = "json"


@dataclass
class ObfuscationPrimitive:
    """An individual detected batch obfuscation primitive."""
    primitive_type: ObfuscationPrimitiveType
    severity: PrimitiveSeverity
    confidence: float
    description: str
    line_number: int
    matched_token: str
    ast_node_type: str = ""
    mitre_attack: Optional[MitreAttackMapping] = None
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the primitive into a dictionary representation."""
        res: Dict[str, Any] = {
            "primitive_type": (
                self.primitive_type.value
                if isinstance(self.primitive_type, ObfuscationPrimitiveType)
                else str(self.primitive_type)
            ),
            "severity": (
                self.severity.value
                if isinstance(self.severity, PrimitiveSeverity)
                else str(self.severity)
            ),
            "confidence": round(self.confidence, 4),
            "description": self.description,
            "line_number": self.line_number,
            "matched_token": self.matched_token,
            "ast_node_type": self.ast_node_type,
            "weight": round(self.weight, 2),
            "metadata": dict(self.metadata),
        }
        if self.mitre_attack:
            res["mitre_attack"] = self.mitre_attack.to_dict()
        else:
            res["mitre_attack"] = None
        return res

    def zeroize(self) -> None:
        """Securely cleanses in-memory token strings and metadata."""
        if self.description:
            self.description = "\x00" * len(self.description)
        if self.matched_token:
            self.matched_token = "\x00" * len(self.matched_token)
        self.metadata.clear()
        self.confidence = 0.0
        self.weight = 0.0


@dataclass
class ObfuscationScore:
    """Composite quantification of obfuscation depth and risk classification."""
    score: float
    level: str
    primitive_counts: Dict[str, int] = field(default_factory=dict)
    total_primitives: int = 0
    entropy: float = 0.0

    @classmethod
    def calculate(
        cls,
        primitives: List[ObfuscationPrimitive],
        entropy: float = 0.0,
    ) -> "ObfuscationScore":
        """Calculates a normalized 0.0 - 100.0 score based on primitive weights and entropy."""
        if not primitives:
            return cls(score=0.0, level="CLEAN", primitive_counts={}, total_primitives=0, entropy=entropy)

        counts: Dict[str, int] = {}
        weighted_sum = 0.0

        severity_multipliers = {
            PrimitiveSeverity.INFORMATIONAL: 0.5,
            PrimitiveSeverity.LOW: 1.0,
            PrimitiveSeverity.MEDIUM: 2.5,
            PrimitiveSeverity.HIGH: 5.0,
            PrimitiveSeverity.CRITICAL: 10.0,
        }

        for p in primitives:
            p_key = p.primitive_type.value if isinstance(p.primitive_type, ObfuscationPrimitiveType) else str(p.primitive_type)
            counts[p_key] = counts.get(p_key, 0) + 1
            mult = severity_multipliers.get(p.severity, 1.0)
            weighted_sum += p.weight * mult * p.confidence

        # Logarithmic saturation to 0 - 100 range
        raw_score = (weighted_sum * 3.5) + (max(0.0, entropy - 4.5) * 6.0)
        final_score = min(100.0, max(0.0, round(raw_score, 1)))

        if final_score < 15.0:
            level = "CLEAN"
        elif final_score < 35.0:
            level = "LOW_SUSPICION"
        elif final_score < 65.0:
            level = "MODERATELY_OBFUSCATED"
        elif final_score < 85.0:
            level = "HIGHLY_OBFUSCATED"
        else:
            level = "MALICIOUS"

        return cls(
            score=final_score,
            level=level,
            primitive_counts=counts,
            total_primitives=len(primitives),
            entropy=round(entropy, 4),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes scoring metrics into a dictionary."""
        return {
            "score": self.score,
            "level": self.level,
            "primitive_counts": dict(self.primitive_counts),
            "total_primitives": self.total_primitives,
            "entropy": self.entropy,
        }

    def zeroize(self) -> None:
        """Resets all metrics in memory."""
        self.score = 0.0
        self.level = "CLEAN"
        self.primitive_counts.clear()
        self.total_primitives = 0
        self.entropy = 0.0


@dataclass
class SigmaRule:
    """Standard Sigma v2.0 Rule representation with multi-target transpilation."""
    title: str
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "experimental"
    description: str = ""
    references: List[str] = field(default_factory=list)
    author: str = "cmd-ast-deobfuscator"
    date: str = "2026-10-22"
    modified: str = ""
    tags: List[str] = field(default_factory=list)
    logsource: Dict[str, str] = field(
        default_factory=lambda: {"category": "process_creation", "product": "windows"}
    )
    detection: Dict[str, Any] = field(default_factory=dict)
    falsepositives: List[str] = field(
        default_factory=lambda: [
            "Administrative batch scripts",
            "Legacy enterprise automation wrappers",
        ]
    )
    level: str = "high"

    def to_dict(self) -> Dict[str, Any]:
        """Converts the Sigma rule to a structured dictionary."""
        data: Dict[str, Any] = {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status,
            "description": self.description,
            "references": list(self.references),
            "author": self.author,
            "date": self.date,
        }
        if self.modified:
            data["modified"] = self.modified
        data["tags"] = list(self.tags)
        data["logsource"] = dict(self.logsource)
        data["detection"] = dict(self.detection)
        data["falsepositives"] = list(self.falsepositives)
        data["level"] = self.level
        return data

    def to_yaml(self) -> str:
        """Serializes the Sigma rule into a compliant YAML string without external libraries."""
        lines: List[str] = []
        lines.append(f"title: {self._escape_yaml_val(self.title)}")
        lines.append(f"id: {self.rule_id}")
        lines.append(f"status: {self.status}")
        lines.append(f"description: {self._escape_yaml_val(self.description)}")
        if self.references:
            lines.append("references:")
            for ref in self.references:
                lines.append(f"    - {self._escape_yaml_val(ref)}")
        lines.append(f"author: {self._escape_yaml_val(self.author)}")
        lines.append(f"date: '{self.date}'")
        if self.modified:
            lines.append(f"modified: '{self.modified}'")
        if self.tags:
            lines.append("tags:")
            for tag in self.tags:
                lines.append(f"    - {tag}")
        lines.append("logsource:")
        for k, v in self.logsource.items():
            lines.append(f"    {k}: {v}")

        lines.append("detection:")
        self._format_detection_yaml(self.detection, lines, indent=4)

        if self.falsepositives:
            lines.append("falsepositives:")
            for fp in self.falsepositives:
                lines.append(f"    - {self._escape_yaml_val(fp)}")
        lines.append(f"level: {self.level}")
        return "\n".join(lines) + "\n"

    def _format_detection_yaml(self, d: Dict[str, Any], lines: List[str], indent: int) -> None:
        """Helper to format nested detection dicts into YAML."""
        prefix = " " * indent
        for key, val in d.items():
            if isinstance(val, dict):
                lines.append(f"{prefix}{key}:")
                self._format_detection_yaml(val, lines, indent + 4)
            elif isinstance(val, list):
                lines.append(f"{prefix}{key}:")
                for item in val:
                    lines.append(f"{prefix}    - {self._escape_yaml_val(str(item))}")
            else:
                lines.append(f"{prefix}{key}: {self._escape_yaml_val(str(val))}")

    @staticmethod
    def _escape_yaml_val(val: str) -> str:
        """Safely quotes and escapes YAML strings."""
        if not val:
            return "''"
        if any(c in val for c in ":#%&*!|>'\"[]{}?,\n"):
            escaped = val.replace("'", "''")
            return f"'{escaped}'"
        return val

    def zeroize(self) -> None:
        """Securely cleanses in-memory rule strings."""
        if self.title:
            self.title = "\x00" * len(self.title)
        if self.description:
            self.description = "\x00" * len(self.description)
        self.references.clear()
        self.tags.clear()
        self.detection.clear()
        self.falsepositives.clear()


@dataclass
class SigmaAnalysisResult:
    """Comprehensive container for detected primitives, scoring, and generated rules."""
    primitives: List[ObfuscationPrimitive] = field(default_factory=list)
    score: ObfuscationScore = field(default_factory=lambda: ObfuscationScore(0.0, "CLEAN"))
    rules: List[SigmaRule] = field(default_factory=list)
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the complete analysis results into a dictionary."""
        return {
            "source_file": self.source_file,
            "score": self.score.to_dict(),
            "total_primitives": len(self.primitives),
            "primitives": [p.to_dict() for p in self.primitives],
            "rules": [r.to_dict() for r in self.rules],
            "metadata": dict(self.metadata),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes the analysis results into a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Renders an enterprise security markdown summary report."""
        lines = [
            "# Batch Obfuscation Primitive & Sigma SIEM Analysis Report",
            "",
            f"**File / Target:** `{self.source_file or 'Inline Batch Script'}`  ",
            f"**Risk Score:** `{self.score.score} / 100.0` (`{self.score.level}`)  ",
            f"**Total Primitives Detected:** `{len(self.primitives)}`  ",
            f"**Calculated Shannon Entropy:** `{self.score.entropy:.4f}`  ",
            "",
            "## Detected Obfuscation Primitives",
            "",
            "| Line | Primitive Type | Severity | Confidence | Matched Pattern | MITRE Technique |",
            "|:---|:---|:---|:---|:---|:---|",
        ]

        if not self.primitives:
            lines.append("| - | *None* | INFORMATIONAL | 1.00 | Clean script baseline | - |")
        else:
            for p in self.primitives:
                p_type = p.primitive_type.value if isinstance(p.primitive_type, ObfuscationPrimitiveType) else str(p.primitive_type)
                p_sev = p.severity.value if isinstance(p.severity, PrimitiveSeverity) else str(p.severity)
                token_disp = p.matched_token.replace("|", "\\|").replace("\n", " ")
                if len(token_disp) > 36:
                    token_disp = token_disp[:33] + "..."
                mitre_str = p.mitre_attack.technique_id if p.mitre_attack else "N/A"
                lines.append(f"| `{p.line_number}` | `{p_type}` | `{p_sev}` | `{p.confidence:.2f}` | `{token_disp}` | `{mitre_str}` |")

        if self.rules:
            lines.append("")
            lines.append("## Generated Sigma Detection Rules")
            lines.append("")
            for r in self.rules:
                lines.append(f"### {r.title} (`{r.level.upper()}`)")
                lines.append("```yaml")
                lines.append(r.to_yaml().strip())
                lines.append("```")
                lines.append("")

        return "\n".join(lines) + "\n"

    def zeroize(self) -> None:
        """Securely cleanses in-memory analysis data."""
        for p in self.primitives:
            p.zeroize()
        self.primitives.clear()
        for r in self.rules:
            r.zeroize()
        self.rules.clear()
        self.score.zeroize()
        self.metadata.clear()
        if self.source_file:
            self.source_file = "\x00" * len(self.source_file)
            self.source_file = None
