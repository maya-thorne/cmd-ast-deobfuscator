"""
cmd-ast-deobfuscator: Formal EBNF Grammar Models, Rules & Conformance Telemetry.
Defines data structures representing formal grammar rules, validation outcomes,
and aggregate conformance audit reports for Microsoft Windows cmd.exe scripts.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
import json
import time


class GrammarRuleType(str, Enum):
    """Classification of grammar rules according to language hierarchy."""
    LEXICAL = "lexical"
    SYNTACTIC = "syntactic"
    EXPANSION = "expansion"
    CONTROL_FLOW = "control_flow"
    REDIRECTION = "redirection"
    ATOM = "atom"


class ValidationStatus(str, Enum):
    """Validation outcome for a grammar rule or test sample."""
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


@dataclass
class GrammarRule:
    """
    Formal Extended Backus-Naur Form (EBNF) grammar rule specification.
    Models production syntax, structural constraints, and mapped AST node types.
    """
    name: str
    rule_type: GrammarRuleType
    ebnf_expression: str
    description: str
    category: str
    ast_node_types: List[str] = field(default_factory=list)
    is_terminal: bool = False
    examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "rule_type": self.rule_type.value,
            "ebnf_expression": self.ebnf_expression,
            "description": self.description,
            "category": self.category,
            "ast_node_types": list(self.ast_node_types),
            "is_terminal": self.is_terminal,
            "examples": list(self.examples),
        }


@dataclass
class RuleValidationResult:
    """Individual rule validation result against an AST or code snippet."""
    rule_name: str
    status: ValidationStatus
    matched: bool
    occurrences: int = 0
    message: str = ""
    ast_node_types: List[str] = field(default_factory=list)
    matched_samples: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "status": self.status.value,
            "matched": self.matched,
            "occurrences": self.occurrences,
            "message": self.message,
            "ast_node_types": list(self.ast_node_types),
            "matched_samples": list(self.matched_samples),
            "details": self.details,
        }


@dataclass
class SyntaxViolation:
    """Details of an EBNF grammar or structural AST violation."""
    rule_name: str
    message: str
    line_number: Optional[int] = None
    snippet: str = ""
    severity: str = "ERROR"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "message": self.message,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "severity": self.severity,
        }


@dataclass
class ConformanceReport:
    """
    Comprehensive EBNF conformance and coverage report.
    Aggregates per-rule validation, syntax violations, and test corpus results.
    """
    total_rules: int
    tested_rules: int
    covered_rules: int
    passed_rules: int
    failed_rules: int
    grammar_coverage_pct: float
    conformance_pct: float
    results: List[RuleValidationResult] = field(default_factory=list)
    violations: List[SyntaxViolation] = field(default_factory=list)
    corpus_results: Optional[List[Dict[str, Any]]] = None
    source_lines: int = 0
    ast_node_count: int = 0
    elapsed_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    is_conformant: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "is_conformant": self.is_conformant,
            "metrics": {
                "total_rules": self.total_rules,
                "tested_rules": self.tested_rules,
                "covered_rules": self.covered_rules,
                "passed_rules": self.passed_rules,
                "failed_rules": self.failed_rules,
                "grammar_coverage_pct": round(self.grammar_coverage_pct, 2),
                "conformance_pct": round(self.conformance_pct, 2),
                "source_lines": self.source_lines,
                "ast_node_count": self.ast_node_count,
                "elapsed_ms": round(self.elapsed_ms, 2),
            },
            "results": [r.to_dict() for r in self.results],
            "violations": [v.to_dict() for v in self.violations],
            "corpus_results": self.corpus_results,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        status_str = "PASS" if self.is_conformant else "FAIL"
        return (
            f"EBNF Conformance: [{status_str}] | "
            f"Coverage: {self.covered_rules}/{self.total_rules} ({self.grammar_coverage_pct:.1f}%) | "
            f"Conformance: {self.passed_rules}/{self.covered_rules} "
            f"({self.conformance_pct:.1f}%) | Violations: {len(self.violations)} | Elapsed: {self.elapsed_ms:.2f}ms"
        )

    def to_markdown(self) -> str:
        status_badge = "[PASS] CONFORMANT" if self.is_conformant else "[FAIL] NON-CONFORMANT"
        lines = [
            f"# cmd.exe EBNF Grammar Conformance Report",
            f"",
            f"**Evaluation Status:** {status_badge}  ",
            f"**Timestamp:** `{self.timestamp}`  ",
            f"**Grammar Coverage:** `{self.grammar_coverage_pct:.1f}%` ({self.covered_rules}/{self.total_rules} rules)  ",
            f"**Rule Conformance:** `{self.conformance_pct:.1f}%` ({self.passed_rules}/{self.covered_rules} passed)  ",
            f"**Total Violations:** `{len(self.violations)}`  ",
            f"**Execution Time:** `{self.elapsed_ms:.2f} ms`  ",
            f"",
            f"## Grammar Metrics Summary",
            f"",
            f"| Metric | Value |",
            f"|:---|:---|",
            f"| Total Grammar Rules | `{self.total_rules}` |",
            f"| Covered Rules | `{self.covered_rules}` |",
            f"| Passed Rules | `{self.passed_rules}` |",
            f"| Failed Rules | `{self.failed_rules}` |",
            f"| Grammar Coverage | `{self.grammar_coverage_pct:.1f}%` |",
            f"| Conformance Rate | `{self.conformance_pct:.1f}%` |",
            f"| Source Lines Analyzed | `{self.source_lines}` |",
            f"| AST Nodes Evaluated | `{self.ast_node_count}` |",
            f"",
        ]

        if self.violations:
            lines.extend([
                f"## Syntax & Conformance Violations",
                f"",
                f"| Rule | Severity | Line | Message | Snippet |",
                f"|:---|:---|:---|:---|:---|",
            ])
            for v in self.violations:
                line_str = str(v.line_number) if v.line_number is not None else "-"
                snippet_clean = v.snippet.replace("\n", " ").replace("|", "\\|")[:40]
                lines.append(f"| `{v.rule_name}` | `{v.severity}` | `{line_str}` | {v.message} | `{snippet_clean}` |")
            lines.append("")

        lines.extend([
            f"## Rule Evaluation Breakdown",
            f"",
            f"| Rule Name | Status | Occurrences | AST Nodes | Message |",
            f"|:---|:---|:---|:---|:---|",
        ])
        for r in self.results:
            icon = "[PASS]" if r.status == ValidationStatus.PASS else (
                "[FAIL]" if r.status == ValidationStatus.FAIL else (
                    "[PARTIAL]" if r.status == ValidationStatus.PARTIAL else "[SKIPPED]"
                )
            )
            node_types = ", ".join(r.ast_node_types) if r.ast_node_types else "-"
            msg = r.message if r.message else "Conformant"
            lines.append(f"| `{r.rule_name}` | {icon} | `{r.occurrences}` | `{node_types}` | {msg} |")
        lines.append("")

        if self.corpus_results:
            lines.extend([
                f"## Canonical Corpus Suite Results",
                f"",
                f"| ID | Sample Name | Category | Status | Rules Tested | Elapsed |",
                f"|:---|:---|:---|:---|:---|:---|",
            ])
            for c in self.corpus_results:
                c_icon = "[PASS]" if c.get("status") == "PASS" else "[FAIL]"
                c_id = c.get("id", "-")
                c_name = c.get("name", "-")
                c_cat = c.get("category", "-")
                c_rules = len(c.get("covered_rules", []))
                c_elapsed = f"{c.get('elapsed_ms', 0.0):.2f}ms"
                lines.append(f"| `{c_id}` | {c_name} | `{c_cat}` | {c_icon} | `{c_rules}` | `{c_elapsed}` |")
            lines.append("")

        return "\n".join(lines)


@dataclass
class GrammarSpecification:
    """
    Complete registry of cmd.exe formal EBNF grammar rules.
    Provides rule lookup, category filtering, and EBNF text generation.
    """
    title: str = "Formal cmd.exe EBNF Grammar Specification"
    version: str = "0.20.0"
    rules: Dict[str, GrammarRule] = field(default_factory=dict)

    def add_rule(self, rule: GrammarRule) -> None:
        self.rules[rule.name] = rule

    def get_rule(self, name: str) -> Optional[GrammarRule]:
        return self.rules.get(name)

    @property
    def rule_names(self) -> List[str]:
        return list(self.rules.keys())

    def list_rules(
        self,
        rule_type: Optional[GrammarRuleType] = None,
        category: Optional[str] = None
    ) -> List[GrammarRule]:
        result = list(self.rules.values())
        if rule_type is not None:
            result = [r for r in result if r.rule_type == rule_type]
        if category is not None:
            result = [r for r in result if r.category == category]
        return result

    def to_ebnf_text(self) -> str:
        """Exports the full formal EBNF grammar specification text."""
        sections: Dict[str, List[GrammarRule]] = {}
        for r in self.rules.values():
            sections.setdefault(r.category, []).append(r)

        output = [
            f"(* ======================================================== *)",
            f"(* {self.title} (v{self.version}) *)",
            f"(* ======================================================== *)",
            f"",
        ]

        for cat, rule_list in sections.items():
            output.append(f"(* --- {cat.upper()} PRODUCTIONS --- *)")
            for r in rule_list:
                output.append(f"(* {r.description} *)")
                output.append(f"{r.ebnf_expression}")
                output.append("")
            output.append("")

        return "\n".join(output)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "version": self.version,
            "total_rules": len(self.rules),
            "rules": {name: r.to_dict() for name, r in self.rules.items()},
        }
