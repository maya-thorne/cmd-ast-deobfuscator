"""
CLI Presentation and Formatting Helper for Sigma SIEM Integration.
"""

import sys
from typing import Optional

from src.ast_nodes import ASTNode
from src.sigma.detector import ObfuscationPrimitiveDetector
from src.sigma.generator import SigmaRuleGenerator
from src.sigma.models import PrimitiveSeverity, SIEMTarget, SigmaAnalysisResult
from src.sigma.transpiler import SIEMTranspiler


def handle_sigma_cli(
    args,
    norm_ast: Optional[ASTNode],
    source: str,
    clean_code: str,
) -> None:
    """Handles CLI flags for obfuscation primitive detection and Sigma rule generation."""
    min_confidence = getattr(args, "sigma_min_confidence", 0.5) or 0.5
    detector = ObfuscationPrimitiveDetector(min_confidence=min_confidence)

    # Perform analysis across both AST and raw text (prefer raw source for tokens + AST for structure)
    analysis_text = source or clean_code or ""
    res: SigmaAnalysisResult = detector.detect(
        ast_root=norm_ast,
        source_text=analysis_text,
        source_file=getattr(args, "input", None),
    )

    # Filter minimum severity if requested
    min_sev_str = getattr(args, "sigma_min_severity", None)
    if min_sev_str:
        sev_rank = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            target_idx = sev_rank.index(min_sev_str.upper())
            res.primitives = [
                p for p in res.primitives
                if sev_rank.index(p.severity.value) >= target_idx
            ]
        except ValueError:
            pass

    # Generate rules if requested or if generating SIEM dialect
    target_dialect_str = getattr(args, "sigma_target", "yaml") or "yaml"
    try:
        target_dialect = SIEMTarget(target_dialect_str.lower())
    except ValueError:
        target_dialect = SIEMTarget.YAML

    generator = SigmaRuleGenerator()
    custom_title = getattr(args, "sigma_title", None)
    custom_id = getattr(args, "sigma_rule_id", None)
    rules = generator.generate_rules(res, custom_title=custom_title, custom_rule_id=custom_id)

    # Transpile rules
    transpiler = SIEMTranspiler()
    emitted_rules: list[str] = []
    for r in rules:
        emitted_rules.append(transpiler.transpile(r, target=target_dialect))

    output_content = "\n\n---\n\n".join(emitted_rules) if emitted_rules else ""

    # CLI Output Handlers
    if getattr(args, "sigma_score", False):
        print("\n=== [BATCH OBFUSCATION RISK SCORE] ===")
        print(f"  Score            : {res.score.score} / 100.0")
        print(f"  Threat Level     : {res.score.level}")
        print(f"  Total Primitives : {res.score.total_primitives}")
        print(f"  Shannon Entropy  : {res.score.entropy:.4f}")
        if res.score.primitive_counts:
            print("  Breakdown by Primitive:")
            for p_type, count in res.score.primitive_counts.items():
                print(f"    - {p_type:<26}: {count}")

    if getattr(args, "sigma_detect", False):
        print("\n" + res.to_markdown())

    if getattr(args, "sigma_generate", False) or getattr(args, "sigma_target", None):
        if output_content:
            if not getattr(args, "sigma_out", None):
                print(f"\n=== [GENERATED SIEM RULES ({target_dialect.value.upper()})] ===")
                print(output_content)

    out_path = getattr(args, "sigma_out", None)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            if output_content:
                f.write(output_content + "\n")
            else:
                f.write(res.to_markdown() + "\n")
        print(f"[✓] Sigma SIEM output written to {out_path}")
