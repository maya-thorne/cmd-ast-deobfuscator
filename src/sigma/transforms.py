"""
AST Transform Pass for Enterprise SIEM & Sigma Obfuscation Primitive Detection.
Integrates with the cmd-ast-deobfuscator PassManager pipeline.
"""

from typing import Dict, List, Optional, Union

from ..ast_nodes import ASTNode
from ..transforms.base import TransformPass
from .detector import ObfuscationPrimitiveDetector
from .generator import SigmaRuleGenerator
from .models import SigmaAnalysisResult, SigmaRule


class SigmaTransformPass(TransformPass):
    """
    Compiler pipeline transform pass that inspects AST structures,
    detects obfuscation primitives, calculates threat scoring, and synthesizes Sigma rules.
    """

    def __init__(
        self,
        name: Optional[str] = None,
        min_confidence: float = 0.5,
        generate_rules: bool = True,
        env: Optional[Dict[str, str]] = None,
    ):
        super().__init__(name=name or "SigmaTransformPass", env=env)
        self.min_confidence = min_confidence
        self.generate_rules = generate_rules
        self.detector = ObfuscationPrimitiveDetector(min_confidence=min_confidence)
        self.generator = SigmaRuleGenerator()
        self.analysis_result: Optional[SigmaAnalysisResult] = None

    def transform(self, root: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        """Executes primitive detection across the AST and attaches results."""
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v

        self.analysis_result = self.detector.detect(ast_root=root)
        if self.generate_rules and self.analysis_result.primitives:
            self.generator.generate_rules(self.analysis_result)

        self.modified = False
        return root


def analyze_sigma_primitives(
    target: Union[ASTNode, str],
    min_confidence: float = 0.5,
    source_file: Optional[str] = None,
    generate_rules: bool = True,
) -> SigmaAnalysisResult:
    """Convenience helper to detect obfuscation primitives and synthesize Sigma rules."""
    detector = ObfuscationPrimitiveDetector(min_confidence=min_confidence)
    if isinstance(target, str):
        result = detector.detect(source_text=target, source_file=source_file)
    elif isinstance(target, ASTNode):
        result = detector.detect(ast_root=target, source_file=source_file)
    else:
        raise TypeError(f"Expected ASTNode or str, got {type(target).__name__}")

    if generate_rules and result.primitives:
        generator = SigmaRuleGenerator()
        generator.generate_rules(result)

    return result
