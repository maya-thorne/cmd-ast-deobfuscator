"""
AST Transform Pass for Malware Indicator of Compromise (IOC) Extraction.
Integrates with the cmd-ast-deobfuscator PassManager pipeline.
"""

from typing import Dict, List, Optional, Union

from ..ast_nodes import ASTNode
from ..transforms.base import TransformPass
from .extractor import IOCExtractor
from .models import IOCExtractionResult, IOCMetrics


class IOCTransformPass(TransformPass):
    """
    Compiler pipeline transform pass that inspects deobfuscated AST trees,
    extracts malware IOCs, maps MITRE ATT&CK techniques, and tracks telemetry.
    """

    def __init__(
        self,
        name: Optional[str] = None,
        min_confidence: float = 0.0,
        env: Optional[Dict[str, str]] = None,
    ):
        super().__init__(name=name or "IOCTransformPass", env=env)
        self.min_confidence = min_confidence
        self.extractor = IOCExtractor(min_confidence=min_confidence)
        self.ioc_result: Optional[IOCExtractionResult] = None
        self.metrics: IOCMetrics = IOCMetrics()

    def transform(self, root: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        """Executes IOC extraction across the AST and records telemetry."""
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v

        self.ioc_result = self.extractor.extract_from_ast(root)
        self.metrics = self.ioc_result.metrics
        self.modified = False
        return root


def extract_iocs(
    target: Union[ASTNode, str],
    min_confidence: float = 0.0,
    source_file: Optional[str] = None,
) -> IOCExtractionResult:
    """Convenience helper to extract malware IOCs from either an ASTNode or raw source string."""
    extractor = IOCExtractor(min_confidence=min_confidence)
    if isinstance(target, str):
        return extractor.extract_from_source(target, source_file=source_file)
    elif isinstance(target, ASTNode):
        return extractor.extract_from_ast(target, source_file=source_file)
    raise TypeError(f"Expected ASTNode or str, got {type(target).__name__}")
