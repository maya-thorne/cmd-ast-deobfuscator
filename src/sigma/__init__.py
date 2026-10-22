"""
cmd-ast-deobfuscator: Enterprise SIEM / Sigma Rule Integration & Obfuscation Primitive Detector.
"""

from .detector import ObfuscationPrimitiveDetector
from .generator import SigmaRuleGenerator
from .models import (
    ObfuscationPrimitive,
    ObfuscationPrimitiveType,
    ObfuscationScore,
    PrimitiveSeverity,
    SIEMTarget,
    SigmaAnalysisResult,
    SigmaRule,
)
from .transforms import SigmaTransformPass, analyze_sigma_primitives
from .transpiler import SIEMTranspiler

__all__ = [
    "ObfuscationPrimitiveDetector",
    "SigmaRuleGenerator",
    "SIEMTranspiler",
    "SigmaTransformPass",
    "analyze_sigma_primitives",
    "ObfuscationPrimitive",
    "ObfuscationPrimitiveType",
    "PrimitiveSeverity",
    "ObfuscationScore",
    "SigmaRule",
    "SigmaAnalysisResult",
    "SIEMTarget",
]
