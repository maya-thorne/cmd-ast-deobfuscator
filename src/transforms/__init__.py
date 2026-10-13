"""
AST Transformation and Optimization Pass Infrastructure for cmd-ast-deobfuscator.
Exports the base TransformPass, PassManager pipeline, SlicingFolderPass, ConstantFolderPass,
CaretNormalizerPass, and run_transforms runner.
"""

from .base import TransformPass, PassManager, run_transforms
from .slicing_folder import SlicingFolderPass
from .constant_folder import ConstantFolderPass
from .caret_normalizer import CaretNormalizerPass, normalize_carets
from .param_resolver import ParamResolverPass
from .arithmetic_folder import ArithmeticFolderPass, fold_arithmetic
from .reversal_folder import ReversalFolderPass
from .dce import (
    DeadCodeEliminationPass,
    VariableLivenessAnalyzer,
    DCEMetrics,
    eliminate_dead_code,
)
from .quote_normalizer import QuoteNormalizerPass

__all__ = [
    'TransformPass',
    'PassManager',
    'SlicingFolderPass',
    'ConstantFolderPass',
    'CaretNormalizerPass',
    'QuoteNormalizerPass',
    'ParamResolverPass',
    'ArithmeticFolderPass',
    'fold_arithmetic',
    'ReversalFolderPass',
    'DeadCodeEliminationPass',
    'VariableLivenessAnalyzer',
    'DCEMetrics',
    'eliminate_dead_code',
    'run_transforms',
    'normalize_carets',
]

