"""
AST Transformation and Optimization Pass Infrastructure for cmd-ast-deobfuscator.
Exports the base TransformPass, PassManager pipeline, SlicingFolderPass, ConstantFolderPass,
CaretNormalizerPass, and run_transforms runner.
"""

from .base import TransformPass, PassManager, run_transforms
from .slicing_folder import SlicingFolderPass
from .constant_folder import ConstantFolderPass
from .caret_normalizer import CaretNormalizerPass, normalize_carets

__all__ = [
    'TransformPass',
    'PassManager',
    'SlicingFolderPass',
    'ConstantFolderPass',
    'CaretNormalizerPass',
    'run_transforms',
    'normalize_carets',
]
