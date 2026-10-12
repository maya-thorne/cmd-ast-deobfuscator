"""
AST Transformation and Optimization Pass Infrastructure for cmd-ast-deobfuscator.
Exports the base TransformPass, PassManager pipeline, SlicingFolderPass, ConstantFolderPass,
and run_transforms runner.
"""

from .base import TransformPass, PassManager, run_transforms
from .slicing_folder import SlicingFolderPass
from .constant_folder import ConstantFolderPass

__all__ = [
    'TransformPass',
    'PassManager',
    'SlicingFolderPass',
    'ConstantFolderPass',
    'run_transforms',
]
