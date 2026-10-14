"""
Transpiler target emitters for Intermediate Representation (IR).
"""

from .python import PythonEmitter
from .powershell import PowerShellEmitter

__all__ = ["PythonEmitter", "PowerShellEmitter"]
