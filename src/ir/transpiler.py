"""
High-Level Batch Transpiler Coordinator.
Converts cmd.exe batch scripts into clean, production-grade Python or PowerShell via IR.
"""

import time
from typing import Union, Optional, Dict, Any
from dataclasses import dataclass, field

from ..ast_nodes import ASTNode
from ..parser import CmdASTParser
from .models import IRProgram, IRMetrics
from .builder import ASTToIRBuilder
from .targets.python import PythonEmitter
from .targets.powershell import PowerShellEmitter


@dataclass
class TranspilationResult:
    """Holds the outcome and telemetry of a transpilation run."""
    target_language: str = "python"
    emitted_code: str = ""
    ir_program: Optional[IRProgram] = None
    metrics: IRMetrics = field(default_factory=IRMetrics)

    def zeroize(self) -> None:
        """Securely zeroizes emitted code buffers and internal telemetry."""
        self.emitted_code = ""
        if self.metrics:
            self.metrics.zeroize()
        self.ir_program = None


class BatchTranspiler:
    """End-to-end coordinator for converting batch scripts to Python or PowerShell."""

    def __init__(self, deobfuscate_first: bool = False):
        self.deobfuscate_first = deobfuscate_first
        self.builder = ASTToIRBuilder()

    def transpile(
        self,
        source_or_ast: Union[str, ASTNode],
        target: str = "python",
        wrap_in_main: bool = True,
        indent_str: str = "    ",
    ) -> TranspilationResult:
        """Transpiles input batch source or AST into the chosen target language."""
        start_time = time.perf_counter()

        # Step 1: Obtain AST
        if isinstance(source_or_ast, str):
            source = source_or_ast
            if self.deobfuscate_first:
                from ..deobfuscator_engine import BatchDeobfuscator
                engine = BatchDeobfuscator()
                source = engine.deobfuscate(source)
            ast = CmdASTParser.from_source(source).parse()
        else:
            ast = source_or_ast

        # Step 2: Build Intermediate Representation (IR)
        ir_program = self.builder.build(ast)

        # Step 3: Emit target code
        target_norm = target.strip().lower()
        if target_norm in ("python", "py"):
            emitter = PythonEmitter(indent_str=indent_str, wrap_in_main=wrap_in_main)
            emitted = emitter.emit(ir_program)
            lang_name = "python"
        elif target_norm in ("powershell", "ps1", "posh"):
            emitter = PowerShellEmitter(indent_str=indent_str)
            emitted = emitter.emit(ir_program)
            lang_name = "powershell"
        else:
            raise ValueError(f"Unsupported transpilation target: {target}. Choose 'python' or 'powershell'.")

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        self.builder.metrics.transpile_time_ms = elapsed_ms

        return TranspilationResult(
            target_language=lang_name,
            emitted_code=emitted,
            ir_program=ir_program,
            metrics=self.builder.metrics
        )

    def transpile_to_python(
        self,
        source_or_ast: Union[str, ASTNode],
        wrap_in_main: bool = True
    ) -> str:
        """Convenience method returning pure Python 3 code."""
        res = self.transpile(source_or_ast, target="python", wrap_in_main=wrap_in_main)
        return res.emitted_code

    def transpile_to_powershell(
        self,
        source_or_ast: Union[str, ASTNode]
    ) -> str:
        """Convenience method returning pure PowerShell code."""
        res = self.transpile(source_or_ast, target="powershell")
        return res.emitted_code
