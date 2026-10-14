"""
Unit and Integration Test Suite for Intermediate Representation (IR) and Transpiler Engine.
Verifies IR models, ASTToIRBuilder, PythonEmitter, PowerShellEmitter, BatchTranspiler, and CLI.
"""

import ast
import json
import unittest

from src.ast_nodes import ScriptNode, CommandNode, LiteralNode
from src.parser import CmdASTParser
from src.ir.models import (
    IRProgram, IRBlock, IRConstant, IRVariable, IRPathModifier,
    IRBinaryOp, IROpType, IRAssignment, IRExec, IREcho, IRIf, IRFor,
    IRCall, IRReturn, IRMetrics
)
from src.ir.builder import ASTToIRBuilder
from src.ir.targets.python import PythonEmitter
from src.ir.targets.powershell import PowerShellEmitter
from src.ir.transpiler import BatchTranspiler, TranspilationResult


class TestIRModelsAndZeroize(unittest.TestCase):
    """Verifies IR data models, serialization, and memory zeroization."""

    def test_ir_metrics_and_zeroize(self):
        metrics = IRMetrics(
            statements_created=10,
            commands_translated=5,
            variables_mapped=3,
            functions_lifted=2,
            loops_structured=1,
            branches_created=4,
            transpile_time_ms=12.5,
        )
        self.assertEqual(metrics.statements_created, 10)
        d = metrics.to_dict()
        self.assertEqual(d["commands_translated"], 5)
        self.assertIn("IR Metrics:", metrics.summary())

        metrics.zeroize()
        self.assertEqual(metrics.statements_created, 0)
        self.assertEqual(metrics.commands_translated, 0)
        self.assertEqual(metrics.transpile_time_ms, 0.0)

    def test_ir_node_serialization(self):
        block = IRBlock(statements=[
            IRAssignment(target="FOO", value=IRConstant("bar", "str")),
            IREcho(content=[IRConstant("hello")]),
        ])
        prog = IRProgram(entry_block=block, env_vars=["FOO"])
        d = prog.to_dict()
        self.assertEqual(d["node_type"], "IRProgram")
        self.assertIn("entry_block", d)
        self.assertEqual(len(d["entry_block"]["statements"]), 2)
        self.assertEqual(d["env_vars"], ["FOO"])

    def test_transpilation_result_zeroize(self):
        res = TranspilationResult(
            target_language="python",
            emitted_code="import os\nprint('secret')",
            metrics=IRMetrics(statements_created=5)
        )
        self.assertEqual(res.emitted_code, "import os\nprint('secret')")
        res.zeroize()
        self.assertEqual(res.emitted_code, "")
        self.assertEqual(res.metrics.statements_created, 0)


class TestASTToIRBuilder(unittest.TestCase):
    """Verifies translation of cmd.exe AST nodes into IRProgram structures."""

    def setUp(self):
        self.builder = ASTToIRBuilder()

    def test_builder_basic_commands(self):
        source = "@echo off\necho hello world\ncls\npause\nmkdir test_dir"
        ast_tree = CmdASTParser.from_source(source).parse()
        program = self.builder.build(ast_tree)

        self.assertIsInstance(program, IRProgram)
        stmts = program.entry_block.statements
        self.assertGreaterEqual(len(stmts), 4)

        # Check echo statement
        echo_stmt = next(s for s in stmts if isinstance(s, IREcho))
        self.assertIsNotNone(echo_stmt)

        # Check cls builtin
        cls_stmt = next(s for s in stmts if isinstance(s, IRExec) and s.builtin_kind == "cls")
        self.assertTrue(cls_stmt.is_builtin)

        # Check mkdir builtin
        mkdir_stmt = next(s for s in stmts if isinstance(s, IRExec) and s.builtin_kind == "mkdir")
        self.assertEqual(mkdir_stmt.builtin_kind, "mkdir")

    def test_builder_assignments_and_slices(self):
        source = 'set "TARGET=malware.bin"\nset /a NUM=10+2\necho %TARGET:~0,7%'
        ast_tree = CmdASTParser.from_source(source).parse()
        program = self.builder.build(ast_tree)

        stmts = program.entry_block.statements
        assignments = [s for s in stmts if isinstance(s, IRAssignment)]
        self.assertEqual(len(assignments), 2)
        self.assertEqual(assignments[0].target, "TARGET")
        self.assertTrue(assignments[1].is_arithmetic)

        # Check env vars collected
        self.assertIn("TARGET", program.env_vars)

    def test_builder_if_conditionals(self):
        source = 'if "%FLAG%"=="1" ( echo enabled ) else ( echo disabled )'
        ast_tree = CmdASTParser.from_source(source).parse()
        program = self.builder.build(ast_tree)

        if_stmts = [s for s in program.entry_block.statements if isinstance(s, IRIf)]
        self.assertEqual(len(if_stmts), 1)
        ir_if = if_stmts[0]
        self.assertIsInstance(ir_if.condition, IRBinaryOp)
        self.assertEqual(ir_if.condition.op, IROpType.EQ)
        self.assertIsNotNone(ir_if.then_body)
        self.assertIsNotNone(ir_if.else_body)

    def test_builder_for_numeric_range(self):
        source = "for /l %%i in (1, 2, 9) do echo %%i"
        ast_tree = CmdASTParser.from_source(source).parse()
        program = self.builder.build(ast_tree)

        for_stmts = [s for s in program.entry_block.statements if isinstance(s, IRFor)]
        self.assertEqual(len(for_stmts), 1)
        ir_for = for_stmts[0]
        self.assertEqual(ir_for.loop_type, "range")
        self.assertEqual(ir_for.range_start, 1)
        self.assertEqual(ir_for.range_step, 2)
        self.assertEqual(ir_for.range_end, 9)

    def test_builder_subroutine_lifting(self):
        source = (
            "@echo off\n"
            "call :do_work arg1\n"
            "exit /b 0\n"
            ":do_work\n"
            "echo inside work\n"
            "exit /b\n"
        )
        ast_tree = CmdASTParser.from_source(source).parse()
        program = self.builder.build(ast_tree)

        self.assertIn("do_work", program.functions)
        func = program.functions["do_work"]
        self.assertGreaterEqual(len(func.body.statements), 1)


class TestPythonEmitter(unittest.TestCase):
    """Verifies that PythonEmitter outputs clean, PEP 8, syntactically valid Python code."""

    def setUp(self):
        self.transpiler = BatchTranspiler()

    def test_python_syntax_compiles(self):
        batch_source = (
            "@echo off\n"
            'set "NAME=cmd_deobf"\n'
            "set /a VAL=42\n"
            "echo Running with %NAME%\n"
            'if exist "C:\\Windows" ( echo windows exists )\n'
            "for /l %%i in (0, 1, 3) do echo %%i\n"
            "cls\n"
            "timeout 2\n"
        )
        res = self.transpiler.transpile(batch_source, target="python")
        py_code = res.emitted_code

        # Mechanically verify that the emitted Python code compiles without syntax errors!
        try:
            parsed_ast = ast.parse(py_code)
            self.assertIsNotNone(parsed_ast)
        except SyntaxError as e:
            self.fail(f"Emitted Python code failed ast.parse(): {e}\n\nCode:\n{py_code}")

    def test_python_path_modifier_and_imports(self):
        batch_source = 'set "CURR_DIR=%~dp0"\necho %CURR_DIR%'
        res = self.transpiler.transpile(batch_source, target="python")
        py_code = res.emitted_code

        self.assertIn("SCRIPT_DIR = Path(__file__).resolve().parent", py_code)
        self.assertIn("from pathlib import Path", py_code)
        self.assertIn("os.environ", py_code)

    def test_python_subroutines(self):
        batch_source = (
            "call :cleanup\n"
            "exit /b 0\n"
            ":cleanup\n"
            "echo cleaning up\n"
            "exit /b\n"
        )
        res = self.transpiler.transpile(batch_source, target="python")
        py_code = res.emitted_code

        self.assertIn("def cleanup(*args):", py_code)
        self.assertIn("cleanup()", py_code)
        ast.parse(py_code)  # Must be valid syntax


class TestPowerShellEmitter(unittest.TestCase):
    """Verifies that PowerShellEmitter outputs clean, idiomatic PowerShell code."""

    def setUp(self):
        self.transpiler = BatchTranspiler()

    def test_powershell_emission(self):
        batch_source = (
            "@echo off\n"
            'set "MY_VAR=powershell_test"\n'
            "echo Output is %MY_VAR%\n"
            "mkdir my_folder\n"
            "del temp.txt\n"
            "for /l %%i in (1, 1, 5) do echo loop %%i\n"
        )
        res = self.transpiler.transpile(batch_source, target="powershell")
        ps_code = res.emitted_code

        self.assertIn('$env:MY_VAR = [string]("powershell_test")', ps_code)
        self.assertIn("Write-Host", ps_code)
        self.assertIn("New-Item -ItemType Directory", ps_code)
        self.assertIn("Remove-Item -Path", ps_code)
        self.assertIn("for ($i = 1; $i -le 5; $i += 1)", ps_code)

    def test_powershell_subroutine_functions(self):
        batch_source = (
            "call :init_system\n"
            "exit /b 0\n"
            ":init_system\n"
            "echo system init\n"
            "exit /b\n"
        )
        res = self.transpiler.transpile(batch_source, target="powershell")
        ps_code = res.emitted_code

        self.assertIn("function Invoke-InitSystem {", ps_code)
        self.assertIn("Invoke-InitSystem", ps_code)


class TestBatchTranspilerIntegration(unittest.TestCase):
    """Verifies end-to-end integration and deobfuscation pipeline."""

    def test_transpiler_deobfuscate_first(self):
        transpiler = BatchTranspiler(deobfuscate_first=True)
        # Obfuscated batch using caret escapes and variable slicing
        obfuscated = 's^e^t ^"X^=c^m^d^" & %X%'
        res = transpiler.transpile(obfuscated, target="python")
        self.assertIn("os.environ", res.emitted_code)
        self.assertGreater(res.metrics.statements_created, 0)
        ast.parse(res.emitted_code)

    def test_transpile_convenience_methods(self):
        transpiler = BatchTranspiler()
        source = "echo hello"
        py_code = transpiler.transpile_to_python(source)
        ps_code = transpiler.transpile_to_powershell(source)

        self.assertIn("print", py_code)
        self.assertIn("Write-Host", ps_code)


if __name__ == "__main__":
    unittest.main()
