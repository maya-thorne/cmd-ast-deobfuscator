"""
Python 3 Emitter for Intermediate Representation (IR).
Produces clean, idiomatic, PEP 8-compliant Python code from batch script IR.
"""

import re
from typing import List, Set, Optional
from ..models import (
    IRProgram, IRBlock, IRFunction, IRStatement, IRExpression,
    IRConstant, IRVariable, IRPathModifier, IRBinaryOp, IRUnaryOp,
    IRSlice, IRSubst, IRAssignment, IRExec, IREcho, IRRedirect,
    IRIf, IRFor, IRCall, IRReturn, IRLabel, IRGoto, IRChain, IRPipe,
    IRComment, IROpType, IRStreamType
)


class PythonEmitter:
    """Emits clean, production-grade Python 3 code from an IRProgram."""

    def __init__(self, indent_str: str = "    ", wrap_in_main: bool = True):
        self.indent_str = indent_str
        self.wrap_in_main = wrap_in_main
        self._required_modules: Set[str] = set()
        self._needs_script_dir: bool = False

    def emit(self, program: IRProgram) -> str:
        """Translates an IRProgram into formatted Python 3 source text."""
        self._required_modules = set()
        self._needs_script_dir = False

        # First pass: collect necessary imports and requirements
        self._inspect_program(program)

        lines: List[str] = []
        lines.append('"""')
        lines.append('Clean Python 3 translation transpiled from batch script.')
        lines.append('"""')
        lines.append("")

        # Module imports
        if not self._required_modules:
            self._required_modules.add("sys")

        sorted_mods = sorted(list(self._required_modules))
        for mod in sorted_mods:
            if mod == "Path":
                lines.append("from pathlib import Path")
            else:
                lines.append(f"import {mod}")

        lines.append("")

        if self._needs_script_dir:
            lines.append("SCRIPT_DIR = Path(__file__).resolve().parent")
            lines.append("")

        # Emit lifted subroutines as Python functions
        for func_name, func_obj in program.functions.items():
            py_func_name = self._sanitize_identifier(func_name)
            lines.append(f"def {py_func_name}(*args):")
            func_lines = self._emit_block(func_obj.body, indent_level=1)
            if not func_lines:
                func_lines.append(f"{self.indent_str}pass")
            lines.extend(func_lines)
            lines.append("")

        # Emit main entry point
        if self.wrap_in_main:
            lines.append("def main():")
            entry_lines = self._emit_block(program.entry_block, indent_level=1)
            if not entry_lines:
                entry_lines.append(f"{self.indent_str}pass")
            lines.extend(entry_lines)
            lines.append("")
            lines.append('if __name__ == "__main__":')
            lines.append(f"{self.indent_str}main()")
        else:
            entry_lines = self._emit_block(program.entry_block, indent_level=0)
            lines.extend(entry_lines)

        return "\n".join(lines).rstrip() + "\n"

    def _inspect_program(self, program: IRProgram) -> None:
        """Determines required standard library imports."""
        def _check_expr(e: IRExpression):
            if isinstance(e, IRVariable) and e.is_env:
                self._required_modules.add("os")
            elif isinstance(e, IRPathModifier):
                self._required_modules.add("Path")
                if e.is_script_dir:
                    self._needs_script_dir = True

        def _check_stmt(s: IRStatement):
            if isinstance(s, IRAssignment):
                if s.is_env:
                    self._required_modules.add("os")
                _check_expr(s.value)
            elif isinstance(s, IRExec):
                self._required_modules.add("subprocess")
                if s.is_builtin:
                    if s.builtin_kind in ("cls", "cd"):
                        self._required_modules.add("os")
                    elif s.builtin_kind in ("mkdir", "del"):
                        self._required_modules.add("Path")
                    elif s.builtin_kind in ("rmdir", "copy", "move"):
                        self._required_modules.add("shutil")
                    elif s.builtin_kind == "timeout":
                        self._required_modules.add("time")
                for a in s.args:
                    _check_expr(a)
            elif isinstance(s, IRReturn):
                if not s.is_subroutine_return:
                    self._required_modules.add("sys")
            elif isinstance(s, IRFor):
                if s.loop_type == "files":
                    self._required_modules.add("Path")
                for b in s.body.statements:
                    _check_stmt(b)
            elif isinstance(s, IRIf):
                _check_expr(s.condition)
                for ts in s.then_body.statements:
                    _check_stmt(ts)
                if s.else_body:
                    for es in s.else_body.statements:
                        _check_stmt(es)
            elif isinstance(s, (IRChain, IRPipe)):
                self._required_modules.add("subprocess")
                if hasattr(s, "left") and s.left:
                    _check_stmt(s.left)
                if hasattr(s, "right") and s.right:
                    _check_stmt(s.right)

        for stmt in program.entry_block.statements:
            _check_stmt(stmt)

        for func in program.functions.values():
            for stmt in func.body.statements:
                _check_stmt(stmt)

    def _emit_block(self, block: IRBlock, indent_level: int) -> List[str]:
        """Translates a sequence of IRStatements into indented lines."""
        lines: List[str] = []
        indent = self.indent_str * indent_level

        for stmt in block.statements:
            stmt_lines = self._emit_statement(stmt, indent_level)
            lines.extend(stmt_lines)

        return lines

    def _emit_statement(self, stmt: IRStatement, indent_level: int) -> List[str]:
        """Translates a single IRStatement."""
        indent = self.indent_str * indent_level
        lines: List[str] = []

        if isinstance(stmt, IRComment):
            clean_cmt = stmt.text.lstrip(": \t").replace("REM ", "").replace("rem ", "")
            lines.append(f"{indent}# {clean_cmt.strip()}")

        elif isinstance(stmt, IRAssignment):
            val_code = self._emit_expr(stmt.value)
            if stmt.is_env:
                lines.append(f'{indent}os.environ["{stmt.target}"] = str({val_code})')
            else:
                var_name = self._sanitize_identifier(stmt.target)
                lines.append(f"{indent}{var_name} = {val_code}")

        elif isinstance(stmt, IREcho):
            if not stmt.content:
                lines.append(f"{indent}print()")
            else:
                args_code = ", ".join(self._emit_expr(c) for c in stmt.content)
                if stmt.target_stream == IRStreamType.STDERR:
                    lines.append(f"{indent}print({args_code}, file=sys.stderr)")
                else:
                    lines.append(f"{indent}print({args_code})")

        elif isinstance(stmt, IRExec):
            lines.extend(self._emit_exec(stmt, indent_level))

        elif isinstance(stmt, IRIf):
            cond_code = self._emit_condition(stmt.condition)
            lines.append(f"{indent}if {cond_code}:")
            then_lines = self._emit_block(stmt.then_body, indent_level + 1)
            if not then_lines:
                then_lines.append(f"{self.indent_str * (indent_level + 1)}pass")
            lines.extend(then_lines)

            if stmt.else_body and stmt.else_body.statements:
                lines.append(f"{indent}else:")
                else_lines = self._emit_block(stmt.else_body, indent_level + 1)
                if not else_lines:
                    else_lines.append(f"{self.indent_str * (indent_level + 1)}pass")
                lines.extend(else_lines)

        elif isinstance(stmt, IRFor):
            it = self._sanitize_identifier(stmt.iterator)
            if stmt.loop_type == "range":
                lines.append(f"{indent}for {it} in range({stmt.range_start}, {stmt.range_end} + 1, {stmt.range_step}):")
            elif stmt.loop_type == "files":
                method = "rglob" if stmt.is_recursive else "glob"
                pat = stmt.file_pattern or "*"
                lines.append(f'{indent}for {it} in Path(".").{method}("{pat}"):')
            elif stmt.loop_type == "items":
                items_code = ", ".join(self._emit_expr(i) for i in stmt.items)
                lines.append(f"{indent}for {it} in [{items_code}]:")
            else:
                lines.append(f"{indent}for {it} in []:")

            body_lines = self._emit_block(stmt.body, indent_level + 1)
            if not body_lines:
                body_lines.append(f"{self.indent_str * (indent_level + 1)}pass")
            lines.extend(body_lines)

        elif isinstance(stmt, IRCall):
            if stmt.is_subroutine:
                func_name = self._sanitize_identifier(stmt.target)
                args_code = ", ".join(self._emit_expr(a) for a in stmt.args)
                lines.append(f"{indent}{func_name}({args_code})")
            else:
                cmd_parts = [repr(stmt.target)] + [self._emit_expr(a) for a in stmt.args]
                lines.append(f"{indent}subprocess.run([{', '.join(cmd_parts)}], check=True)")

        elif isinstance(stmt, IRReturn):
            if stmt.is_subroutine_return:
                ret_val = self._emit_expr(stmt.exit_code) if stmt.exit_code else ""
                lines.append(f"{indent}return {ret_val}".rstrip())
            else:
                code_val = self._emit_expr(stmt.exit_code) if stmt.exit_code else "0"
                lines.append(f"{indent}sys.exit({code_val})")

        elif isinstance(stmt, IRLabel):
            lines.append(f"{indent}# Label: {stmt.name}")

        elif isinstance(stmt, IRGoto):
            lines.append(f"{indent}# goto {stmt.target} (handled via control flow)")

        elif isinstance(stmt, IRChain):
            # Sequential or conditional chain
            if stmt.operator == "&&":
                lines.extend(self._emit_statement(stmt.left, indent_level))
                lines.extend(self._emit_statement(stmt.right, indent_level))
            elif stmt.operator == "||":
                lines.append(f"{indent}try:")
                lines.extend(self._emit_statement(stmt.left, indent_level + 1))
                lines.append(f"{indent}except Exception:")
                lines.extend(self._emit_statement(stmt.right, indent_level + 1))
            else:
                lines.extend(self._emit_statement(stmt.left, indent_level))
                lines.extend(self._emit_statement(stmt.right, indent_level))

        elif isinstance(stmt, IRPipe):
            # Subprocess pipe
            lines.append(f"{indent}# Pipeline: {stmt}")

        return lines

    def _emit_exec(self, stmt: IRExec, indent_level: int) -> List[str]:
        """Translates built-in or external commands into Python standard calls."""
        indent = self.indent_str * indent_level
        lines: List[str] = []

        if stmt.is_builtin:
            kind = stmt.builtin_kind
            if kind == "cls":
                return [f'{indent}os.system("cls" if os.name == "nt" else "clear")']
            elif kind == "pause":
                return [f'{indent}input("Press Enter to continue...")']
            elif kind == "timeout":
                sec = "1"
                if stmt.args:
                    sec = self._emit_expr(stmt.args[0])
                return [f"{indent}time.sleep({sec})"]
            elif kind == "mkdir":
                if stmt.args:
                    p = self._emit_expr(stmt.args[0])
                    return [f"{indent}Path({p}).mkdir(parents=True, exist_ok=True)"]
            elif kind == "del":
                if stmt.args:
                    p = self._emit_expr(stmt.args[0])
                    return [f"{indent}Path({p}).unlink(missing_ok=True)"]
            elif kind == "rmdir":
                if stmt.args:
                    p = self._emit_expr(stmt.args[0])
                    return [f"{indent}shutil.rmtree({p}, ignore_errors=True)"]
            elif kind == "copy":
                if len(stmt.args) >= 2:
                    src = self._emit_expr(stmt.args[0])
                    dst = self._emit_expr(stmt.args[1])
                    return [f"{indent}shutil.copy({src}, {dst})"]
            elif kind == "move":
                if len(stmt.args) >= 2:
                    src = self._emit_expr(stmt.args[0])
                    dst = self._emit_expr(stmt.args[1])
                    return [f"{indent}shutil.move({src}, {dst})"]
            elif kind == "cd":
                if stmt.args:
                    target = self._emit_expr(stmt.args[0])
                    return [f"{indent}os.chdir({target})"]

        # Default external command execution
        cmd_items = [repr(stmt.command)] + [self._emit_expr(a) for a in stmt.args]
        stdout_kw = ""
        stderr_kw = ""
        for r in stmt.redirects:
            if r.is_devnull:
                stdout_kw = ", stdout=subprocess.DEVNULL"
                stderr_kw = ", stderr=subprocess.DEVNULL"

        lines.append(f"{indent}subprocess.run([{', '.join(cmd_items)}]{stdout_kw}{stderr_kw}, check=False)")
        return lines

    def _emit_expr(self, expr: IRExpression) -> str:
        """Translates an IRExpression into a valid Python expression string."""
        if isinstance(expr, IRConstant):
            if expr.type_hint == "int":
                return str(expr.value)
            elif expr.type_hint == "bool":
                return "True" if expr.value else "False"
            return repr(str(expr.value))

        elif isinstance(expr, IRVariable):
            if expr.is_positional:
                return f"sys.argv[{expr.pos_index}] if len(sys.argv) > {expr.pos_index} else ''"
            elif expr.is_all_args:
                return "' '.join(sys.argv[1:])"
            elif expr.is_env:
                return f'os.environ.get("{expr.name}", "")'
            return self._sanitize_identifier(expr.name)

        elif isinstance(expr, IRPathModifier):
            if expr.is_script_dir:
                return "str(SCRIPT_DIR)"
            elif expr.is_script_path:
                return "str(Path(__file__).resolve())"
            return f"str(Path(sys.argv[{expr.target_var}]))"

        elif isinstance(expr, IRSlice):
            var_access = f'os.environ.get("{expr.var_name}", "")'
            start = expr.start if expr.start is not None else 0
            if expr.length is not None:
                end = start + expr.length
                return f"{var_access}[{start}:{end}]"
            return f"{var_access}[{start}:]"

        elif isinstance(expr, IRSubst):
            var_access = f'os.environ.get("{expr.var_name}", "")'
            return f"{var_access}.replace({repr(expr.search)}, {repr(expr.replace)})"

        elif isinstance(expr, IRBinaryOp):
            left_str = self._emit_expr(expr.left)
            right_str = self._emit_expr(expr.right)
            if expr.op == IROpType.CONCAT:
                return f"str({left_str}) + str({right_str})"
            return f"({left_str} {expr.op.value} {right_str})"

        elif isinstance(expr, IRUnaryOp):
            return f"({expr.op} {self._emit_expr(expr.operand)})"

        return repr(str(expr))

    def _emit_condition(self, expr: IRExpression) -> str:
        """Translates an IR condition expression to Python boolean logic."""
        if isinstance(expr, IRBinaryOp):
            if expr.left == IRConstant("exist"):
                self._required_modules.add("Path")
                target = self._emit_expr(expr.right)
                return f"Path({target}).exists()"

            left_code = self._emit_expr(expr.left)
            right_code = self._emit_expr(expr.right)
            op_sym = expr.op.value
            return f"{left_code} {op_sym} {right_code}"

        elif isinstance(expr, IRUnaryOp):
            if expr.op == "not":
                return f"not ({self._emit_condition(expr.operand)})"

        return self._emit_expr(expr)

    def _sanitize_identifier(self, name: str) -> str:
        """Sanitizes names into valid Python function/variable identifiers."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name.strip())
        if not clean or clean[0].isdigit():
            clean = f"var_{clean}"
        return clean.lower()
