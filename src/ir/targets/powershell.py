"""
PowerShell Emitter for Intermediate Representation (IR).
Produces clean, idiomatic PowerShell (.ps1) code from batch script IR.
"""

import re
from typing import List, Optional
from ..models import (
    IRProgram, IRBlock, IRFunction, IRStatement, IRExpression,
    IRConstant, IRVariable, IRPathModifier, IRBinaryOp, IRUnaryOp,
    IRSlice, IRSubst, IRAssignment, IRExec, IREcho, IRRedirect,
    IRIf, IRFor, IRCall, IRReturn, IRLabel, IRGoto, IRChain, IRPipe,
    IRComment, IROpType, IRStreamType
)


class PowerShellEmitter:
    """Emits clean, production-grade PowerShell code from an IRProgram."""

    def __init__(self, indent_str: str = "    "):
        self.indent_str = indent_str

    def emit(self, program: IRProgram) -> str:
        """Translates an IRProgram into formatted PowerShell script text."""
        lines: List[str] = []
        lines.append("<#")
        lines.append("Clean PowerShell translation transpiled from batch script.")
        lines.append("#>")
        lines.append("")

        # Emit lifted subroutines as PowerShell functions
        for func_name, func_obj in program.functions.items():
            ps_func_name = self._to_ps_function_name(func_name)
            lines.append(f"function {ps_func_name} {{")
            lines.append(f"{self.indent_str}[CmdletBinding()]")
            lines.append(f"{self.indent_str}param()")
            func_lines = self._emit_block(func_obj.body, indent_level=1)
            lines.extend(func_lines)
            lines.append("}")
            lines.append("")

        # Emit main entry statements
        entry_lines = self._emit_block(program.entry_block, indent_level=0)
        lines.extend(entry_lines)

        return "\n".join(lines).rstrip() + "\n"

    def _emit_block(self, block: IRBlock, indent_level: int) -> List[str]:
        """Translates a sequence of IRStatements into indented PowerShell lines."""
        lines: List[str] = []
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
                lines.append(f'{indent}$env:{stmt.target} = [string]({val_code})')
            else:
                var_name = self._sanitize_identifier(stmt.target)
                lines.append(f"{indent}${var_name} = {val_code}")

        elif isinstance(stmt, IREcho):
            if not stmt.content:
                lines.append(f"{indent}Write-Host ''")
            else:
                args_code = " ".join(self._emit_expr(c) for c in stmt.content)
                redir_code = self._format_redirects(stmt.redirects)
                lines.append(f"{indent}Write-Host {args_code}{redir_code}".rstrip())

        elif isinstance(stmt, IRExec):
            lines.extend(self._emit_exec(stmt, indent_level))

        elif isinstance(stmt, IRIf):
            cond_code = self._emit_condition(stmt.condition)
            lines.append(f"{indent}if ({cond_code}) {{")
            then_lines = self._emit_block(stmt.then_body, indent_level + 1)
            lines.extend(then_lines)

            if stmt.else_body and stmt.else_body.statements:
                lines.append(f"{indent}}} else {{")
                else_lines = self._emit_block(stmt.else_body, indent_level + 1)
                lines.extend(else_lines)

            lines.append(f"{indent}}}")

        elif isinstance(stmt, IRFor):
            it = self._sanitize_identifier(stmt.iterator)
            if stmt.loop_type == "range":
                lines.append(f"{indent}for (${it} = {stmt.range_start}; ${it} -le {stmt.range_end}; ${it} += {stmt.range_step}) {{")
            elif stmt.loop_type == "files":
                recurse_flag = " -Recurse" if stmt.is_recursive else ""
                pat = stmt.file_pattern or "*"
                lines.append(f'{indent}foreach (${it} in (Get-ChildItem -Path "{pat}"{recurse_flag})) {{')
            elif stmt.loop_type == "items":
                items_code = ", ".join(self._emit_expr(i) for i in stmt.items)
                lines.append(f"{indent}foreach (${it} in @({items_code})) {{")
            else:
                lines.append(f"{indent}foreach (${it} in @()) {{")

            body_lines = self._emit_block(stmt.body, indent_level + 1)
            lines.extend(body_lines)
            lines.append(f"{indent}}}")

        elif isinstance(stmt, IRCall):
            if stmt.is_subroutine:
                func_name = self._to_ps_function_name(stmt.target)
                args_code = " ".join(self._emit_expr(a) for a in stmt.args)
                lines.append(f"{indent}{func_name} {args_code}".rstrip())
            else:
                cmd_code = self._format_command_target(stmt.target)
                args_code = " ".join(self._emit_expr(a) for a in stmt.args)
                lines.append(f"{indent}& {cmd_code} {args_code}".rstrip())

        elif isinstance(stmt, IRReturn):
            if stmt.is_subroutine_return:
                ret_val = f" {self._emit_expr(stmt.exit_code)}" if stmt.exit_code else ""
                lines.append(f"{indent}return{ret_val}".rstrip())
            else:
                code_val = f" {self._emit_expr(stmt.exit_code)}" if stmt.exit_code else " 0"
                lines.append(f"{indent}exit{code_val}".rstrip())

        elif isinstance(stmt, IRLabel):
            lines.append(f"{indent}# :label {stmt.name}")

        elif isinstance(stmt, IRGoto):
            lines.append(f"{indent}# goto {stmt.target}")

        elif isinstance(stmt, IRChain):
            if stmt.operator == "&&":
                lines.extend(self._emit_statement(stmt.left, indent_level))
                lines.append(f"{indent}if ($?) {{")
                lines.extend(self._emit_statement(stmt.right, indent_level + 1))
                lines.append(f"{indent}}}")
            elif stmt.operator == "||":
                lines.extend(self._emit_statement(stmt.left, indent_level))
                lines.append(f"{indent}if (-not $?) {{")
                lines.extend(self._emit_statement(stmt.right, indent_level + 1))
                lines.append(f"{indent}}}")
            else:
                lines.extend(self._emit_statement(stmt.left, indent_level))
                lines.extend(self._emit_statement(stmt.right, indent_level))

        elif isinstance(stmt, IRPipe):
            lines.append(f"{indent}# Pipeline: {stmt}")

        return lines

    def _emit_exec(self, stmt: IRExec, indent_level: int) -> List[str]:
        """Translates built-in or external commands into PowerShell calls."""
        indent = self.indent_str * indent_level

        if stmt.is_builtin:
            kind = stmt.builtin_kind
            if kind == "cls":
                return [f"{indent}Clear-Host"]
            elif kind == "pause":
                return [f'{indent}Read-Host "Press Enter to continue..." | Out-Null']
            elif kind == "timeout":
                sec = "1"
                if stmt.args:
                    sec = self._emit_expr(stmt.args[0])
                return [f"{indent}Start-Sleep -Seconds {sec}"]
            elif kind == "mkdir":
                if stmt.args:
                    p = self._emit_expr(stmt.args[0])
                    return [f"{indent}New-Item -ItemType Directory -Path {p} -Force | Out-Null"]
            elif kind == "del":
                if stmt.args:
                    p = self._emit_expr(stmt.args[0])
                    return [f"{indent}Remove-Item -Path {p} -Force -ErrorAction SilentlyContinue"]
            elif kind == "rmdir":
                if stmt.args:
                    p = self._emit_expr(stmt.args[0])
                    return [f"{indent}Remove-Item -Path {p} -Recurse -Force -ErrorAction SilentlyContinue"]
            elif kind == "copy":
                if len(stmt.args) >= 2:
                    src = self._emit_expr(stmt.args[0])
                    dst = self._emit_expr(stmt.args[1])
                    return [f"{indent}Copy-Item -Path {src} -Destination {dst} -Force"]
            elif kind == "move":
                if len(stmt.args) >= 2:
                    src = self._emit_expr(stmt.args[0])
                    dst = self._emit_expr(stmt.args[1])
                    return [f"{indent}Move-Item -Path {src} -Destination {dst} -Force"]
            elif kind == "cd":
                if stmt.args:
                    target = self._emit_expr(stmt.args[0])
                    return [f"{indent}Set-Location -Path {target}"]

        cmd_code = self._format_command_target(stmt.command)
        args_code = " ".join(self._emit_expr(a) for a in stmt.args)
        redir_code = self._format_redirects(stmt.redirects)

        line = f"{indent}& {cmd_code}"
        if args_code:
            line += f" {args_code}"
        if redir_code:
            line += f" {redir_code}"
        return [line.strip()]

    def _emit_expr(self, expr: IRExpression) -> str:
        """Translates an IRExpression into a valid PowerShell expression string."""
        if isinstance(expr, IRConstant):
            if expr.type_hint == "int":
                return str(expr.value)
            elif expr.type_hint == "bool":
                return "$true" if expr.value else "$false"
            return f'"{self._escape_ps_string(str(expr.value))}"'

        elif isinstance(expr, IRVariable):
            if expr.is_positional:
                return f"$args[{expr.pos_index}]"
            elif expr.is_all_args:
                return "$args"
            elif expr.is_env:
                return f"$env:{expr.name}"
            return f"${self._sanitize_identifier(expr.name)}"

        elif isinstance(expr, IRPathModifier):
            if expr.is_script_dir:
                return "$PSScriptRoot"
            elif expr.is_script_path:
                return "$MyInvocation.MyCommand.Path"
            return f"$args[{expr.target_var}]"

        elif isinstance(expr, IRSlice):
            var_ref = f"$env:{expr.var_name}"
            start = expr.start if expr.start is not None else 0
            if expr.length is not None:
                return f"({var_ref}.Substring({start}, {expr.length}))"
            return f"({var_ref}.Substring({start}))"

        elif isinstance(expr, IRSubst):
            var_ref = f"$env:{expr.var_name}"
            search_str = f'"{self._escape_ps_string(expr.search)}"'
            replace_str = f'"{self._escape_ps_string(expr.replace)}"'
            return f"({var_ref}.Replace({search_str}, {replace_str}))"

        elif isinstance(expr, IRBinaryOp):
            left_str = self._emit_expr(expr.left)
            right_str = self._emit_expr(expr.right)
            if expr.op == IROpType.CONCAT:
                return f"({left_str} + {right_str})"
            ps_ops = {
                IROpType.ADD: "+",
                IROpType.SUB: "-",
                IROpType.MUL: "*",
                IROpType.DIV: "/",
                IROpType.MOD: "%",
                IROpType.EQ: "-eq",
                IROpType.NEQ: "-ne",
                IROpType.LT: "-lt",
                IROpType.LTE: "-le",
                IROpType.GT: "-gt",
                IROpType.GTE: "-ge",
            }
            op_str = ps_ops.get(expr.op, "+")
            return f"({left_str} {op_str} {right_str})"

        elif isinstance(expr, IRUnaryOp):
            op_sym = "-not " if expr.op == "not" else "-"
            return f"({op_sym}{self._emit_expr(expr.operand)})"

        return f'"{expr}"'

    def _emit_condition(self, expr: IRExpression) -> str:
        """Translates an IR condition into PowerShell boolean syntax."""
        if isinstance(expr, IRBinaryOp):
            if expr.left == IRConstant("exist"):
                target = self._emit_expr(expr.right)
                return f"Test-Path -Path {target}"

            left_code = self._emit_expr(expr.left)
            right_code = self._emit_expr(expr.right)
            ps_cmp_map = {
                IROpType.EQ: "-eq",
                IROpType.NEQ: "-ne",
                IROpType.LT: "-lt",
                IROpType.LTE: "-le",
                IROpType.GT: "-gt",
                IROpType.GTE: "-ge",
            }
            op_code = ps_cmp_map.get(expr.op, "-eq")
            return f"{left_code} {op_code} {right_code}"

        elif isinstance(expr, IRUnaryOp):
            if expr.op == "not":
                return f"-not ({self._emit_condition(expr.operand)})"

        return self._emit_expr(expr)

    def _format_redirects(self, redirects: List[IRRedirect]) -> str:
        """Formats redirect operators for PowerShell."""
        parts = []
        for r in redirects:
            if r.is_devnull:
                parts.append("| Out-Null")
            elif r.operator == ">>":
                parts.append(f'| Out-File -FilePath "{r.destination}" -Append')
            elif r.operator == ">":
                parts.append(f'| Out-File -FilePath "{r.destination}"')
        return " " + " ".join(parts) if parts else ""

    def _format_command_target(self, cmd: str) -> str:
        """Formats a command name safely for execution operator '&'."""
        clean = cmd.strip().strip('"')
        if " " in clean or "\\" in clean or "/" in clean:
            return f'"{clean}"'
        return clean

    def _to_ps_function_name(self, name: str) -> str:
        """Maps subroutine name to PowerShell verb-noun convention."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name.strip())
        parts = clean.split("_")
        capitalized = "".join(p.capitalize() for p in parts if p)
        return f"Invoke-{capitalized or 'Sub'}"

    def _sanitize_identifier(self, name: str) -> str:
        """Sanitizes names into valid PowerShell variable identifiers."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name.strip())
        if not clean or clean[0].isdigit():
            clean = f"var_{clean}"
        return clean

    def _escape_ps_string(self, text: str) -> str:
        """Escapes quotes and dollar signs in PowerShell strings."""
        return text.replace("`", "``").replace('"', '`"').replace("$", "`$")
