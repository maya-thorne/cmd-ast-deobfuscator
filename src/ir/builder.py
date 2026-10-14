"""
AST-to-IR Builder for cmd.exe Batch Scripts.
Translates concrete cmd.exe AST trees into structured Intermediate Representation.
"""

import re
from typing import List, Optional, Dict, Set, Tuple
from ..ast_nodes import (
    ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode,
    CommentNode, ParamExpandNode, ForNode, IfNode, LabelNode, GotoNode,
    CallNode, ExitNode
)
from .models import (
    IRNode, IRProgram, IRBlock, IRFunction, IRStatement, IRExpression,
    IRConstant, IRVariable, IRPathModifier, IRBinaryOp, IRUnaryOp,
    IRSlice, IRSubst, IRAssignment, IRExec, IREcho, IRRedirect,
    IRIf, IRFor, IRCall, IRReturn, IRLabel, IRGoto, IRChain, IRPipe,
    IRComment, IROpType, IRStreamType, IRMetrics
)
from .expressions import (
    parse_if_condition, parse_operand, convert_ast_expr, convert_value_nodes
)

MAX_IR_RECURSION_DEPTH = 500


class ASTToIRBuilder:
    """Constructs an IRProgram from a cmd.exe Abstract Syntax Tree."""

    def __init__(self):
        self.metrics = IRMetrics()
        self._depth = 0
        self._subroutine_labels: Set[str] = set()

    def build(self, ast: ASTNode) -> IRProgram:
        """Entry point: converts an AST tree into an IRProgram."""
        self.metrics.zeroize()
        self._depth = 0
        self._subroutine_labels = self._find_subroutine_targets(ast)

        program = IRProgram()
        statements: List[ASTNode] = []
        if isinstance(ast, ScriptNode):
            statements = ast.statements
        elif isinstance(ast, BlockNode):
            statements = ast.statements
        elif isinstance(ast, list):
            statements = ast
        else:
            statements = [ast]

        # Partition statements into main entry and lifted subroutines
        main_stmts, func_blocks = self._partition_subroutines(statements)

        # Build main entry block
        for stmt_ast in main_stmts:
            ir_stmt = self._build_statement(stmt_ast)
            if ir_stmt is not None:
                program.entry_block.statements.append(ir_stmt)
                self.metrics.statements_created += 1

        # Build lifted functions
        for func_name, func_ast_list in func_blocks.items():
            func_block = IRBlock()
            for stmt_ast in func_ast_list:
                ir_stmt = self._build_statement(stmt_ast)
                if ir_stmt is not None:
                    func_block.statements.append(ir_stmt)
                    self.metrics.statements_created += 1

            func_obj = IRFunction(name=func_name, body=func_block)
            program.functions[func_name] = func_obj
            self.metrics.functions_lifted += 1

        # Collect environment variables
        env_vars = self._collect_env_vars(program)
        program.env_vars = sorted(list(env_vars))
        self.metrics.variables_mapped = len(program.env_vars)

        return program

    def _find_subroutine_targets(self, node: ASTNode) -> Set[str]:
        """Scans for CALL :label statements to identify internal subroutines."""
        targets = set()

        def _scan(n: ASTNode):
            if isinstance(n, CallNode) and n.is_subroutine:
                raw_target = n.target.lstrip(":").strip().lower()
                if raw_target and raw_target != "eof":
                    targets.add(raw_target)
            elif isinstance(n, (ScriptNode, BlockNode)):
                for s in n.statements:
                    _scan(s)
            elif isinstance(n, IfNode):
                _scan(n.then_block)
                if n.else_block:
                    _scan(n.else_block)
            elif isinstance(n, ForNode):
                _scan(n.body)
            elif isinstance(n, ChainNode):
                _scan(n.left)
                _scan(n.right)
            elif isinstance(n, PipeNode):
                _scan(n.left)
                _scan(n.right)

        _scan(node)
        return targets

    def _partition_subroutines(
        self, statements: List[ASTNode]
    ) -> Tuple[List[ASTNode], Dict[str, List[ASTNode]]]:
        """Separates top-level statements from subroutine bodies."""
        main_stmts: List[ASTNode] = []
        func_blocks: Dict[str, List[ASTNode]] = {}
        current_func: Optional[str] = None

        for stmt in statements:
            if isinstance(stmt, LabelNode):
                lbl_clean = stmt.name.lstrip(":").strip().lower()
                if lbl_clean in self._subroutine_labels:
                    current_func = lbl_clean
                    func_blocks[current_func] = []
                    continue
                else:
                    # Regular label inside code
                    if current_func is not None:
                        func_blocks[current_func].append(stmt)
                    else:
                        main_stmts.append(stmt)
                    continue

            # Check for subroutine termination
            if current_func is not None:
                if isinstance(stmt, ExitNode) and stmt.is_batch_return:
                    func_blocks[current_func].append(stmt)
                    current_func = None
                    continue
                elif isinstance(stmt, GotoNode) and (stmt.is_eof or stmt.target.lower() in (":eof", "eof")):
                    func_blocks[current_func].append(stmt)
                    current_func = None
                    continue
                func_blocks[current_func].append(stmt)
            else:
                main_stmts.append(stmt)

        return main_stmts, func_blocks

    def _build_statement(self, node: ASTNode) -> Optional[IRStatement]:
        """Converts a single ASTNode to an IRStatement."""
        self._depth += 1
        if self._depth > MAX_IR_RECURSION_DEPTH:
            self._depth -= 1
            return None

        try:
            if isinstance(node, CommentNode):
                return IRComment(text=node.text)

            elif isinstance(node, AssignmentNode):
                return self._build_assignment(node)

            elif isinstance(node, CommandNode):
                return self._build_command(node)

            elif isinstance(node, RedirectNode):
                return self._build_redirect(node)

            elif isinstance(node, IfNode):
                return self._build_if(node)

            elif isinstance(node, ForNode):
                return self._build_for(node)

            elif isinstance(node, CallNode):
                return self._build_call(node)

            elif isinstance(node, GotoNode):
                if node.is_eof or node.target.lower() in (":eof", "eof"):
                    return IRReturn(is_subroutine_return=True)
                return IRGoto(target=node.target.lstrip(":").strip())

            elif isinstance(node, ExitNode):
                exit_code_expr = None
                if node.exit_code:
                    try:
                        exit_code_expr = IRConstant(int(node.exit_code), "int")
                    except ValueError:
                        exit_code_expr = IRConstant(node.exit_code, "str")
                return IRReturn(exit_code=exit_code_expr, is_subroutine_return=node.is_batch_return)

            elif isinstance(node, LabelNode):
                return IRLabel(name=node.name.lstrip(":").strip())

            elif isinstance(node, ChainNode):
                left_stmt = self._build_statement(node.left)
                right_stmt = self._build_statement(node.right)
                if left_stmt and right_stmt:
                    return IRChain(left=left_stmt, operator=node.operator, right=right_stmt)
                return left_stmt or right_stmt

            elif isinstance(node, PipeNode):
                left_stmt = self._build_statement(node.left)
                right_stmt = self._build_statement(node.right)
                if left_stmt and right_stmt:
                    return IRPipe(left=left_stmt, right=right_stmt)
                return left_stmt or right_stmt

            elif isinstance(node, BlockNode):
                # Flatten block if single statement or return composite
                block = IRBlock()
                for s in node.statements:
                    st = self._build_statement(s)
                    if st:
                        block.statements.append(st)
                if len(block.statements) == 1:
                    return block.statements[0]
                return None  # Top-level handler handles lists

            return None
        finally:
            self._depth -= 1

    def _build_assignment(self, node: AssignmentNode) -> IRAssignment:
        """Converts an AssignmentNode to an IRAssignment."""
        val_expr = self._convert_value_nodes(node.value_nodes, node.raw_value)
        return IRAssignment(
            target=node.var_name,
            value=val_expr,
            is_env=True,
            is_arithmetic=node.is_arithmetic
        )

    def _build_command(self, node: CommandNode) -> IRStatement:
        """Converts a CommandNode into an IRExec or specialized built-in statement."""
        cmd_name = node.target.strip()
        cmd_lower = cmd_name.lower()

        # Handle echo variants
        if cmd_lower in ("echo", "echo.", "echo/", "echo\\"):
            arg_exprs = [self._convert_ast_expr(a) for a in node.arguments]
            self.metrics.commands_translated += 1
            return IREcho(content=arg_exprs, newline=True)

        arg_exprs = [self._convert_ast_expr(a) for a in node.arguments]

        # Detect built-in commands
        builtin_map = {
            "cls": "cls",
            "pause": "pause",
            "mkdir": "mkdir",
            "md": "mkdir",
            "del": "del",
            "erase": "del",
            "rd": "rmdir",
            "rmdir": "rmdir",
            "copy": "copy",
            "move": "move",
            "timeout": "timeout",
            "cd": "cd",
            "chdir": "cd",
            "dir": "dir",
            "type": "type",
            "start": "start",
        }

        is_builtin = cmd_lower in builtin_map
        builtin_kind = builtin_map.get(cmd_lower)

        self.metrics.commands_translated += 1
        return IRExec(
            command=cmd_name,
            args=arg_exprs,
            is_builtin=is_builtin,
            builtin_kind=builtin_kind
        )

    def _build_redirect(self, node: RedirectNode) -> IRStatement:
        """Converts a RedirectNode, extracting the command and routing stream."""
        inner_stmt = self._build_statement(node.command)
        is_devnull = node.destination.strip().lower() in ("nul", "null")
        stream_type = IRStreamType.DEVNULL if is_devnull else IRStreamType.STDOUT

        redir = IRRedirect(
            operator=node.stream,
            destination=node.destination.strip(),
            is_devnull=is_devnull,
            source_stream=stream_type
        )

        if isinstance(inner_stmt, IRExec):
            inner_stmt.redirects.append(redir)
            return inner_stmt
        elif isinstance(inner_stmt, IREcho):
            inner_stmt.redirects.append(redir)
            return inner_stmt
        return inner_stmt or IRComment(f"Redirect: {node.stream} {node.destination}")

    def _build_if(self, node: IfNode) -> IRIf:
        """Converts an IfNode into an IRIf statement."""
        self.metrics.branches_created += 1
        cond_expr = self._parse_if_condition(node.condition)

        then_block = IRBlock()
        if isinstance(node.then_block, BlockNode):
            for s in node.then_block.statements:
                st = self._build_statement(s)
                if st:
                    then_block.statements.append(st)
        else:
            st = self._build_statement(node.then_block)
            if st:
                then_block.statements.append(st)

        else_block = None
        if node.else_block:
            else_block = IRBlock()
            if isinstance(node.else_block, BlockNode):
                for s in node.else_block.statements:
                    st = self._build_statement(s)
                    if st:
                        else_block.statements.append(st)
            else:
                st = self._build_statement(node.else_block)
                if st:
                    else_block.statements.append(st)

        return IRIf(condition=cond_expr, then_body=then_block, else_body=else_block)

    def _parse_if_condition(self, raw_cond: str) -> IRExpression:
        """Parses cmd.exe IF conditions (==, equ, neq, exist, not, errorlevel)."""
        return parse_if_condition(raw_cond)

    def _parse_operand(self, token: str) -> IRExpression:
        """Parses an operand string into an IRExpression."""
        return parse_operand(token)

    def _build_for(self, node: ForNode) -> IRFor:
        """Converts a ForNode into an IRFor statement."""
        self.metrics.loops_structured += 1
        flags = node.flags.lower().strip()
        body_block = IRBlock()

        if isinstance(node.body, BlockNode):
            for s in node.body.statements:
                st = self._build_statement(s)
                if st:
                    body_block.statements.append(st)
        else:
            st = self._build_statement(node.body)
            if st:
                body_block.statements.append(st)

        # /L flag: Numeric range loop (start, step, end)
        if "/l" in flags:
            in_clause = node.in_clause.strip("() \t")
            parts = [p.strip() for p in in_clause.replace(",", " ").split() if p.strip()]
            start, step, end = 0, 1, 0
            if len(parts) >= 3:
                try:
                    start = int(parts[0])
                    step = int(parts[1])
                    end = int(parts[2])
                except ValueError:
                    pass
            return IRFor(
                iterator=node.iterator.lstrip("%"),
                loop_type="range",
                range_start=start,
                range_step=step,
                range_end=end,
                body=body_block
            )

        # /R flag: Recursive directory/file loop
        if "/r" in flags:
            pattern = node.in_clause.strip("() \t") or "*"
            return IRFor(
                iterator=node.iterator.lstrip("%"),
                loop_type="files",
                file_pattern=pattern,
                is_recursive=True,
                body=body_block
            )

        # Standard items or wildcard files
        in_raw = node.in_clause.strip("() \t")
        if any(c in in_raw for c in ("*", "?")):
            return IRFor(
                iterator=node.iterator.lstrip("%"),
                loop_type="files",
                file_pattern=in_raw,
                body=body_block
            )

        # Explicit item list
        items = [IRConstant(item.strip('"')) for item in in_raw.replace(",", " ").split() if item.strip()]
        return IRFor(
            iterator=node.iterator.lstrip("%"),
            loop_type="items",
            items=items,
            body=body_block
        )

    def _build_call(self, node: CallNode) -> IRCall:
        """Converts a CallNode into an IRCall statement."""
        target_name = node.target.lstrip(":").strip()
        arg_exprs = [self._convert_ast_expr(a) for a in node.arguments]
        return IRCall(
            target=target_name,
            args=arg_exprs,
            is_subroutine=node.is_subroutine
        )

    def _convert_value_nodes(self, nodes: List[ASTNode], raw_val: str) -> IRExpression:
        """Converts assignment value AST nodes into an IRExpression."""
        return convert_value_nodes(nodes, raw_val)

    def _convert_ast_expr(self, node: ASTNode) -> IRExpression:
        """Maps an AST expression token into an IRExpression."""
        return convert_ast_expr(node)

    def _collect_env_vars(self, program: IRProgram) -> Set[str]:
        """Scans the IR program to collect all referenced environment variables."""
        vars_found = set()

        def _scan_expr(e: IRExpression):
            if isinstance(e, IRVariable) and e.is_env:
                vars_found.add(e.name)
            elif isinstance(e, (IRSlice, IRSubst)):
                vars_found.add(e.var_name)
            elif isinstance(e, IRBinaryOp):
                _scan_expr(e.left)
                _scan_expr(e.right)
            elif isinstance(e, IRUnaryOp):
                _scan_expr(e.operand)

        def _scan_stmt(s: IRStatement):
            if isinstance(s, IRAssignment) and s.is_env:
                vars_found.add(s.target)
                _scan_expr(s.value)
            elif isinstance(s, IRExec):
                for a in s.args:
                    _scan_expr(a)
            elif isinstance(s, IREcho):
                for c in s.content:
                    _scan_expr(c)
            elif isinstance(s, IRIf):
                _scan_expr(s.condition)
                for ts in s.then_body.statements:
                    _scan_stmt(ts)
                if s.else_body:
                    for es in s.else_body.statements:
                        _scan_stmt(es)
            elif isinstance(s, IRFor):
                for b in s.body.statements:
                    _scan_stmt(b)
            elif isinstance(s, IRChain):
                _scan_stmt(s.left)
                _scan_stmt(s.right)
            elif isinstance(s, IRPipe):
                _scan_stmt(s.left)
                _scan_stmt(s.right)

        for stmt in program.entry_block.statements:
            _scan_stmt(stmt)

        for func in program.functions.values():
            for stmt in func.body.statements:
                _scan_stmt(stmt)

        return vars_found
