"""
Arithmetic Expression Folding AST Transform Pass for cmd-ast-deobfuscator.
Evaluates 'set /a' statements, folds compound operators, resolves variables,
updates the environment symbol table, and normalizes arithmetic AST nodes.
"""

import re
from typing import Dict, List, Optional, Any, Set
from ..ast_nodes import (
    ASTNode, AssignmentNode, CommandNode, LiteralNode,
    VarExpandNode, ScriptNode, BlockNode, ChainNode, IfNode
)
from .base import TransformPass
from ..arithmetic.evaluator import CmdArithmeticEvaluator, to_int32
from ..arithmetic.models import ArithmeticMetrics, ArithmeticResult


class ArithmeticFolderPass(TransformPass):
    """
    Compiler optimization pass folding obfuscated arithmetic expressions:
      1. Evaluates 'set /a [var=]expr' with 32-bit signed math.
      2. Resolves arithmetic operators (*, /, %, +, -, <<, >>, &, ^, |, ~, !).
      3. Handles compound assignments (+=, -=, *=, /=, %=, &=, ^=, |=, <<=, >>=).
      4. Propagates computed values into the environment symbol table for downstream passes.
      5. Simplifies multi-assignment sequences ('set /a a=1, b=a*2' -> 'set /a a=1, b=2').
      6. Strips carets and unnecessary quotes from arithmetic payloads.
    """

    def __init__(
        self,
        env: Optional[Dict[str, str]] = None,
        decompose_multi: bool = False,
        fold_to_plain_set: bool = False
    ):
        super().__init__(name="ArithmeticFolderPass", env=env)
        self.evaluator = CmdArithmeticEvaluator(env=self.env)
        self.metrics = ArithmeticMetrics()
        self.decompose_multi = decompose_multi
        self.fold_to_plain_set = fold_to_plain_set

    def transform(self, root: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        if env:
            for k, v in env.items():
                self.env[k.lower()] = str(v)
        self.evaluator.env = self.env
        self.modified = False
        return self.visit(root)

    def visit_AssignmentNode(self, node: AssignmentNode) -> Any:
        if not node.is_arithmetic:
            # Standard assignment: record variable in env
            var_key = node.var_name.lower()
            if var_key:
                self.env[var_key] = node.raw_value
            return node

        # Reconstruct full arithmetic expression string
        raw_expr = self._extract_raw_expression(node)
        if not raw_expr.strip():
            return node

        # Pre-process: unmask carets and expand existing known variables
        norm_expr = self._normalize_expression_text(raw_expr)

        # Evaluate arithmetic expression
        res = self.evaluator.evaluate(norm_expr, env=self.env)
        self.metrics.expressions_evaluated += 1

        # Synchronize evaluated assignments into pass environment
        for v_name, val in res.assignments.items():
            self.env[v_name.lower()] = str(val)
            self.metrics.assignments_folded += 1

        self.metrics.operators_evaluated = self.evaluator.metrics.operators_evaluated
        self.metrics.variables_resolved = self.evaluator.metrics.variables_resolved

        # Determine folded representation
        if res.assignments:
            if len(res.assignments) == 1 and not (',' in raw_expr):
                # Single variable assignment
                target_var = list(res.assignments.keys())[0]
                folded_val = str(res.assignments[target_var])
                is_changed = (node.raw_value.strip() != folded_val) or (node.var_name.strip() != target_var)
                if is_changed:
                    self.modified = True
                is_arith = not self.fold_to_plain_set
                return AssignmentNode(
                    var_name=target_var,
                    raw_value=folded_val,
                    value_nodes=[LiteralNode(value=folded_val)],
                    is_arithmetic=is_arith,
                    span=node.span
                )
            else:
                # Multi-variable assignment: 'x=1, y=2'
                folded_raw = res.folded_repr
                if node.raw_value.strip() != folded_raw:
                    self.modified = True
                return AssignmentNode(
                    var_name="",
                    raw_value=folded_raw,
                    value_nodes=[LiteralNode(value=folded_raw)],
                    is_arithmetic=True,
                    span=node.span
                )
        else:
            # Pure arithmetic expression without assignment: 'set /a 10+20'
            folded_val = str(res.value)
            if node.raw_value.strip() != folded_val:
                self.modified = True
            return AssignmentNode(
                var_name="",
                raw_value=folded_val,
                value_nodes=[LiteralNode(value=folded_val)],
                is_arithmetic=True,
                span=node.span
            )

    def visit_CommandNode(self, node: CommandNode) -> ASTNode:
        # Check if a command is 'set /a ...' parsed as CommandNode
        if node.target.lower() == 'set' and node.arguments:
            first_arg = node.arguments[0]
            first_val = first_arg.value if isinstance(first_arg, LiteralNode) else ""
            if first_val.strip().lower().startswith('/a'):
                # Extract trailing arguments as arithmetic expression
                tail_parts = []
                # Check if first arg has content after /a, e.g., '/a x=1'
                after_flag = re.sub(r'^\s*/a\b', '', first_val, flags=re.IGNORECASE).strip()
                if after_flag:
                    tail_parts.append(after_flag)
                for arg in node.arguments[1:]:
                    tail_parts.append(arg.value if isinstance(arg, LiteralNode) else "")
                full_expr = " ".join(tail_parts).strip()
                dummy_assign = AssignmentNode(
                    var_name="",
                    raw_value=full_expr,
                    is_arithmetic=True,
                    span=node.span
                )
                folded = self.visit_AssignmentNode(dummy_assign)
                self.modified = True
                return folded

        # Default traversal for other commands
        new_target_nodes = [self.visit(t) for t in node.target_nodes] if node.target_nodes else []
        new_args = [self.visit(a) for a in node.arguments]
        if new_target_nodes != node.target_nodes or new_args != node.arguments:
            self.modified = True
            return CommandNode(
                target=node.target,
                target_nodes=new_target_nodes,
                arguments=new_args,
                span=node.span
            )
        return node

    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        new_stmts: List[ASTNode] = []
        changed = False
        for stmt in node.statements:
            new_stmt = self.visit(stmt)
            if self.decompose_multi and isinstance(new_stmt, AssignmentNode) and new_stmt.is_arithmetic and ',' in new_stmt.raw_value:
                # Decompose 'set /a a=1, b=2' into individual AssignmentNodes
                sub_stmts = self._decompose_assignment(new_stmt)
                new_stmts.extend(sub_stmts)
                changed = True
            elif new_stmt is not None:
                new_stmts.append(new_stmt)
            if new_stmt is not stmt:
                changed = True
        if changed:
            self.modified = True
            return ScriptNode(statements=new_stmts, span=node.span)
        return node

    def visit_BlockNode(self, node: BlockNode) -> BlockNode:
        new_stmts: List[ASTNode] = []
        changed = False
        for s in node.statements:
            new_s = self.visit(s)
            if self.decompose_multi and isinstance(new_s, AssignmentNode) and new_s.is_arithmetic and ',' in new_s.raw_value:
                sub_stmts = self._decompose_assignment(new_s)
                new_stmts.extend(sub_stmts)
                changed = True
            elif new_s is not None:
                new_stmts.append(new_s)
            if new_s is not s:
                changed = True
        if changed:
            self.modified = True
            return BlockNode(statements=new_stmts, span=node.span)
        return node

    def _extract_raw_expression(self, node: AssignmentNode) -> str:
        """Extracts the complete arithmetic expression string from an AssignmentNode."""
        if node.var_name:
            if '=' in node.raw_value:
                # e.g., var_name='x', raw_value='10, y=20' -> 'x=10, y=20'
                return f"{node.var_name}={node.raw_value}"
            return f"{node.var_name}={node.raw_value}"
        return node.raw_value

    def _normalize_expression_text(self, expr: str) -> str:
        """Unmasks carets, strips double quotes, and substitutes known environment variables."""
        text = expr.strip()
        # Collapse multiple carets
        text = re.sub(r'\^{2,}', '^', text)
        text = re.sub(r'\^([&|^<>()%+*~!=,])', r'\1', text)
        # Strip outer quotes
        if text.startswith('"') and text.endswith('"') and len(text) >= 2:
            text = text[1:-1].strip()

        # Substitute %VAR% or !VAR! if known in environment
        def _sub_var(m):
            vkey = m.group(1).lower()
            if vkey in self.env:
                return self.env[vkey]
            return m.group(0)

        prev = None
        count = 0
        while prev != text and count < 5:
            prev = text
            count += 1
            text = re.sub(r'[%!]([a-zA-Z0-9_#$@.-]+)[%!]', _sub_var, text)

        return text

    def _decompose_assignment(self, node: AssignmentNode) -> List[AssignmentNode]:
        """Splits a multi-assignment node 'x=1, y=2' into separate AssignmentNodes."""
        parts = [p.strip() for p in node.raw_value.split(',') if p.strip()]
        result: List[AssignmentNode] = []
        for part in parts:
            if '=' in part:
                v, val = part.split('=', 1)
                result.append(AssignmentNode(
                    var_name=v.strip(),
                    raw_value=val.strip(),
                    value_nodes=[LiteralNode(value=val.strip())],
                    is_arithmetic=True
                ))
            else:
                result.append(AssignmentNode(
                    var_name="",
                    raw_value=part,
                    value_nodes=[LiteralNode(value=part)],
                    is_arithmetic=True
                ))
        return result


def fold_arithmetic(
    ast: ASTNode,
    env: Optional[Dict[str, str]] = None,
    decompose_multi: bool = False,
    fold_to_plain_set: bool = False
) -> ASTNode:
    """Convenience helper function to run the ArithmeticFolderPass over an AST."""
    folder = ArithmeticFolderPass(
        env=env,
        decompose_multi=decompose_multi,
        fold_to_plain_set=fold_to_plain_set
    )
    return folder.transform(root=ast, env=env)
