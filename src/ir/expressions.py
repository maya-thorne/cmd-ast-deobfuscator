"""
Expression and Condition Parsers for Intermediate Representation (IR).
Extracts, translates, and normalizes AST expressions and condition syntax.
"""

import re
from typing import List, Optional
from ..ast_nodes import (
    ASTNode, LiteralNode, VarExpandNode, ParamExpandNode
)
from .models import (
    IRExpression, IRConstant, IRVariable, IRPathModifier, IRBinaryOp,
    IRUnaryOp, IRSlice, IRSubst, IROpType
)


def parse_operand(token: str) -> IRExpression:
    """Parses an operand string into an IRExpression."""
    token = token.strip()
    # Environment variable %VAR% or !VAR!
    m_var = re.match(r"^[%!]([a-zA-Z0-9_#$@]+)[%!]$", token)
    if m_var:
        return IRVariable(m_var.group(1))

    # Integer constant
    if re.match(r"^-?\d+$", token):
        return IRConstant(int(token), "int")

    # Strip surrounding quotes if present
    if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
        token = token[1:-1]

    return IRConstant(token, "str")


def parse_if_condition(raw_cond: str) -> IRExpression:
    """Parses cmd.exe IF conditions (==, equ, neq, exist, not, errorlevel)."""
    cond = raw_cond.strip()
    is_not = False
    if cond.lower().startswith("not "):
        is_not = True
        cond = cond[4:].strip()

    # Check for EXIST condition
    if cond.lower().startswith("exist "):
        path_target = cond[6:].strip().strip('"')
        expr = IRBinaryOp(
            op=IROpType.EQ,
            left=IRConstant("exist"),
            right=IRConstant(path_target)
        )
        return IRUnaryOp("not", expr) if is_not else expr

    # Check for ERRORLEVEL condition
    if cond.lower().startswith("errorlevel "):
        lvl_str = cond[11:].strip()
        try:
            lvl = int(lvl_str)
        except ValueError:
            lvl = 0
        expr = IRBinaryOp(
            op=IROpType.GTE,
            left=IRVariable("errorlevel"),
            right=IRConstant(lvl, "int")
        )
        return IRUnaryOp("not", expr) if is_not else expr

    # Check comparison operators: ==, equ, neq, lss, leq, gtr, geq
    op_patterns = [
        (r"==", IROpType.EQ),
        (r"\s+equ\s+", IROpType.EQ),
        (r"\s+neq\s+", IROpType.NEQ),
        (r"\s+lss\s+", IROpType.LT),
        (r"\s+leq\s+", IROpType.LTE),
        (r"\s+gtr\s+", IROpType.GT),
        (r"\s+geq\s+", IROpType.GTE),
    ]

    for pat, op_type in op_patterns:
        parts = re.split(pat, cond, maxsplit=1, flags=re.IGNORECASE)
        if len(parts) == 2:
            left_str, right_str = parts[0].strip(), parts[1].strip()
            left_expr = parse_operand(left_str)
            right_expr = parse_operand(right_str)
            cmp_op = op_type
            if is_not:
                invert_map = {
                    IROpType.EQ: IROpType.NEQ,
                    IROpType.NEQ: IROpType.EQ,
                    IROpType.LT: IROpType.GTE,
                    IROpType.LTE: IROpType.GT,
                    IROpType.GT: IROpType.LTE,
                    IROpType.GTE: IROpType.LT,
                }
                cmp_op = invert_map.get(cmp_op, cmp_op)
            return IRBinaryOp(op=cmp_op, left=left_expr, right=right_expr)

    # Fallback single expression
    return IRConstant(cond, "str")


def convert_ast_expr(node: ASTNode) -> IRExpression:
    """Maps an AST expression token into an IRExpression."""
    if isinstance(node, LiteralNode):
        return IRConstant(node.value, "str")

    elif isinstance(node, VarExpandNode):
        if node.slice_start is not None or node.slice_len is not None:
            return IRSlice(
                var_name=node.name,
                start=node.slice_start,
                length=node.slice_len
            )
        elif node.sub_search is not None:
            return IRSubst(
                var_name=node.name,
                search=node.sub_search,
                replace=node.sub_replace or ""
            )
        return IRVariable(node.name, is_env=True)

    elif isinstance(node, ParamExpandNode):
        if node.is_for_var:
            return IRVariable(node.name, is_env=False)
        if node.modifiers:
            mod = node.modifiers.lower()
            is_s_dir = "dp" in mod and node.name == "0"
            is_s_path = "f" in mod and node.name == "0"
            return IRPathModifier(
                target_var=node.name,
                modifier=mod,
                is_script_dir=is_s_dir,
                is_script_path=is_s_path
            )
        if node.name == "*":
            return IRVariable("*", is_env=False, is_all_args=True)
        if node.name.isdigit():
            return IRVariable(node.name, is_env=False, is_positional=True, pos_index=int(node.name))
        return IRVariable(node.name, is_env=False)

    return IRConstant(str(getattr(node, "value", "")), "str")


def convert_value_nodes(nodes: List[ASTNode], raw_val: str) -> IRExpression:
    """Converts assignment value AST nodes into an IRExpression."""
    if not nodes:
        return IRConstant(raw_val.strip('"'), "str")
    if len(nodes) == 1:
        return convert_ast_expr(nodes[0])

    left = convert_ast_expr(nodes[0])
    for n in nodes[1:]:
        right = convert_ast_expr(n)
        left = IRBinaryOp(op=IROpType.CONCAT, left=left, right=right)
    return left
