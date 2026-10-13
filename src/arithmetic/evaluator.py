"""
Evaluator for cmd.exe 32-bit Signed Integer Arithmetic Expressions.
Evaluates ArithmeticNode ASTs with 32-bit signed overflow wrapping,
zero-division defenses, variable resolution, and compound assignment tracking.
"""

from typing import Dict, Optional, Any, Tuple
from .models import (
    ArithmeticNode, NumberNode, VariableNode, UnaryOpNode,
    BinaryOpNode, AssignmentOpNode, SequenceNode, ArithmeticResult,
    ArithmeticMetrics
)
from .parser import ArithmeticParser


def to_int32(val: int) -> int:
    """Clamps an integer to 32-bit signed two's complement [-2147483648, 2147483647]."""
    val = val & 0xFFFFFFFF
    if val >= 0x80000000:
        val -= 0x100000000
    return val


class CmdArithmeticEvaluator:
    """
    Evaluates cmd.exe arithmetic expressions against an environment symbol table.
    Ensures safe bounded execution, recursion depth clamping, and 32-bit semantics.
    """

    MAX_RECURSION_DEPTH = 16

    def __init__(self, env: Optional[Dict[str, str]] = None):
        self.env: Dict[str, str] = {k.lower(): v for k, v in env.items()} if env else {}
        self.metrics = ArithmeticMetrics()

    def evaluate(self, expr_str: str, env: Optional[Dict[str, str]] = None) -> ArithmeticResult:
        """Parses and evaluates a raw arithmetic expression string."""
        if env:
            for k, v in env.items():
                self.env[k.lower()] = str(v)

        parser = ArithmeticParser(expr_str)
        ast = parser.parse()

        local_vars: Dict[str, int] = {}
        target_case_map: Dict[str, str] = {}
        final_val = self._eval_node(ast, local_vars, target_case_map, depth=0)
        self.metrics.expressions_evaluated += 1

        # Format folded representation
        if local_vars:
            folded_parts = []
            for v_lower, val in local_vars.items():
                display_name = target_case_map.get(v_lower, v_lower)
                folded_parts.append(f"{display_name}={val}")
            folded_repr = ", ".join(folded_parts)
        else:
            folded_repr = str(final_val)

        # Store assignments with original casings where possible
        assignments = {target_case_map.get(k, k): v for k, v in local_vars.items()}

        return ArithmeticResult(
            value=final_val,
            assignments=assignments,
            expression=expr_str,
            folded_repr=folded_repr,
            is_constant=True
        )

    def _eval_node(
        self,
        node: ArithmeticNode,
        local_vars: Dict[str, int],
        case_map: Dict[str, str],
        depth: int
    ) -> int:
        if depth > self.MAX_RECURSION_DEPTH:
            return 0

        if isinstance(node, NumberNode):
            return to_int32(node.value)

        if isinstance(node, VariableNode):
            self.metrics.variables_resolved += 1
            v_lower = node.name.lower()
            if v_lower in local_vars:
                return local_vars[v_lower]
            if v_lower in self.env:
                raw_val = self.env[v_lower]
                return self._resolve_env_value(raw_val, local_vars, case_map, depth + 1)
            # Undefined variables default to 0 in cmd.exe arithmetic
            return 0

        if isinstance(node, UnaryOpNode):
            self.metrics.operators_evaluated += 1
            op_val = self._eval_node(node.operand, local_vars, case_map, depth)
            if node.operator == '+':
                return to_int32(op_val)
            if node.operator == '-':
                return to_int32(-op_val)
            if node.operator == '~':
                return to_int32(~op_val)
            if node.operator == '!':
                return 1 if op_val == 0 else 0
            return op_val

        if isinstance(node, BinaryOpNode):
            self.metrics.operators_evaluated += 1
            left_val = self._eval_node(node.left, local_vars, case_map, depth)
            right_val = self._eval_node(node.right, local_vars, case_map, depth)
            return self._eval_binary_op(node.operator, left_val, right_val)

        if isinstance(node, AssignmentOpNode):
            self.metrics.operators_evaluated += 1
            self.metrics.assignments_folded += 1
            target_key = node.target.lower()
            case_map[target_key] = node.target

            rhs_val = self._eval_node(node.value, local_vars, case_map, depth)

            if node.operator == '=':
                res_val = rhs_val
            else:
                # Compound assignment: retrieve current value
                curr_val = 0
                if target_key in local_vars:
                    curr_val = local_vars[target_key]
                elif target_key in self.env:
                    curr_val = self._resolve_env_value(self.env[target_key], local_vars, case_map, depth + 1)

                base_op = node.operator[:-1]  # strip trailing '='
                res_val = self._eval_binary_op(base_op, curr_val, rhs_val)

            res_val = to_int32(res_val)
            local_vars[target_key] = res_val
            self.env[target_key] = str(res_val)
            return res_val

        if isinstance(node, SequenceNode):
            last_val = 0
            for expr in node.expressions:
                last_val = self._eval_node(expr, local_vars, case_map, depth)
            return last_val

        return 0

    def _eval_binary_op(self, op: str, left: int, right: int) -> int:
        """Executes a binary operator with 32-bit signed math and zero-division protection."""
        if op == '+':
            return to_int32(left + right)
        if op == '-':
            return to_int32(left - right)
        if op == '*':
            return to_int32(left * right)
        if op == '/':
            if right == 0:
                # Safe zero-division defense: return 0 without exception
                return 0
            # C-style integer division (truncate toward zero)
            res = int(left / right)
            return to_int32(res)
        if op == '%':
            if right == 0:
                return 0
            # C-style modulus: sign follows numerator
            quotient = int(left / right)
            rem = left - quotient * right
            return to_int32(rem)
        if op == '<<':
            shift_amt = right & 31
            return to_int32(left << shift_amt)
        if op == '>>':
            shift_amt = right & 31
            return to_int32(left >> shift_amt)
        if op == '&':
            return to_int32(left & right)
        if op == '^':
            return to_int32(left ^ right)
        if op == '|':
            return to_int32(left | right)
        return 0

    def _resolve_env_value(
        self,
        raw: str,
        local_vars: Dict[str, int],
        case_map: Dict[str, str],
        depth: int
    ) -> int:
        """Parses a string from the environment into an integer, recursively if needed."""
        raw_s = raw.strip()
        if not raw_s:
            return 0
        try:
            if raw_s.startswith(('0x', '0X')):
                return to_int32(int(raw_s, 16))
            if raw_s.startswith('0') and len(raw_s) > 1 and all(c in '01234567' for c in raw_s):
                return to_int32(int(raw_s, 8))
            return to_int32(int(raw_s, 10))
        except ValueError:
            pass

        # String is an expression, recursively evaluate
        sub_parser = ArithmeticParser(raw_s)
        sub_ast = sub_parser.parse()
        return self._eval_node(sub_ast, local_vars, case_map, depth + 1)


def evaluate_arithmetic(expr: str, env: Optional[Dict[str, str]] = None) -> ArithmeticResult:
    """Convenience helper to evaluate a cmd.exe arithmetic expression string."""
    evaluator = CmdArithmeticEvaluator(env=env)
    return evaluator.evaluate(expr)
