"""
Arithmetic AST Models and Data Structures for cmd.exe Expression Evaluation.
Provides representation for numbers, variables, operators, assignments, and evaluation metrics.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ArithmeticNode:
    """Base class for arithmetic expression AST nodes."""
    def to_dict(self) -> Dict[str, Any]:
        result = {"node_type": self.__class__.__name__}
        for k, v in self.__dict__.items():
            if isinstance(v, ArithmeticNode):
                result[k] = v.to_dict()
            elif isinstance(v, list) and all(isinstance(x, ArithmeticNode) for x in v):
                result[k] = [x.to_dict() for x in v]
            else:
                result[k] = v
        return result


@dataclass
class NumberNode(ArithmeticNode):
    """32-bit signed integer literal."""
    value: int = 0
    raw: str = ""


@dataclass
class VariableNode(ArithmeticNode):
    """Variable reference in arithmetic expression (bare or %VAR% / !VAR!)."""
    name: str = ""
    is_delayed: bool = False


@dataclass
class UnaryOpNode(ArithmeticNode):
    """Unary operator expression (+, -, ~, !)."""
    operator: str = ""
    operand: ArithmeticNode = field(default_factory=ArithmeticNode)


@dataclass
class BinaryOpNode(ArithmeticNode):
    """Binary operator expression (*, /, %, +, -, <<, >>, &, ^, |)."""
    left: ArithmeticNode = field(default_factory=ArithmeticNode)
    operator: str = ""
    right: ArithmeticNode = field(default_factory=ArithmeticNode)


@dataclass
class AssignmentOpNode(ArithmeticNode):
    """Assignment expression (=, +=, -=, *=, /=, %=, &=, ^=, |=, <<=, >>=)."""
    target: str = ""
    operator: str = "="
    value: ArithmeticNode = field(default_factory=ArithmeticNode)


@dataclass
class SequenceNode(ArithmeticNode):
    """Comma-separated sequence of expressions (e.g., 'a=1, b=2, a+b')."""
    expressions: List[ArithmeticNode] = field(default_factory=list)


@dataclass
class ArithmeticResult:
    """Result of evaluating a cmd.exe arithmetic expression."""
    value: int = 0
    assignments: Dict[str, int] = field(default_factory=dict)
    expression: str = ""
    folded_repr: str = ""
    is_constant: bool = True


@dataclass
class ArithmeticMetrics:
    """Telemetry and performance metrics for arithmetic folding pass."""
    expressions_evaluated: int = 0
    assignments_folded: int = 0
    variables_resolved: int = 0
    operators_evaluated: int = 0
    dead_expressions_pruned: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "expressions_evaluated": self.expressions_evaluated,
            "assignments_folded": self.assignments_folded,
            "variables_resolved": self.variables_resolved,
            "operators_evaluated": self.operators_evaluated,
            "dead_expressions_pruned": self.dead_expressions_pruned,
        }
