"""
Deobfuscation Complexity and Efficiency Metrics for cmd-ast-deobfuscator.
Computes Shannon entropy, lexical token density, AST node tree depth and reduction ratios.
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

from ..ast_nodes import (
    ASTNode, ASTVisitor, ScriptNode, CommandNode, PipeNode,
    ChainNode, BlockNode, AssignmentNode, VarExpandNode,
    LiteralNode, RedirectNode, CommentNode, IfNode, ForNode,
    ParamExpandNode, LabelNode, GotoNode, CallNode, ExitNode
)
from ..lexer import CmdLexer, CmdTokenType


def calculate_entropy(text: str) -> float:
    """
    Computes the Shannon entropy of a string: H(X) = -sum(p * log2(p)).
    Returns 0.0 for empty or single-character strings.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def calculate_reduction_ratio(original_val: int, current_val: int) -> float:
    """
    Calculates the reduction percentage: (original - current) / original.
    Positive values denote compression or artifact stripping.
    """
    if original_val <= 0:
        return 0.0
    delta = original_val - current_val
    return round(delta / original_val, 4)


class NodeCounterVisitor(ASTVisitor):
    """AST Visitor that traverses and tallies the total number of syntax nodes."""
    def __init__(self):
        self.total_nodes = 0

    def generic_visit(self, node: ASTNode) -> None:
        pass

    def visit(self, node: Optional[ASTNode]) -> None:
        if node is None:
            return
        self.total_nodes += 1
        super().visit(node)

    def visit_ScriptNode(self, node: ScriptNode) -> None:
        for s in node.statements:
            self.visit(s)

    def visit_CommandNode(self, node: CommandNode) -> None:
        for t in node.target_nodes:
            self.visit(t)
        for a in node.arguments:
            self.visit(a)

    def visit_AssignmentNode(self, node: AssignmentNode) -> None:
        for v in node.value_nodes:
            self.visit(v)

    def visit_ChainNode(self, node: ChainNode) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_PipeNode(self, node: PipeNode) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_BlockNode(self, node: BlockNode) -> None:
        for s in node.statements:
            self.visit(s)

    def visit_RedirectNode(self, node: RedirectNode) -> None:
        self.visit(node.command)

    def visit_IfNode(self, node: IfNode) -> None:
        self.visit(node.then_block)
        if node.else_block:
            self.visit(node.else_block)

    def visit_ForNode(self, node: ForNode) -> None:
        self.visit(node.body)

    def visit_LiteralNode(self, node: LiteralNode) -> None:
        pass

    def visit_VarExpandNode(self, node: VarExpandNode) -> None:
        pass

    def visit_CommentNode(self, node: CommentNode) -> None:
        pass

    def visit_ParamExpandNode(self, node: ParamExpandNode) -> None:
        pass

    def visit_LabelNode(self, node: LabelNode) -> None:
        pass

    def visit_GotoNode(self, node: GotoNode) -> None:
        for t in node.target_nodes:
            self.visit(t)

    def visit_CallNode(self, node: CallNode) -> None:
        for t in node.target_nodes:
            self.visit(t)
        for a in node.arguments:
            self.visit(a)

    def visit_ExitNode(self, node: ExitNode) -> None:
        pass



def count_ast_nodes(root: Optional[ASTNode]) -> int:
    """Recursively computes the total count of AST nodes in a tree."""
    if root is None:
        return 0
    visitor = NodeCounterVisitor()
    visitor.visit(root)
    return visitor.total_nodes


def count_tokens(code: str) -> int:
    """Counts lexical tokens produced by CmdLexer, ignoring EOF markers."""
    if not code:
        return 0
    lexer = CmdLexer(code)
    tokens = lexer.tokenize()
    return sum(1 for t in tokens if t.type != CmdTokenType.EOF)


@dataclass
class ComplexityMetrics:
    """Quantitative complexity metrics before and after deobfuscation."""
    original_chars: int = 0
    deobfuscated_chars: int = 0
    char_reduction_rate: float = 0.0
    original_tokens: int = 0
    deobfuscated_tokens: int = 0
    token_reduction_rate: float = 0.0
    original_nodes: int = 0
    deobfuscated_nodes: int = 0
    node_reduction_rate: float = 0.0
    original_entropy: float = 0.0
    deobfuscated_entropy: float = 0.0
    entropy_reduction_rate: float = 0.0


@dataclass
class SampleMetricResult:
    """Evaluation result for an individual benchmark test case."""
    sample_id: str
    name: str
    category: str
    success: bool
    execution_time_ms: float
    metrics: ComplexityMetrics
    recovered_indicators: List[str] = field(default_factory=list)
    missing_indicators: List[str] = field(default_factory=list)
    deobfuscated_text: str = ""
