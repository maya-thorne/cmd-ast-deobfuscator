"""
High-level quote normalization coordinator and AST literal coalescer.
Provides unified quote deobfuscation for command targets, arguments, and variable assignments.
"""

from typing import List, Tuple, Optional
from ..ast_nodes import ASTNode, LiteralNode
from .automaton import QuoteToggleAutomaton
from .models import QuoteNormalizerMetrics


class QuoteNormalizer:
    """
    Coordinates quote toggle boundary normalization across text and AST structures.
    """

    def __init__(self):
        self.automaton = QuoteToggleAutomaton()

    @property
    def metrics(self) -> QuoteNormalizerMetrics:
        return self.automaton.metrics

    def normalize_text(self, text: str, is_target: bool = False) -> str:
        """
        Normalizes a string with quote awareness.
        If is_target is True, applies command target deobfuscation.
        Otherwise applies general empty-quote collapse.
        """
        if is_target:
            return self.automaton.normalize_target(text)
        return self.automaton.collapse_empty_quotes(text)

    def normalize_target(self, target: str) -> str:
        """Normalizes a command executable name or internal command."""
        return self.automaton.normalize_target(target)

    def normalize_argument(self, arg: str) -> str:
        """Normalizes a command argument token."""
        return self.automaton.normalize_argument(arg)

    def normalize_assignment(self, var_name: str, raw_value: str) -> Tuple[str, str, bool]:
        """
        Normalizes a variable assignment.
        Strips quotes from variable name and canonicalizes the assignment value.
        Returns: (clean_var_name, clean_value, is_enclosed)
        """
        clean_var = self.automaton.normalize_target(var_name)
        clean_val, is_enclosed = self.automaton.normalize_assignment_value(raw_value)
        return clean_var, clean_val, is_enclosed

    def coalesce_literal_nodes(self, nodes: List[ASTNode]) -> List[ASTNode]:
        """
        Fuses adjacent LiteralNode tokens where quotes were toggled.
        Preserves non-literal nodes (such as VarExpandNode, ParamExpandNode).
        """
        if not nodes:
            return []

        coalesced: List[ASTNode] = []
        pending_literal: Optional[str] = None
        pending_quoted: bool = False
        pending_span: Tuple[int, int] = (0, 0)

        for node in nodes:
            if isinstance(node, LiteralNode):
                # Clean up empty quotes inside literal
                cleaned_val = self.automaton.collapse_empty_quotes(node.value)
                if pending_literal is None:
                    pending_literal = cleaned_val
                    pending_quoted = node.is_quoted
                    pending_span = node.span
                else:
                    pending_literal += cleaned_val
                    pending_quoted = pending_quoted or node.is_quoted
                    pending_span = (pending_span[0], node.span[1])
            else:
                if pending_literal is not None:
                    if pending_literal:  # Only emit if non-empty
                        coalesced.append(LiteralNode(
                            value=pending_literal,
                            is_quoted=pending_quoted,
                            span=pending_span
                        ))
                    pending_literal = None
                coalesced.append(node)

        if pending_literal is not None:
            if pending_literal:
                coalesced.append(LiteralNode(
                    value=pending_literal,
                    is_quoted=pending_quoted,
                    span=pending_span
                ))

        return coalesced

    def zeroize(self) -> None:
        """Securely resets internal state."""
        self.automaton.zeroize()


def normalize_quotes(text: str, is_target: bool = False) -> str:
    """Convenience function to normalize quotes in a string."""
    normalizer = QuoteNormalizer()
    return normalizer.normalize_text(text, is_target=is_target)


def collapse_empty_quotes(text: str) -> str:
    """Convenience function to collapse empty quote pairs in a string."""
    automaton = QuoteToggleAutomaton()
    return automaton.collapse_empty_quotes(text)
