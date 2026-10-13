"""
Domain package for cmd.exe quote toggle boundary normalization and token reduction.
Exports automata, models, normalizers, and functional helpers.
"""

from .models import QuoteState, QuoteSegment, QuoteNormalizerMetrics
from .automaton import QuoteToggleAutomaton
from .normalizer import QuoteNormalizer, normalize_quotes, collapse_empty_quotes

__all__ = [
    "QuoteState",
    "QuoteSegment",
    "QuoteNormalizerMetrics",
    "QuoteToggleAutomaton",
    "QuoteNormalizer",
    "normalize_quotes",
    "collapse_empty_quotes",
]
