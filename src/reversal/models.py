"""
Data Models and Telemetry Structures for Batch String Reversal and Transposition Deobfuscation.
Covers Somalifuscator-style reverse string loops, pushdown stack automata,
permutation transpositions, and dictionary-based character substitution decoders.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Any, Tuple
from ..ast_nodes import ASTNode


class ReversalPatternType(Enum):
    """Classification of string reversal and transposition patterns."""
    FOR_L_REVERSAL = auto()             # for /l %i in (len,-1,0) do set out=!out!!s:~%i,1!
    FOR_L_PREPEND = auto()              # for /l %i in (0,1,len) do set out=!s:~%i,1!!out!
    FOR_IN_TRANSPOSITION = auto()       # for %a in (indices) do set out=!out!!dict:~%a,1!
    DIRECT_SLICE_SEQUENCE = auto()      # %s:~3,1%%s:~2,1%%s:~1,1%%s:~0,1%
    GOTO_STACK_REVERSAL = auto()        # :loop ... set out=%out%%s:~-1% & set s=%s:~0,-1% ... goto loop
    SUBSTITUTION_TRANSPOSITION = auto() # combined substitution and transposition


@dataclass
class ReversalLoopSpec:
    """Detailed specification of an identified reversal or transposition loop in AST."""
    pattern_type: ReversalPatternType
    iterator_var: str
    source_var: str
    dest_var: str
    start: Optional[int] = None
    step: Optional[int] = None
    stop: Optional[int] = None
    slice_len: int = 1
    is_prepend: bool = False
    in_items: List[str] = field(default_factory=list)
    confidence: float = 1.0
    matched_ast_node: Optional[ASTNode] = None


@dataclass
class TranspositionResult:
    """Represents the decoded output of a reversal or transposition operation."""
    pattern_type: ReversalPatternType
    source_text: str
    decoded_text: str
    source_var: str
    dest_var: str
    steps_simulated: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReversalMetrics:
    """Telemetry metrics tracking reversal and transposition optimizations."""
    loops_detected: int = 0
    loops_folded: int = 0
    transposed_slices_folded: int = 0
    goto_loops_folded: int = 0
    characters_decoded: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "loops_detected": self.loops_detected,
            "loops_folded": self.loops_folded,
            "transposed_slices_folded": self.transposed_slices_folded,
            "goto_loops_folded": self.goto_loops_folded,
            "characters_decoded": self.characters_decoded,
        }
