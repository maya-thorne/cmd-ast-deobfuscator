"""
Data models, state structures, and telemetry for Control Flow De-flattening (Anti-CFF).
Represents dispatcher blocks, state machine topologies, transitions, and metrics.
"""

from enum import Enum
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from ..ast_nodes import ASTNode


class CFFPatternType(str, Enum):
    """Categorization of batch Control Flow Flattening (CFF) dispatch mechanisms."""
    SWITCH_DISPATCHER = "switch_dispatcher"       # if "%state%"=="1" goto :block_1
    EQU_DISPATCHER = "equ_dispatcher"             # if !state! equ 2 goto :block_2
    COMPUTED_GOTO = "computed_goto"               # goto :state_%state% / goto :b_!state!
    FOR_DISPATCHER = "for_dispatcher"             # for in (...) do goto ...
    HYBRID_DISPATCHER = "hybrid_dispatcher"       # combination of computed and switch
    UNKNOWN = "unknown"


@dataclass
class CFFTransition:
    """Represents a state machine transition between two CFF state handlers."""
    source_state: str
    target_state: str
    condition: Optional[str] = None
    is_conditional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_state,
            "target": self.target_state,
            "condition": self.condition,
            "is_conditional": self.is_conditional
        }


@dataclass
class CFFBlockInfo:
    """Represents a basic block / label section serving as a CFF state handler."""
    state_key: str
    label_name: str
    statements: List[ASTNode] = field(default_factory=list)      # Clean payload statements
    raw_statements: List[ASTNode] = field(default_factory=list)  # All statements before unrolling
    next_state: Optional[str] = None                            # Static next state
    conditional_transitions: List[Tuple[str, str]] = field(default_factory=list)  # (condition, next_state)
    is_terminal: bool = False                                   # Ends with exit / goto :eof
    jumps_to_dispatcher: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_key": self.state_key,
            "label_name": self.label_name,
            "statement_count": len(self.statements),
            "next_state": self.next_state,
            "conditional_transitions": [
                {"condition": c, "target_state": s} for c, s in self.conditional_transitions
            ],
            "is_terminal": self.is_terminal,
            "jumps_to_dispatcher": self.jumps_to_dispatcher
        }


@dataclass
class CFFStateMachine:
    """Topology of a detected Control Flow Flattening state machine."""
    state_var: str
    initial_state: str
    dispatcher_label: str
    blocks: Dict[str, CFFBlockInfo] = field(default_factory=dict)
    pattern_type: CFFPatternType = CFFPatternType.UNKNOWN
    all_cff_labels: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_var": self.state_var,
            "initial_state": self.initial_state,
            "dispatcher_label": self.dispatcher_label,
            "pattern_type": self.pattern_type.value,
            "total_states": len(self.blocks),
            "states": {k: b.to_dict() for k, b in self.blocks.items()},
            "labels": sorted(list(self.all_cff_labels))
        }


@dataclass
class DeflatMetrics:
    """Telemetry metrics recording control flow de-flattening efficacy."""
    dispatchers_detected: int = 0
    states_unrolled: int = 0
    blocks_linearized: int = 0
    dead_jumps_pruned: int = 0
    conditional_branches_recovered: int = 0
    loops_reconstructed: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "dispatchers_detected": self.dispatchers_detected,
            "states_unrolled": self.states_unrolled,
            "blocks_linearized": self.blocks_linearized,
            "dead_jumps_pruned": self.dead_jumps_pruned,
            "conditional_branches_recovered": self.conditional_branches_recovered,
            "loops_reconstructed": self.loops_reconstructed
        }

    def zeroize(self) -> None:
        """Securely clears internal telemetry counters."""
        self.dispatchers_detected = 0
        self.states_unrolled = 0
        self.blocks_linearized = 0
        self.dead_jumps_pruned = 0
        self.conditional_branches_recovered = 0
        self.loops_reconstructed = 0


@dataclass
class DeflatResult:
    """Consolidated outcome of the de-flattening and unrolling pass."""
    success: bool = False
    state_machine: Optional[CFFStateMachine] = None
    linearized_nodes: List[ASTNode] = field(default_factory=list)
    metrics: DeflatMetrics = field(default_factory=DeflatMetrics)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "has_state_machine": self.state_machine is not None,
            "state_machine": self.state_machine.to_dict() if self.state_machine else None,
            "linearized_nodes_count": len(self.linearized_nodes),
            "metrics": self.metrics.to_dict()
        }

    def zeroize(self) -> None:
        """Securely zeroizes internal result structures."""
        self.linearized_nodes.clear()
        self.state_machine = None
        self.metrics.zeroize()
