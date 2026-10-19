"""
Data models, state structures, and telemetry for Control Flow De-flattening (Anti-CFF).
Represents dispatcher blocks, state machine topologies, transitions, loop structures, and metrics.
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

class CFFLoopType(str, Enum):
    """Classification of detected loops within flattened control flow dispatchers."""
    DETERMINISTIC_UNROLLED = "deterministic_unrolled"
    STRUCTURED_WHILE = "structured_while"
    STRUCTURED_FOR = "structured_for"
    COMPLEX_IRREDUCIBLE = "complex_irreducible"

class UnrollMode(str, Enum):
    """Execution policy for control flow loop unrolling and reconstruction."""
    AUTO = "auto"
    FULL_UNROLL = "full_unroll"
    STRUCTURED = "structured"
    PRESERVE_LOOPS = "preserve_loops"

@dataclass
class CFFTransition:
    """Represents a state machine transition between two CFF state handlers."""
    source_state: str
    target_state: str
    condition: Optional[str] = None
    is_conditional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source_state, "target": self.target_state,
                "condition": self.condition, "is_conditional": self.is_conditional}

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
            "state_key": self.state_key, "label_name": self.label_name,
            "statement_count": len(self.statements), "next_state": self.next_state,
            "conditional_transitions": [{"condition": c, "target_state": s} for c, s in self.conditional_transitions],
            "is_terminal": self.is_terminal, "jumps_to_dispatcher": self.jumps_to_dispatcher
        }


@dataclass
class CFFLoopInfo:
    """Natural loop structure extracted from CFF state transition graph."""
    header_state: str
    latch_states: Set[str] = field(default_factory=set)
    body_states: Set[str] = field(default_factory=set)
    exit_states: Set[str] = field(default_factory=set)
    back_edges: List[Tuple[str, str]] = field(default_factory=list)
    loop_type: CFFLoopType = CFFLoopType.DETERMINISTIC_UNROLLED
    iteration_count: Optional[int] = None
    exit_conditions: List[str] = field(default_factory=list)
    continue_conditions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header_state": self.header_state,
            "latch_states": sorted(list(self.latch_states)),
            "body_states": sorted(list(self.body_states)),
            "exit_states": sorted(list(self.exit_states)),
            "back_edges": [{"source": u, "target": v} for u, v in self.back_edges],
            "loop_type": self.loop_type.value,
            "iteration_count": self.iteration_count,
            "exit_conditions": list(self.exit_conditions),
            "continue_conditions": list(self.continue_conditions)
        }

    def zeroize(self) -> None:
        """Securely zeroizes internal loop analysis fields."""
        self.header_state = ""
        self.latch_states.clear()
        self.body_states.clear()
        self.exit_states.clear()
        self.back_edges.clear()
        self.iteration_count = None
        self.exit_conditions.clear()
        self.continue_conditions.clear()


@dataclass
class CFFUnrollConfig:
    """Configuration options for CFF dispatcher unrolling and loop reconstruction."""
    max_unroll_iterations: int = 50
    max_unroll_steps: int = 5000
    unroll_mode: UnrollMode = UnrollMode.AUTO
    detect_loops: bool = True
    prune_dead_states: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_unroll_iterations": self.max_unroll_iterations,
            "max_unroll_steps": self.max_unroll_steps,
            "unroll_mode": self.unroll_mode.value,
            "detect_loops": self.detect_loops,
            "prune_dead_states": self.prune_dead_states
        }

    def zeroize(self) -> None:
        """Securely resets configuration fields."""
        self.max_unroll_iterations = 0
        self.max_unroll_steps = 0
        self.detect_loops = False
        self.prune_dead_states = False


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
    loops_detected: int = 0
    loops_fully_unrolled: int = 0
    dead_states_pruned: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "dispatchers_detected": self.dispatchers_detected,
            "states_unrolled": self.states_unrolled,
            "blocks_linearized": self.blocks_linearized,
            "dead_jumps_pruned": self.dead_jumps_pruned,
            "conditional_branches_recovered": self.conditional_branches_recovered,
            "loops_reconstructed": self.loops_reconstructed,
            "loops_detected": self.loops_detected,
            "loops_fully_unrolled": self.loops_fully_unrolled,
            "dead_states_pruned": self.dead_states_pruned
        }

    def zeroize(self) -> None:
        """Securely clears internal telemetry counters."""
        self.dispatchers_detected = 0
        self.states_unrolled = 0
        self.blocks_linearized = 0
        self.dead_jumps_pruned = 0
        self.conditional_branches_recovered = 0
        self.loops_reconstructed = 0
        self.loops_detected = 0
        self.loops_fully_unrolled = 0
        self.dead_states_pruned = 0


@dataclass
class DeflatResult:
    """Consolidated outcome of the de-flattening and unrolling pass."""
    success: bool = False
    state_machine: Optional[CFFStateMachine] = None
    linearized_nodes: List[ASTNode] = field(default_factory=list)
    loops: List[CFFLoopInfo] = field(default_factory=list)
    metrics: DeflatMetrics = field(default_factory=DeflatMetrics)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "has_state_machine": self.state_machine is not None,
            "state_machine": self.state_machine.to_dict() if self.state_machine else None,
            "linearized_nodes_count": len(self.linearized_nodes),
            "loops": [lp.to_dict() for lp in self.loops],
            "metrics": self.metrics.to_dict()
        }

    def zeroize(self) -> None:
        """Securely zeroizes internal result structures."""
        self.linearized_nodes.clear()
        for lp in self.loops:
            lp.zeroize()
        self.loops.clear()
        self.state_machine = None
        self.metrics.zeroize()
