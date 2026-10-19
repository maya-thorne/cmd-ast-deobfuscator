"""
Control Flow De-flattening (Anti-CFF) Linearizer and AST Decompiler Facade.
Coordinates CFFLoopDetector and CFFDispatcherUnroller to eliminate dispatcher loops,
unroll deterministic state cycles, structure dynamic loops, and decompile clean ASTs.
"""

from typing import Optional, List, Set, Tuple
from ..ast_nodes import ASTNode
from .models import (
    CFFStateMachine, DeflatResult, DeflatMetrics, CFFUnrollConfig, CFFLoopInfo
)
from .loop_detector import CFFLoopDetector
from .unroller import CFFDispatcherUnroller


class CFFLinearizer:
    """
    Backwards-compatible de-flattening and linearizing coordinator.
    Delegates loop analysis to CFFLoopDetector and unrolling to CFFDispatcherUnroller.
    """

    def __init__(self, config: Optional[CFFUnrollConfig] = None):
        self.config = config or CFFUnrollConfig()
        self.metrics = DeflatMetrics()
        self.detector = CFFLoopDetector()
        self.unroller = CFFDispatcherUnroller(config=self.config)

    def linearize(
        self,
        state_machine: CFFStateMachine,
        config: Optional[CFFUnrollConfig] = None
    ) -> DeflatResult:
        """
        Detects loops and unreachable states, unrolls dispatcher loops, and returns DeflatResult.
        """
        cfg = config or self.config
        self.unroller.config = cfg

        # Step 1: Detect natural loops and dead states
        loops, dead_states = self.detector.detect(state_machine, cfg)

        # Step 2: Unroll dispatcher and synthesize clean AST
        result = self.unroller.unroll(
            state_machine=state_machine,
            loops=loops,
            dead_states=dead_states,
            metrics=self.metrics
        )
        return result

    def zeroize(self) -> None:
        """Securely zeroizes internal metrics, detectors, and unroller state."""
        self.metrics.zeroize()
        self.config.zeroize()
        self.detector.zeroize()
        self.unroller.zeroize()


class CFFDecompiler(CFFLinearizer):
    """
    Compiler-grade AST Decompiler for flattened control flow scripts.
    Provides standard decompile() method matching pipeline standards.
    """

    def decompile(
        self,
        state_machine: CFFStateMachine,
        config: Optional[CFFUnrollConfig] = None
    ) -> DeflatResult:
        """Decompiles state machine into structured and unrolled AST statements."""
        return self.linearize(state_machine, config=config)
