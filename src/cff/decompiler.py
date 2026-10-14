"""
Control Flow De-flattening (Anti-CFF) Linearizer and AST Decompiler.
Traces state machine execution paths from initial state, unrolls linear sequences,
structures conditional branching, eliminates dispatcher overhead, and recovers clean ASTs.
"""

from typing import List, Dict, Set, Optional, Tuple
from ..ast_nodes import (
    ASTNode, ScriptNode, BlockNode, IfNode, GotoNode, LabelNode, ExitNode
)
from .models import (
    CFFStateMachine, CFFBlockInfo, DeflatResult, DeflatMetrics
)

# DoS and infinite loop prevention threshold
MAX_UNROLL_STEPS = 5000


class CFFLinearizer:
    """
    Simulates and linearizes Control Flow Flattening state machines.
    Eliminates state dispatcher loops and reconstructs orthodox execution sequences.
    """

    def __init__(self):
        self.metrics = DeflatMetrics()

    def linearize(self, state_machine: CFFStateMachine) -> DeflatResult:
        """
        Unrolls state transitions and synthesizes a linearized list of AST statements.
        """
        result = DeflatResult(state_machine=state_machine, metrics=self.metrics)
        self.metrics.dispatchers_detected += 1

        unrolled_nodes, success = self._unroll_path(
            state_machine=state_machine,
            start_state=state_machine.initial_state,
            visited_states=set(),
            depth=0
        )

        if success and unrolled_nodes:
            result.success = True
            result.linearized_nodes = unrolled_nodes
        else:
            result.success = False
            result.linearized_nodes = []

        return result

    def _unroll_path(
        self,
        state_machine: CFFStateMachine,
        start_state: str,
        visited_states: Set[str],
        depth: int
    ) -> Tuple[List[ASTNode], bool]:
        """
        Recursively walks the state machine starting at start_state.
        Returns the unrolled AST nodes and success status.
        """
        nodes: List[ASTNode] = []
        curr_state = start_state
        local_visited = set(visited_states)
        steps = 0

        while curr_state and steps < MAX_UNROLL_STEPS:
            steps += 1
            block = state_machine.blocks.get(curr_state)
            if not block:
                # If target state is not in CFF blocks, it might be a static exit label or external jump
                if curr_state.lower() in ('exit', 'eof', 'end'):
                    nodes.append(ExitNode(is_batch_return=False))
                    self.metrics.states_unrolled += 1
                break

            # Loop detection
            if curr_state in local_visited:
                # Loop detected: create clean loop label and goto
                loop_lbl = f"loop_{curr_state}"
                nodes.append(LabelNode(name=loop_lbl))
                # Add payload
                for s in block.statements:
                    nodes.append(s)
                nodes.append(GotoNode(target=loop_lbl))
                self.metrics.loops_reconstructed += 1
                break

            local_visited.add(curr_state)
            self.metrics.states_unrolled += 1
            self.metrics.blocks_linearized += 1
            if block.jumps_to_dispatcher:
                self.metrics.dead_jumps_pruned += 1

            # Append payload statements
            for stmt in block.statements:
                nodes.append(stmt)

            # Check if block is terminal (exit / exit /b / goto :eof)
            if block.is_terminal:
                break

            # Handle conditional branching
            if block.conditional_transitions and len(block.conditional_transitions) >= 2:
                self.metrics.conditional_branches_recovered += 1
                then_cond, then_state = block.conditional_transitions[0]
                else_cond, else_state = block.conditional_transitions[1]

                then_nodes, _ = self._unroll_path(state_machine, then_state, local_visited, depth + 1)
                else_nodes, _ = self._unroll_path(state_machine, else_state, local_visited, depth + 1)

                then_block = BlockNode(statements=then_nodes) if len(then_nodes) > 1 else (then_nodes[0] if then_nodes else BlockNode())
                else_block = BlockNode(statements=else_nodes) if len(else_nodes) > 1 else (else_nodes[0] if else_nodes else None)

                clean_cond = then_cond.replace('NOT (', '').rstrip(')') if then_cond.startswith('NOT (') else then_cond
                ifNode = IfNode(
                    condition=clean_cond,
                    then_block=then_block,
                    else_block=else_block
                )
                nodes.append(ifNode)
                break

            # Advance to next state
            if block.next_state:
                curr_state = block.next_state
            else:
                break

        return nodes, len(nodes) > 0
