"""
Control Flow De-flattening (Anti-CFF) Dispatcher Loop Unroller.
Performs dead state elimination, bounded deterministic loop unrolling,
structured while-loop recovery, and branch structuring from CFF state machines.
"""

from typing import List, Dict, Set, Optional, Tuple, Any
from ..ast_nodes import (
    ASTNode, ScriptNode, BlockNode, IfNode, GotoNode, LabelNode,
    ExitNode, AssignmentNode, CommandNode
)
from .models import (
    CFFStateMachine, CFFBlockInfo, CFFLoopInfo, CFFLoopType,
    CFFUnrollConfig, UnrollMode, DeflatResult, DeflatMetrics
)


class CFFDispatcherUnroller:
    """
    Unrolls state transitions and synthesizes straight-line AST nodes or structured loops.
    Eliminates central dispatcher hubs and reconstructs clean execution flows.
    """

    def __init__(self, config: Optional[CFFUnrollConfig] = None):
        self.config = config or CFFUnrollConfig()
        self.metrics = DeflatMetrics()

    def unroll(
        self,
        state_machine: CFFStateMachine,
        loops: List[CFFLoopInfo],
        dead_states: Set[str],
        metrics: Optional[DeflatMetrics] = None
    ) -> DeflatResult:
        """
        Main entry point for de-flattening and unrolling dispatcher loops.
        Prunes unreachable states, handles loops, structures branches, and generates AST.
        """
        if metrics is not None:
            self.metrics = metrics

        result = DeflatResult(state_machine=state_machine, loops=loops, metrics=self.metrics)
        self.metrics.dispatchers_detected += 1
        self.metrics.loops_detected += len(loops)

        # Step 1: Prune dead / unreachable states
        if self.config.prune_dead_states and dead_states:
            for d in dead_states:
                if d in state_machine.blocks:
                    del state_machine.blocks[d]
                    self.metrics.dead_states_pruned += 1

        # Step 2: Map loops by header
        loops_by_header: Dict[str, CFFLoopInfo] = {lp.header_state: lp for lp in loops}

        # Step 3: Unroll execution path starting from initial state
        unrolled_nodes, success = self._unroll_state_flow(
            state_machine=state_machine,
            start_state=state_machine.initial_state,
            loops_by_header=loops_by_header,
            visited_path=[],
            depth=0
        )

        if success and unrolled_nodes:
            result.success = True
            result.linearized_nodes = unrolled_nodes
        else:
            result.success = False
            result.linearized_nodes = []

        return result

    def _unroll_state_flow(
        self,
        state_machine: CFFStateMachine,
        start_state: str,
        loops_by_header: Dict[str, CFFLoopInfo],
        visited_path: List[str],
        depth: int,
        stop_state: Optional[str] = None
    ) -> Tuple[List[ASTNode], bool]:
        """
        Recursively walks state machine from start_state up to stop_state or terminal.
        """
        nodes: List[ASTNode] = []
        curr = start_state
        steps = 0
        local_path = list(visited_path)

        while curr and steps < self.config.max_unroll_steps:
            steps += 1
            if stop_state and curr == stop_state:
                break

            # Handle loops when encountering a loop header
            if curr in loops_by_header:
                loop_info = loops_by_header[curr]
                loop_nodes, next_state = self._handle_loop(
                    loop_info=loop_info,
                    state_machine=state_machine,
                    depth=depth
                )
                nodes.extend(loop_nodes)
                if next_state:
                    curr = next_state
                    continue
                else:
                    break

            block = state_machine.blocks.get(curr)
            if not block:
                # Handle external terminal targets (exit, eof, end)
                if curr.lower() in ('exit', 'eof', 'end'):
                    nodes.append(ExitNode(is_batch_return=False))
                    self.metrics.states_unrolled += 1
                break

            # Cycle detection fallback for loops not caught by loop detector
            if curr in local_path:
                loop_lbl = f"loop_{curr}"
                nodes.append(LabelNode(name=loop_lbl))
                nodes.extend(self._clean_statements(block.statements, state_machine))
                nodes.append(GotoNode(target=loop_lbl))
                self.metrics.loops_reconstructed += 1
                break

            local_path.append(curr)
            self.metrics.states_unrolled += 1
            self.metrics.blocks_linearized += 1
            if block.jumps_to_dispatcher:
                self.metrics.dead_jumps_pruned += 1

            # Append clean payload statements
            nodes.extend(self._clean_statements(block.statements, state_machine))

            if block.is_terminal:
                break

            # Handle conditional branching (multi-state or if/else)
            if block.conditional_transitions and len(block.conditional_transitions) >= 2:
                branch_nodes, next_after_branch = self._handle_conditional_branch(
                    block=block,
                    state_machine=state_machine,
                    loops_by_header=loops_by_header,
                    local_path=local_path,
                    depth=depth
                )
                nodes.extend(branch_nodes)
                if next_after_branch:
                    curr = next_after_branch
                    continue
                else:
                    break

            # Advance to next state
            if block.next_state:
                curr = block.next_state
            else:
                break

        return nodes, len(nodes) > 0

    def _handle_loop(
        self,
        loop_info: CFFLoopInfo,
        state_machine: CFFStateMachine,
        depth: int
    ) -> Tuple[List[ASTNode], Optional[str]]:
        """Dispatches loop unrolling or reconstruction according to config and loop type."""
        mode = self.config.unroll_mode
        should_unroll = (
            mode == UnrollMode.FULL_UNROLL or
            (mode == UnrollMode.AUTO and loop_info.loop_type == CFFLoopType.DETERMINISTIC_UNROLLED
             and loop_info.iteration_count is not None)
        )

        if should_unroll and loop_info.iteration_count:
            return self._unroll_deterministic_loop(loop_info, state_machine)
        else:
            return self._reconstruct_structured_loop(loop_info, state_machine, depth)

    def _unroll_deterministic_loop(
        self,
        loop_info: CFFLoopInfo,
        state_machine: CFFStateMachine
    ) -> Tuple[List[ASTNode], Optional[str]]:
        """Unrolls all bounded iterations sequentially into linear straight-line statements."""
        nodes: List[ASTNode] = []
        iterations = min(loop_info.iteration_count or 1, self.config.max_unroll_iterations)

        # Sort body states preserving transition order from header
        ordered_states = self._order_body_states(loop_info, state_machine)

        for _ in range(iterations):
            for s in ordered_states:
                blk = state_machine.blocks.get(s)
                if not blk:
                    continue
                self.metrics.states_unrolled += 1
                self.metrics.blocks_linearized += 1
                if blk.jumps_to_dispatcher:
                    self.metrics.dead_jumps_pruned += 1
                nodes.extend(self._clean_statements(blk.statements, state_machine))

        self.metrics.loops_fully_unrolled += 1

        # Determine exit target state outside loop body
        exit_target = self._find_exit_target(loop_info, state_machine)
        return nodes, exit_target

    def _reconstruct_structured_loop(
        self,
        loop_info: CFFLoopInfo,
        state_machine: CFFStateMachine,
        depth: int
    ) -> Tuple[List[ASTNode], Optional[str]]:
        """Reconstructs clean structured while-loop without dispatcher bounces."""
        nodes: List[ASTNode] = []
        header = loop_info.header_state
        loop_lbl = f"loop_{header}"
        exit_lbl = f"loop_exit_{header}"

        nodes.append(LabelNode(name=loop_lbl))

        # Order body states from header to latches
        ordered_states = self._order_body_states(loop_info, state_machine)
        exit_target = self._find_exit_target(loop_info, state_machine)

        for s in ordered_states:
            blk = state_machine.blocks.get(s)
            if not blk:
                continue
            self.metrics.states_unrolled += 1
            self.metrics.blocks_linearized += 1
            if blk.jumps_to_dispatcher:
                self.metrics.dead_jumps_pruned += 1

            # Emit exit condition if this state exits the loop
            if s in loop_info.exit_states:
                for cond, tgt in blk.conditional_transitions:
                    if tgt not in loop_info.body_states:
                        clean_c = self._clean_condition(cond)
                        nodes.append(IfNode(condition=clean_c, then_block=GotoNode(target=exit_lbl)))
                        break

            nodes.extend(self._clean_statements(blk.statements, state_machine))

        # Close loop with back jump to header
        nodes.append(GotoNode(target=loop_lbl))
        nodes.append(LabelNode(name=exit_lbl))

        self.metrics.loops_reconstructed += 1
        return nodes, exit_target

    def _handle_conditional_branch(
        self,
        block: CFFBlockInfo,
        state_machine: CFFStateMachine,
        loops_by_header: Dict[str, CFFLoopInfo],
        local_path: List[str],
        depth: int
    ) -> Tuple[List[ASTNode], Optional[str]]:
        """Constructs structured IfNode for multi-state branches and identifies join points."""
        self.metrics.conditional_branches_recovered += 1
        then_cond, then_state = block.conditional_transitions[0]
        else_cond, else_state = block.conditional_transitions[1]

        # Determine join state if both branches converge
        join_state = self._find_join_state(then_state, else_state, state_machine)

        then_nodes, _ = self._unroll_state_flow(
            state_machine=state_machine,
            start_state=then_state,
            loops_by_header=loops_by_header,
            visited_path=local_path,
            depth=depth + 1,
            stop_state=join_state
        )

        else_nodes, _ = self._unroll_state_flow(
            state_machine=state_machine,
            start_state=else_state,
            loops_by_header=loops_by_header,
            visited_path=local_path,
            depth=depth + 1,
            stop_state=join_state
        )

        then_block = BlockNode(statements=then_nodes) if len(then_nodes) > 1 else (
            then_nodes[0] if then_nodes else BlockNode()
        )
        else_block = BlockNode(statements=else_nodes) if len(else_nodes) > 1 else (
            else_nodes[0] if else_nodes else None
        )

        clean_cond = self._clean_condition(then_cond)
        ifNode = IfNode(
            condition=clean_cond,
            then_block=then_block,
            else_block=else_block
        )

        return [ifNode], join_state

    def _find_join_state(
        self,
        state_a: str,
        state_b: str,
        state_machine: CFFStateMachine
    ) -> Optional[str]:
        """Finds nearest common successor node where branches converge."""
        blk_a = state_machine.blocks.get(state_a)
        blk_b = state_machine.blocks.get(state_b)
        if not blk_a or not blk_b:
            return None
        if blk_a.next_state and blk_a.next_state == blk_b.next_state:
            return blk_a.next_state
        return None

    def _order_body_states(
        self,
        loop_info: CFFLoopInfo,
        state_machine: CFFStateMachine
    ) -> List[str]:
        """Orders states in loop body starting from header following next_state transitions."""
        ordered: List[str] = []
        curr = loop_info.header_state
        visited: Set[str] = set()

        while curr in loop_info.body_states and curr not in visited:
            visited.add(curr)
            ordered.append(curr)
            blk = state_machine.blocks.get(curr)
            if not blk:
                break
            nxt = None
            if blk.next_state and blk.next_state in loop_info.body_states:
                nxt = blk.next_state
            else:
                for _, tgt in blk.conditional_transitions:
                    if tgt in loop_info.body_states and tgt not in visited:
                        nxt = tgt
                        break
            curr = nxt

        # Append any remaining body states not covered by simple linear path
        for s in loop_info.body_states:
            if s not in visited:
                ordered.append(s)

        return ordered

    def _find_exit_target(
        self,
        loop_info: CFFLoopInfo,
        state_machine: CFFStateMachine
    ) -> Optional[str]:
        """Identifies target state outside loop body reached upon loop exit."""
        for s in loop_info.exit_states:
            blk = state_machine.blocks.get(s)
            if not blk:
                continue
            for _, tgt in blk.conditional_transitions:
                if tgt not in loop_info.body_states:
                    return tgt
            if blk.next_state and blk.next_state not in loop_info.body_states:
                return blk.next_state
        return None

    def _clean_statements(
        self,
        stmts: List[ASTNode],
        state_machine: CFFStateMachine
    ) -> List[ASTNode]:
        """Filters out dispatcher jumps and state variable assignments."""
        clean: List[ASTNode] = []
        dispatch_lbl = state_machine.dispatcher_label.lower()
        state_var = state_machine.state_var.lower()

        for s in stmts:
            if isinstance(s, AssignmentNode):
                if s.var_name.lower() == state_var:
                    continue
            if isinstance(s, GotoNode):
                tgt = s.target.lstrip(':').lower()
                if tgt == dispatch_lbl:
                    continue
            if isinstance(s, CommandNode):
                if s.target.lower() == 'goto' and s.arguments:
                    arg_str = "".join(getattr(a, 'value', str(a)) for a in s.arguments).lstrip(':').lower()
                    if arg_str == dispatch_lbl:
                        continue
            clean.append(s)
        return clean

    def _clean_condition(self, cond: str) -> str:
        """Strips NOT wrapping if present for cleaner IfNode representation."""
        if cond.startswith('NOT (') and cond.endswith(')'):
            return cond[5:-1].strip()
        return cond

    def zeroize(self) -> None:
        """Securely zeroizes internal metrics and configurations."""
        self.metrics.zeroize()
        self.config.zeroize()
