"""
String Reversal and Transposition AST Transform Optimization Pass.
Folds Somalifuscator FOR /L reverse loops, FOR IN index transposition lookups,
pushdown stack GOTO loops, and decreasing/transposed slice sequences into decoded literals.
"""

from typing import Dict, List, Optional
from ..ast_nodes import (
    ASTNode, LiteralNode, VarExpandNode, CommandNode,
    AssignmentNode, BlockNode, ChainNode, PipeNode,
    RedirectNode, ScriptNode, IfNode, ForNode,
    LabelNode, GotoNode
)
from .base import TransformPass
from ..reversal.models import ReversalMetrics, ReversalLoopSpec, ReversalPatternType
from ..reversal.automaton import StringReversalAutomaton
from ..reversal.detector import ReversalPatternDetector


class ReversalFolderPass(TransformPass):
    """
    Compiler-grade AST optimization pass for Windows cmd.exe string reversal
    and transposition obfuscation techniques.
    """

    def __init__(
        self,
        env: Optional[Dict[str, str]] = None,
        max_simulation_steps: int = 20000
    ):
        super().__init__(name="ReversalFolderPass", env=env)
        self.metrics = ReversalMetrics()
        self.detector = ReversalPatternDetector()
        self.automaton = StringReversalAutomaton()
        self.max_simulation_steps = max_simulation_steps

    def _fold_transposed_slices_in_list(self, nodes: List[ASTNode]) -> List[ASTNode]:
        """
        Detects contiguous slice runs of the same variable and folds them into single literals.
        e.g., %s:~3,1%%s:~2,1%%s:~1,1%%s:~0,1% -> 'calc'
        """
        if not nodes or len(nodes) < 2:
            return nodes

        runs = self.detector.detect_slice_transposition_sequence(nodes, self.env)
        if not runs:
            return nodes

        # Process from right to left so indices don't shift
        new_nodes = list(nodes)
        for start_idx, end_idx, var_name, starts, lens in reversed(runs):
            raw_val = self.env.get(var_name.lower())
            if raw_val is None:
                continue

            extracted_parts = []
            for s, l in zip(starts, lens):
                chunk = self.automaton.get_slice(raw_val, s, l)
                extracted_parts.append(chunk)

            fused_value = "".join(extracted_parts)
            folded_node = LiteralNode(
                value=fused_value,
                is_quoted=False,
                is_folded_slice=True,
                span=(new_nodes[start_idx].span[0], new_nodes[end_idx - 1].span[1])
            )

            new_nodes[start_idx:end_idx] = [folded_node]
            self.metrics.transposed_slices_folded += 1
            self.metrics.characters_decoded += len(fused_value)
            self.modified = True

        return new_nodes

    def visit_ForNode(self, node: ForNode) -> ASTNode:
        """
        Folds FOR /L and FOR IN reversal and transposition loops into concrete assignments.
        """
        # 1. Try detecting FOR /L reversal loop
        for_l_spec = self.detector.detect_for_l_reversal(node, self.env)
        if for_l_spec:
            source_key = for_l_spec.source_var.lower()
            if source_key in self.env:
                source_val = self.env[source_key]
                sim_res = self.automaton.simulate_slice_loop(
                    source_text=source_val,
                    start=for_l_spec.start,
                    step=for_l_spec.step,
                    stop=for_l_spec.stop,
                    slice_len=for_l_spec.slice_len,
                    is_prepend=for_l_spec.is_prepend,
                    max_steps=self.max_simulation_steps
                )
                decoded = sim_res.decoded_text
                dest_key = for_l_spec.dest_var.lower()
                self.env[dest_key] = decoded

                self.metrics.loops_detected += 1
                self.metrics.loops_folded += 1
                self.metrics.characters_decoded += len(decoded)
                self.modified = True

                return AssignmentNode(
                    var_name=for_l_spec.dest_var,
                    value_nodes=[LiteralNode(value=decoded, is_quoted=False)],
                    raw_value=decoded,
                    span=node.span
                )

        # 2. Try detecting FOR IN index transposition loop
        for_in_spec = self.detector.detect_for_in_transposition(node, self.env)
        if for_in_spec:
            source_key = for_in_spec.source_var.lower()
            if source_key in self.env:
                source_val = self.env[source_key]
                int_indices = [int(x) for x in for_in_spec.in_items]
                sim_res = self.automaton.simulate_index_sequence(
                    source_text=source_val,
                    indices=int_indices,
                    slice_len=for_in_spec.slice_len,
                    is_prepend=for_in_spec.is_prepend,
                    max_steps=self.max_simulation_steps
                )
                decoded = sim_res.decoded_text
                dest_key = for_in_spec.dest_var.lower()
                self.env[dest_key] = decoded

                self.metrics.loops_detected += 1
                self.metrics.loops_folded += 1
                self.metrics.characters_decoded += len(decoded)
                self.modified = True

                return AssignmentNode(
                    var_name=for_in_spec.dest_var,
                    value_nodes=[LiteralNode(value=decoded, is_quoted=False)],
                    raw_value=decoded,
                    span=node.span
                )

        # Fallback to standard AST traversal on child body
        new_body = self.visit(node.body) if node.body else node.body
        if new_body is not node.body:
            self.modified = True
            return ForNode(
                iterator=node.iterator,
                flags=node.flags,
                options=node.options,
                in_clause=node.in_clause,
                body=new_body,
                span=node.span
            )
        return node

    def _process_statement_list(self, statements: List[ASTNode]) -> List[ASTNode]:
        """
        Processes a list of statements sequentially, updating environment definitions
        and detecting GOTO stack reversal loops at label boundaries.
        """
        new_stmts: List[ASTNode] = []
        i = 0
        n = len(statements)

        while i < n:
            stmt = statements[i]
            # When encountering a label, check if a GOTO reversal loop begins here
            if isinstance(stmt, LabelNode):
                goto_match = self.detector.detect_goto_reversal_loop(statements[i:], self.env)
                if goto_match:
                    rel_start, rel_end, spec = goto_match
                    source_key = spec.source_var.lower()
                    if source_key in self.env:
                        source_val = self.env[source_key]
                        sim_res = self.automaton.simulate_stack_reversal(
                            source_text=source_val,
                            max_steps=self.max_simulation_steps
                        )
                        decoded = sim_res.decoded_text
                        dest_key = spec.dest_var.lower()
                        self.env[dest_key] = decoded
                        self.env[source_key] = ""  # Source stack exhausted

                        self.metrics.goto_loops_folded += 1
                        self.metrics.characters_decoded += len(decoded)
                        self.modified = True

                        replacement_stmt = AssignmentNode(
                            var_name=spec.dest_var,
                            value_nodes=[LiteralNode(value=decoded, is_quoted=False)],
                            raw_value=decoded
                        )
                        new_stmts.append(replacement_stmt)
                        i += (rel_end + 1)
                        continue

            visited = self.visit(stmt)
            if visited is not None:
                new_stmts.append(visited)
            i += 1

        return new_stmts

    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        """
        Processes top-level script statements sequentially with GOTO loop folding.
        """
        new_stmts = self._process_statement_list(node.statements)
        if new_stmts != node.statements:
            self.modified = True
            return ScriptNode(statements=new_stmts, span=node.span)
        return node

    def visit_BlockNode(self, node: BlockNode) -> BlockNode:
        """
        Processes block statements sequentially with GOTO loop folding.
        """
        new_stmts = self._process_statement_list(node.statements)
        if new_stmts != node.statements:
            self.modified = True
            return BlockNode(statements=new_stmts, span=node.span)
        return node

    def visit_AssignmentNode(self, node: AssignmentNode) -> AssignmentNode:
        """
        Records variables in environment and folds any transposed slices in values.
        """
        folded_val_nodes = self._fold_transposed_slices_in_list(node.value_nodes)
        new_val_nodes = [self.visit(v) for v in folded_val_nodes]
        changed = (new_val_nodes != node.value_nodes)

        # Update environment tracking
        var_key = node.var_name.lower()
        if new_val_nodes and all(isinstance(v, LiteralNode) for v in new_val_nodes):
            self.env[var_key] = "".join(v.value for v in new_val_nodes)
        else:
            self.env[var_key] = node.raw_value

        if changed:
            self.modified = True
            raw_v = "".join(self.to_source(v) for v in new_val_nodes)
            return AssignmentNode(
                var_name=node.var_name,
                value_nodes=new_val_nodes,
                raw_value=raw_v or node.raw_value,
                is_arithmetic=node.is_arithmetic,
                span=node.span
            )
        return node

    def visit_CommandNode(self, node: CommandNode) -> CommandNode:
        """
        Folds transposed slice sequences in target_nodes and arguments.
        """
        new_targets = self._fold_transposed_slices_in_list(node.target_nodes) if node.target_nodes else []
        new_targets = [self.visit(t) for t in new_targets]

        new_args = self._fold_transposed_slices_in_list(node.arguments)
        new_args = [self.visit(a) for a in new_args]

        changed = (new_targets != node.target_nodes) or (new_args != node.arguments)
        if changed:
            self.modified = True
            new_target_str = node.target
            if new_targets and all(isinstance(t, LiteralNode) for t in new_targets):
                new_target_str = "".join(t.value for t in new_targets)
            return CommandNode(
                target=new_target_str,
                target_nodes=new_targets,
                arguments=new_args,
                span=node.span
            )
        return node
