"""
Control Flow Graph Builder for cmd.exe scripts.
Constructs basic blocks, decomposes compound structures, models batch fallthrough semantics,
subroutine call/return transitions, and conditional branching paths.
"""

from typing import List, Dict, Optional, Tuple, Any
from ..ast_nodes import (
    ASTNode, ScriptNode, CommandNode, BlockNode, ChainNode,
    IfNode, ForNode, LabelNode, GotoNode, CallNode, ExitNode,
    AssignmentNode, CommentNode
)
from .models import ControlFlowGraph, CFGNode, CFGEdge, CFGEdgeType


class CFGBuilder:
    """
    Transforms hierarchical or sequential cmd.exe ASTs into a ControlFlowGraph.
    Accurately accounts for batch peculiarities:
    1. Labels do not halt execution; control falls through into labeled blocks.
    2. Subroutine CALL statements push return context and resume at the continuation block.
    3. GOTO :EOF and EXIT /B return from subroutines or exit the batch script.
    4. Dynamic jumps are mapped to dynamic edges for subsequent resolution.
    """
    def __init__(self):
        self.block_counter: int = 0

    def _next_block_id(self, prefix: str = "block") -> str:
        bid = f"{prefix}_{self.block_counter}"
        self.block_counter += 1
        return bid

    def build(self, ast: ASTNode) -> ControlFlowGraph:
        """Constructs a ControlFlowGraph from an AST root node."""
        cfg = ControlFlowGraph()
        self.block_counter = 0

        # Create explicit ENTRY and EXIT terminal nodes
        entry_node = CFGNode(id="entry", is_entry=True)
        exit_node = CFGNode(id="exit", is_exit=True)
        cfg.add_node(entry_node)
        cfg.add_node(exit_node)

        # Flatten statements from root
        flat_stmts = self._flatten_statements(ast)
        if not flat_stmts:
            cfg.add_edge("entry", "exit", CFGEdgeType.FALLTHROUGH)
            return cfg

        # Step 1: Pre-pass to register all Label definitions
        self._register_labels(flat_stmts, cfg)

        # Step 2: Build Basic Blocks and sequential control flow
        self._build_blocks(flat_stmts, cfg)

        # Step 3: Resolve jump and call target edges
        self._resolve_control_transfers(cfg)

        # Step 4: Compute reachability and cycles
        cfg.compute_reachability()
        cfg.find_cycles()

        return cfg

    def _flatten_statements(self, node: ASTNode) -> List[ASTNode]:
        """Unwraps ScriptNodes, BlockNodes, and sequential ChainNodes into linear sequence."""
        if isinstance(node, ScriptNode):
            res = []
            for s in node.statements:
                res.extend(self._flatten_statements(s))
            return res
        elif isinstance(node, BlockNode):
            res = []
            for s in node.statements:
                res.extend(self._flatten_statements(s))
            return res
        elif isinstance(node, ChainNode) and node.operator == '&':
            return self._flatten_statements(node.left) + self._flatten_statements(node.right)
        elif isinstance(node, CommentNode):
            # Comments are preserved in CFG metadata but don't divert control flow
            return [node]
        else:
            return [node]

    def _register_labels(self, statements: List[ASTNode], cfg: ControlFlowGraph):
        """Scans statements to pre-create nodes for all defined labels."""
        for stmt in statements:
            if isinstance(stmt, LabelNode):
                clean_lbl = stmt.name.lstrip(':').strip().lower()
                if clean_lbl and clean_lbl != 'eof':
                    node_id = f"label_{clean_lbl}"
                    if node_id not in cfg.nodes:
                        lbl_node = CFGNode(id=node_id, label=stmt.name)
                        cfg.add_node(lbl_node)

    def _build_blocks(self, statements: List[ASTNode], cfg: ControlFlowGraph):
        """Partitions linear statements into basic blocks and connects fallthrough/branch edges."""
        current_block: Optional[CFGNode] = None
        first_executable_id: Optional[str] = None

        def start_new_block(label: Optional[str] = None, custom_id: Optional[str] = None) -> CFGNode:
            nonlocal current_block
            bid = custom_id or (f"label_{label.lower()}" if label else self._next_block_id())
            if bid in cfg.nodes:
                node = cfg.nodes[bid]
                if label and not node.label:
                    node.label = label
            else:
                node = CFGNode(id=bid, label=label)
                cfg.add_node(node)
            return node

        i = 0
        n = len(statements)
        pending_call_returns: List[Tuple[str, str]] = []  # (subroutine_lbl, return_target_block_id)

        while i < n:
            stmt = statements[i]

            if isinstance(stmt, LabelNode):
                clean_lbl = stmt.name.lstrip(':').strip().lower()
                target_id = f"label_{clean_lbl}" if clean_lbl != 'eof' else self._next_block_id("eof_block")

                # If we have an active block, batch falls through into the label block!
                if current_block is not None:
                    if not current_block.has_unconditional_jump and not current_block.has_return and not current_block.has_process_exit:
                        cfg.add_edge(current_block.id, target_id, CFGEdgeType.FALLTHROUGH)

                current_block = start_new_block(label=stmt.name, custom_id=target_id)
                current_block.statements.append(stmt)
                if first_executable_id is None:
                    first_executable_id = current_block.id
                i += 1
                continue

            if current_block is None:
                current_block = start_new_block()
                if first_executable_id is None:
                    first_executable_id = current_block.id

            current_block.statements.append(stmt)

            if isinstance(stmt, GotoNode):
                # Unconditional branch terminates the basic block
                current_block = None
            elif isinstance(stmt, ExitNode):
                # Exit terminates the basic block
                current_block = None
            elif isinstance(stmt, CallNode) and stmt.is_subroutine:
                # Local subroutine call splits the block into a call site and continuation
                continuation_block = start_new_block()
                call_block_id = current_block.id
                clean_target = stmt.target.lstrip(':').strip().lower()
                target_lbl_id = f"label_{clean_target}"

                # Edge from caller to subroutine
                cfg.add_edge(call_block_id, target_lbl_id, CFGEdgeType.CALL, metadata={"subroutine": stmt.target})
                # Remember that subroutine returns to continuation
                pending_call_returns.append((clean_target, continuation_block.id))
                current_block = continuation_block
            elif isinstance(stmt, IfNode):
                # Conditional branch handling
                then_stmts = self._flatten_statements(stmt.then_block)
                else_stmts = self._flatten_statements(stmt.else_block) if stmt.else_block else []

                then_block = start_new_block(custom_id=self._next_block_id("if_then"))
                then_block.statements.extend(then_stmts)

                cont_block = start_new_block(custom_id=self._next_block_id("if_cont"))

                cfg.add_edge(current_block.id, then_block.id, CFGEdgeType.COND_TRUE, condition=stmt.condition)

                if else_stmts:
                    else_block = start_new_block(custom_id=self._next_block_id("if_else"))
                    else_block.statements.extend(else_stmts)
                    cfg.add_edge(current_block.id, else_block.id, CFGEdgeType.COND_FALSE, condition=f"NOT ({stmt.condition})")

                    if not else_block.has_unconditional_jump and not else_block.has_return:
                        cfg.add_edge(else_block.id, cont_block.id, CFGEdgeType.FALLTHROUGH)
                else:
                    cfg.add_edge(current_block.id, cont_block.id, CFGEdgeType.COND_FALSE, condition=f"NOT ({stmt.condition})")

                if not then_block.has_unconditional_jump and not then_block.has_return:
                    cfg.add_edge(then_block.id, cont_block.id, CFGEdgeType.FALLTHROUGH)

                current_block = cont_block
            elif isinstance(stmt, ForNode):
                # Loop construct handling
                loop_header = start_new_block(custom_id=self._next_block_id("for_header"))
                loop_body = start_new_block(custom_id=self._next_block_id("for_body"))
                loop_cont = start_new_block(custom_id=self._next_block_id("for_cont"))

                loop_body.statements.extend(self._flatten_statements(stmt.body))

                cfg.add_edge(current_block.id, loop_header.id, CFGEdgeType.FALLTHROUGH)
                cfg.add_edge(loop_header.id, loop_body.id, CFGEdgeType.COND_TRUE, condition=f"in {stmt.in_clause}")
                cfg.add_edge(loop_header.id, loop_cont.id, CFGEdgeType.COND_FALSE, condition="loop_exhausted")

                if not loop_body.has_unconditional_jump and not loop_body.has_return:
                    cfg.add_edge(loop_body.id, loop_header.id, CFGEdgeType.BACK_EDGE)

                current_block = loop_cont

            i += 1

        # Connect ENTRY to first executable block
        if first_executable_id:
            cfg.add_edge("entry", first_executable_id, CFGEdgeType.FALLTHROUGH)
        else:
            cfg.add_edge("entry", "exit", CFGEdgeType.FALLTHROUGH)

        # Connect dangling fallthrough block to EXIT
        if current_block is not None and not current_block.has_unconditional_jump and not current_block.has_return:
            cfg.add_edge(current_block.id, "exit", CFGEdgeType.FALLTHROUGH)

        # Connect pending subroutine returns
        for sub_lbl, return_target in pending_call_returns:
            sub_nodes = cfg.get_subroutines().get(sub_lbl, [])
            for sn in sub_nodes:
                if sn.has_return:
                    cfg.add_edge(sn.id, return_target, CFGEdgeType.RETURN, metadata={"return_from": sub_lbl})

    def _resolve_control_transfers(self, cfg: ControlFlowGraph):
        """Scans terminator statements in each block and creates outgoing branch edges."""
        for node_id, node in list(cfg.nodes.items()):
            if node.is_entry or node.is_exit or not node.statements:
                continue

            term = node.terminator

            if isinstance(term, GotoNode):
                clean_target = term.target.lstrip(':').strip().lower()
                if term.is_eof or clean_target == 'eof':
                    cfg.add_edge(node_id, "exit", CFGEdgeType.RETURN, metadata={"eof": True})
                elif term.is_dynamic:
                    cfg.add_edge(node_id, "exit", CFGEdgeType.DYNAMIC_JUMP, metadata={"raw_target": term.target, "dynamic": True})
                else:
                    target_id = f"label_{clean_target}"
                    if target_id in cfg.nodes:
                        cfg.add_edge(node_id, target_id, CFGEdgeType.JUMP, metadata={"label": term.target})
                    else:
                        # Target label not found in script: jumps to EXIT or creates unresolved node
                        cfg.add_edge(node_id, "exit", CFGEdgeType.JUMP, metadata={"missing_label": term.target})

            elif isinstance(term, ExitNode):
                if term.is_batch_return:
                    cfg.add_edge(node_id, "exit", CFGEdgeType.RETURN, metadata={"exit_code": term.exit_code})
                else:
                    cfg.add_edge(node_id, "exit", CFGEdgeType.TERMINATE, metadata={"exit_code": term.exit_code})
