"""
Dynamic Jump Table & Call Target Resolver for cmd.exe scripts.
Tracks environment variable assignments, resolves computed GOTO/CALL targets,
maps control flow flattening (CFF) dispatch state machines, and mutates CFG edges.
"""

import re
from typing import Dict, List, Set, Optional, Tuple, Any
from ..ast_nodes import ASTNode, AssignmentNode, GotoNode, CallNode, VarExpandNode
from .models import ControlFlowGraph, CFGEdge, CFGEdgeType, CFGNode


class JumpTableResolutionResult:
    """Telemetry report of jump table resolution and dispatch analysis."""
    def __init__(self):
        self.total_dynamic_jumps: int = 0
        self.resolved_jumps: int = 0
        self.unresolved_jumps: int = 0
        self.cff_dispatchers: List[str] = []
        self.resolved_transitions: List[Tuple[str, str, str]] = []  # (source, var_expr, target)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_dynamic_jumps": self.total_dynamic_jumps,
            "resolved_jumps": self.resolved_jumps,
            "unresolved_jumps": self.unresolved_jumps,
            "cff_dispatchers": self.cff_dispatchers,
            "resolved_transitions": [
                {"source": s, "expression": e, "target": t}
                for s, e, t in self.resolved_transitions
            ]
        }


class JumpTableResolver:
    """
    Analyzes dynamic jumps (%VAR%, !VAR!, :label_%ID%) across CFG basic blocks.
    Propagates variable state along basic block sequences, substitutes target expressions,
    and replaces or supplements dynamic edges with concrete edges.
    """
    def __init__(self, initial_env: Optional[Dict[str, str]] = None):
        self.initial_env: Dict[str, str] = {k.lower(): v for k, v in (initial_env or {}).items()}

    def resolve(self, cfg: ControlFlowGraph) -> JumpTableResolutionResult:
        """
        Scans CFG nodes, tracks variable assignments, and resolves dynamic jump and call edges.
        """
        report = JumpTableResolutionResult()

        # Step 1: Compute block-level variable assignments
        block_env_map: Dict[str, Dict[str, str]] = self._track_block_environments(cfg)

        # Step 2: Iterate over dynamic edges and attempt resolution
        edges_to_remove: List[CFGEdge] = []
        edges_to_add: List[CFGEdge] = []

        for edge in list(cfg.edges):
            if edge.edge_type != CFGEdgeType.DYNAMIC_JUMP:
                continue

            report.total_dynamic_jumps += 1
            src_node = cfg.get_node(edge.source)
            if not src_node:
                continue

            raw_target = edge.metadata.get("raw_target", "")
            env_at_source = block_env_map.get(edge.source, dict(self.initial_env))

            # Attempt evaluation of variable placeholders
            resolved_targets = self._evaluate_target_expression(raw_target, env_at_source, cfg)

            if resolved_targets:
                report.resolved_jumps += 1
                edges_to_remove.append(edge)

                for target_lbl in resolved_targets:
                    clean_lbl = target_lbl.lstrip(':').strip().lower()
                    target_node = cfg.get_node_by_label(clean_lbl)
                    if target_node:
                        new_edge = CFGEdge(
                            source=edge.source,
                            target=target_node.id,
                            edge_type=CFGEdgeType.JUMP,
                            condition=f"resolved:{raw_target}",
                            metadata={
                                "resolved": True,
                                "dynamic_origin": raw_target,
                                "target_label": target_lbl
                            }
                        )
                        edges_to_add.append(new_edge)
                        report.resolved_transitions.append((edge.source, raw_target, target_node.id))
                    elif clean_lbl == 'eof':
                        new_edge = CFGEdge(
                            source=edge.source,
                            target="exit",
                            edge_type=CFGEdgeType.RETURN,
                            condition=f"resolved:{raw_target}",
                            metadata={"resolved": True, "eof": True}
                        )
                        edges_to_add.append(new_edge)
                        report.resolved_transitions.append((edge.source, raw_target, "exit"))
            else:
                report.unresolved_jumps += 1

        # Apply edge modifications
        for old_edge in edges_to_remove:
            if old_edge in cfg.edges:
                cfg.edges.remove(old_edge)

        for new_edge in edges_to_add:
            cfg.edges.append(new_edge)

        # Step 3: Detect Control Flow Flattening (CFF) dispatch structures
        report.cff_dispatchers = self._detect_cff_dispatchers(cfg)

        # Refresh reachability and cycle structure after adding new edges
        cfg.compute_reachability()
        cfg.find_cycles()

        return report

    def _track_block_environments(self, cfg: ControlFlowGraph) -> Dict[str, Dict[str, str]]:
        """
        Constructs an environment map for each basic block by sequentially accumulating SET statements.
        Performs forward data-flow propagation across basic blocks.
        """
        block_envs: Dict[str, Dict[str, str]] = {}

        # First pass: intra-block assignments
        for nid, node in cfg.nodes.items():
            current_env = dict(self.initial_env)
            for stmt in node.statements:
                if isinstance(stmt, AssignmentNode):
                    current_env[stmt.var_name.lower()] = stmt.raw_value
            block_envs[nid] = current_env

        # Second pass: propagate along fallthrough / jump chains
        changed = True
        iterations = 0
        while changed and iterations < 10:
            changed = False
            iterations += 1
            for nid, node in cfg.nodes.items():
                curr_env = block_envs[nid]
                for succ_node, edge in cfg.get_successors(nid):
                    succ_env = block_envs.get(succ_node.id, {})
                    # Propagate variables that are not overwritten in succ_node
                    for k, v in curr_env.items():
                        if k not in succ_env:
                            succ_env[k] = v
                            changed = True

        return block_envs

    def _evaluate_target_expression(
        self,
        target_expr: str,
        env: Dict[str, str],
        cfg: ControlFlowGraph
    ) -> List[str]:
        """
        Resolves variable references in target_expr (%VAR%, !VAR!).
        Returns list of possible matching label names in the script.
        """
        if not target_expr:
            return []

        # Substitute %VAR%
        expanded = re.sub(
            r'%([a-zA-Z0-9_#$@]+)%',
            lambda m: env.get(m.group(1).lower(), m.group(0)),
            target_expr
        )
        # Substitute !VAR!
        expanded = re.sub(
            r'!([a-zA-Z0-9_#$@]+)!',
            lambda m: env.get(m.group(1).lower(), m.group(0)),
            expanded
        )

        clean_exp = expanded.lstrip(':').strip().lower()

        # Check if direct match with known label or EOF
        if clean_exp in cfg.labels_to_nodes or clean_exp == 'eof':
            return [clean_exp]

        # If unresolved variable remains (e.g. %VAR% or !VAR!), try pattern prefix matching
        # Example: goto :state_%ID% -> find all labels matching state_*
        if '%' in expanded or '!' in expanded:
            prefix = re.split(r'[%!]', expanded.lstrip(':'))[0].lower()
            if prefix:
                matching_labels = [
                    lbl for lbl in cfg.labels_to_nodes.keys()
                    if lbl.startswith(prefix) and lbl != 'eof'
                ]
                if matching_labels:
                    return matching_labels

        return []

    def _detect_cff_dispatchers(self, cfg: ControlFlowGraph) -> List[str]:
        """
        Identifies Control Flow Flattening (CFF) dispatcher blocks.
        A dispatcher block typically:
        1. Is targeted by multiple incoming jump transitions from distinct handler blocks.
        2. Forms cycles with those state handler blocks.
        """
        dispatchers: List[str] = []

        for nid, node in cfg.nodes.items():
            if node.is_entry or node.is_exit:
                continue

            preds = cfg.get_predecessors(nid)
            # Find distinct blocks that jump to this block
            jumping_sources = {
                p[0].id for p in preds
                if p[1].edge_type in (CFGEdgeType.JUMP, CFGEdgeType.BACK_EDGE, CFGEdgeType.DYNAMIC_JUMP)
                and not p[0].is_entry and p[0].id != nid
            }

            if len(jumping_sources) >= 2:
                # Verify that this block can reach back to the jumping sources (forming a dispatch cycle)
                reachable = cfg.compute_reachability(start_id=nid)
                if any(src in reachable for src in jumping_sources):
                    dispatchers.append(nid)

        return dispatchers

