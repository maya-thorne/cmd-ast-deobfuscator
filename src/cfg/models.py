"""
Control Flow Graph (CFG) Data Models and Graph Hierarchy for cmd.exe scripts.
Provides basic blocks, typed directed edges, cyclomatic complexity metrics,
and reachability/cycle analysis data structures.
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from ..ast_nodes import ASTNode, LabelNode, GotoNode, CallNode, ExitNode, IfNode, ForNode


class CFGEdgeType(Enum):
    """Classification of directed control flow transitions."""
    FALLTHROUGH = auto()       # Sequential execution to physically succeeding block
    JUMP = auto()              # Unconditional branch (e.g., goto :target)
    COND_TRUE = auto()         # Branch taken when IF condition evaluates to true
    COND_FALSE = auto()        # Branch taken when IF condition evaluates to false (or else/fallthrough)
    CALL = auto()              # Interprocedural subroutine call (e.g., call :sub)
    RETURN = auto()            # Subroutine return to call site (goto :eof or exit /b)
    DYNAMIC_JUMP = auto()      # Dynamic unresolved/resolved jump (e.g., goto %STATE%)
    BACK_EDGE = auto()         # Loop backward transition detected during cycle analysis
    TERMINATE = auto()         # Script or process termination edge


@dataclass
class CFGEdge:
    """Directed edge in the control flow graph."""
    source: str
    target: str
    edge_type: CFGEdgeType = CFGEdgeType.FALLTHROUGH
    condition: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type.name,
            "condition": self.condition,
            "metadata": self.metadata
        }


@dataclass
class CFGNode:
    """
    Basic Block representation in the control flow graph.
    Represents a maximal sequence of straight-line instructions with single entry.
    """
    id: str
    label: Optional[str] = None
    statements: List[ASTNode] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False
    is_dead: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def terminator(self) -> Optional[ASTNode]:
        """Returns the final statement governing control flow out of this block."""
        return self.statements[-1] if self.statements else None

    @property
    def has_unconditional_jump(self) -> bool:
        """True if block unconditionally diverts control via GOTO."""
        t = self.terminator
        return isinstance(t, GotoNode) and not t.is_eof

    @property
    def has_return(self) -> bool:
        """True if block returns from subroutine or script (goto :eof or exit /b)."""
        t = self.terminator
        if isinstance(t, GotoNode) and t.is_eof:
            return True
        if isinstance(t, ExitNode) and t.is_batch_return:
            return True
        return False

    @property
    def has_process_exit(self) -> bool:
        """True if block terminates entire cmd.exe process (exit without /b)."""
        t = self.terminator
        return isinstance(t, ExitNode) and not t.is_batch_return

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "statements_count": len(self.statements),
            "is_entry": self.is_entry,
            "is_exit": self.is_exit,
            "is_dead": self.is_dead,
            "metadata": self.metadata
        }


@dataclass
class CFGMetrics:
    """Quantitative complexity and structural metrics for a CFG."""
    block_count: int
    edge_count: int
    cyclomatic_complexity: int
    reachable_blocks: int
    unreachable_blocks: int
    dead_block_ratio: float
    loop_count: int
    dynamic_jump_count: int
    subroutine_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_count": self.block_count,
            "edge_count": self.edge_count,
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "reachable_blocks": self.reachable_blocks,
            "unreachable_blocks": self.unreachable_blocks,
            "dead_block_ratio": round(self.dead_block_ratio, 4),
            "loop_count": self.loop_count,
            "dynamic_jump_count": self.dynamic_jump_count,
            "subroutine_count": self.subroutine_count
        }


class ControlFlowGraph:
    """
    Control Flow Graph container supporting reachability analysis,
    subroutine grouping, cycle detection, and dead code identification.
    """
    def __init__(self):
        self.nodes: Dict[str, CFGNode] = {}
        self.edges: List[CFGEdge] = []
        self.entry_id: str = "entry"
        self.exit_id: str = "exit"
        self.labels_to_nodes: Dict[str, str] = {}  # lowercase label -> node_id

    def add_node(self, node: CFGNode):
        """Adds a basic block node to the graph."""
        self.nodes[node.id] = node
        if node.label:
            self.labels_to_nodes[node.label.lower()] = node.id

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: CFGEdgeType = CFGEdgeType.FALLTHROUGH,
        condition: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CFGEdge:
        """Adds a directed transition edge between two blocks."""
        edge = CFGEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            condition=condition,
            metadata=metadata or {}
        )
        self.edges.append(edge)
        return edge

    def get_node(self, node_id: str) -> Optional[CFGNode]:
        """Looks up a basic block by identifier."""
        return self.nodes.get(node_id)

    def get_node_by_label(self, label: str) -> Optional[CFGNode]:
        """Looks up a basic block by case-insensitive batch label."""
        clean_lbl = label.lstrip(':').strip().lower()
        node_id = self.labels_to_nodes.get(clean_lbl)
        return self.nodes.get(node_id) if node_id else None

    def get_successors(self, node_id: str) -> List[Tuple[CFGNode, CFGEdge]]:
        """Returns list of (target_node, edge) pairs exiting node_id."""
        succs = []
        for e in self.edges:
            if e.source == node_id and e.target in self.nodes:
                succs.append((self.nodes[e.target], e))
        return succs

    def get_predecessors(self, node_id: str) -> List[Tuple[CFGNode, CFGEdge]]:
        """Returns list of (source_node, edge) pairs entering node_id."""
        preds = []
        for e in self.edges:
            if e.target == node_id and e.source in self.nodes:
                preds.append((self.nodes[e.source], e))
        return preds

    def compute_reachability(self, start_id: Optional[str] = None) -> Set[str]:
        """
        Computes the set of reachable node IDs via BFS traversal from entry.
        Marks unreachable blocks as is_dead = True.
        """
        start = start_id or self.entry_id
        if start not in self.nodes:
            return set()

        visited: Set[str] = set()
        queue = [start]
        visited.add(start)

        while queue:
            curr_id = queue.pop(0)
            for succ_node, edge in self.get_successors(curr_id):
                if succ_node.id not in visited:
                    visited.add(succ_node.id)
                    queue.append(succ_node.id)

        # Update dead state on nodes
        for nid, node in self.nodes.items():
            node.is_dead = (nid not in visited)

        return visited

    def get_unreachable_nodes(self) -> List[CFGNode]:
        """Returns all basic blocks flagged as unreachable / dead code."""
        self.compute_reachability()
        return [node for node in self.nodes.values() if node.is_dead]

    def find_cycles(self) -> List[List[str]]:
        """
        Detects cycles / loops in the CFG using depth-first search back-edge detection.
        Returns list of cycle paths represented as lists of node IDs.
        """
        visited: Set[str] = set()
        rec_stack: List[str] = []
        cycles: List[List[str]] = []

        def dfs(curr: str):
            visited.add(curr)
            rec_stack.append(curr)

            for succ_node, edge in self.get_successors(curr):
                succ = succ_node.id
                if succ not in visited:
                    dfs(succ)
                elif succ in rec_stack:
                    # Cycle detected: extract subpath from rec_stack
                    idx = rec_stack.index(succ)
                    cycle_path = rec_stack[idx:] + [succ]
                    cycles.append(cycle_path)
                    edge.edge_type = CFGEdgeType.BACK_EDGE

            rec_stack.pop()

        if self.entry_id in self.nodes:
            dfs(self.entry_id)

        # Also search unvisited components
        for nid in list(self.nodes.keys()):
            if nid not in visited:
                dfs(nid)

        return cycles

    def get_subroutines(self) -> Dict[str, List[CFGNode]]:
        """
        Groups reachable basic blocks belonging to named subroutines (labeled procedures).
        A subroutine begins at a label block and spans blocks until a return or unconditional exit.
        """
        subroutines: Dict[str, List[CFGNode]] = {}
        for lbl, nid in self.labels_to_nodes.items():
            if lbl == 'eof':
                continue
            entry_node = self.nodes.get(nid)
            if not entry_node:
                continue

            sub_blocks: List[CFGNode] = []
            visited: Set[str] = set()
            queue = [nid]
            visited.add(nid)

            while queue:
                cid = queue.pop(0)
                node = self.nodes[cid]
                sub_blocks.append(node)
                if node.has_return or node.has_process_exit:
                    continue
                for succ_node, edge in self.get_successors(cid):
                    # Do not cross into other distinct named subroutine label headers
                    if succ_node.label and succ_node.label.lower() != lbl and succ_node.label.lower() in self.labels_to_nodes:
                        continue
                    if succ_node.id not in visited and not succ_node.is_exit:
                        visited.add(succ_node.id)
                        queue.append(succ_node.id)

            subroutines[lbl] = sub_blocks

        return subroutines

    def compute_metrics(self) -> CFGMetrics:
        """Calculates cyclomatic complexity and structural properties."""
        reachable = self.compute_reachability()
        unreachable_count = len(self.nodes) - len(reachable)
        dead_ratio = unreachable_count / len(self.nodes) if self.nodes else 0.0
        cycles = self.find_cycles()

        # Cyclomatic complexity M = E - N + 2P where P = connected components (assumed 1)
        # N = number of nodes, E = number of edges
        n = len(self.nodes)
        e = len(self.edges)
        m = max(1, e - n + 2) if n > 0 else 1

        dyn_jumps = sum(
            1 for edge in self.edges if edge.edge_type == CFGEdgeType.DYNAMIC_JUMP
        )

        return CFGMetrics(
            block_count=n,
            edge_count=e,
            cyclomatic_complexity=m,
            reachable_blocks=len(reachable),
            unreachable_blocks=unreachable_count,
            dead_block_ratio=dead_ratio,
            loop_count=len(cycles),
            dynamic_jump_count=dyn_jumps,
            subroutine_count=len(self.labels_to_nodes)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the complete CFG into a JSON-compatible dictionary."""
        return {
            "entry_id": self.entry_id,
            "exit_id": self.exit_id,
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "metrics": self.compute_metrics().to_dict(),
            "labels": self.labels_to_nodes
        }
