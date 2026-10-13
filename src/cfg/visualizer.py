"""
Control Flow Graph Visualizer and Diagnostic Serializer for cmd.exe scripts.
Renders Mermaid flowcharts, Graphviz DOT specifications, tabular ASCII summaries,
and structured JSON payloads with dead-code and loop highlighting.
"""

from typing import Dict, Any, List
from .models import ControlFlowGraph, CFGNode, CFGEdge, CFGEdgeType


class CFGVisualizer:
    """
    Renders ControlFlowGraph instances into visual diagrams and debug text representations.
    """
    @staticmethod
    def to_mermaid(cfg: ControlFlowGraph, direction: str = "TD") -> str:
        """
        Generates Mermaid flowchart code.
        Color codes:
        - ENTRY (purple)
        - EXIT (emerald green)
        - Labels / Subroutines (sky blue)
        - Unreachable / Dead code (red dotted)
        - Normal blocks (slate blue)
        """
        lines = [f"flowchart {direction}"]

        # Class styles
        lines.append("    classDef entryClass fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#f8fafc;")
        lines.append("    classDef exitClass fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#f8fafc;")
        lines.append("    classDef labelClass fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;")
        lines.append("    classDef normalClass fill:#0f172a,stroke:#64748b,stroke-width:1.5px,color:#f8fafc;")
        lines.append("    classDef deadClass fill:#450a0a,stroke:#f87171,stroke-width:2px,stroke-dasharray:5 5,color:#fecaca;")

        # Render Nodes
        for nid, node in cfg.nodes.items():
            label_text = CFGVisualizer._format_block_label(node)
            safe_text = label_text.replace('"', "'")
            lines.append(f'    {nid}["{safe_text}"]')

            if node.is_entry:
                lines.append(f"    class {nid} entryClass;")
            elif node.is_exit:
                lines.append(f"    class {nid} exitClass;")
            elif node.is_dead:
                lines.append(f"    class {nid} deadClass;")
            elif node.label:
                lines.append(f"    class {nid} labelClass;")
            else:
                lines.append(f"    class {nid} normalClass;")

        # Render Edges
        for edge in cfg.edges:
            arrow = CFGVisualizer._format_mermaid_edge(edge)
            lines.append(f"    {edge.source} {arrow} {edge.target}")

        return "\n".join(lines)

    @staticmethod
    def _format_block_label(node: CFGNode) -> str:
        """Constructs human-readable block summary text."""
        parts = []
        if node.is_entry:
            return "🚀 ENTRY"
        if node.is_exit:
            return "🏁 EXIT / EOF"

        if node.is_dead:
            parts.append("💀 [DEAD CODE]")

        if node.label:
            parts.append(f"🏷️ :{node.label}")

        parts.append(f"[{node.id}]")

        # Statement preview
        stmt_count = len(node.statements)
        if stmt_count > 0:
            parts.append(f"({stmt_count} stmts)")
            # Include first statement preview
            first_s = node.statements[0]
            summary = getattr(first_s, 'target', None) or getattr(first_s, 'name', None) or first_s.__class__.__name__
            parts.append(f"{summary}")

        return " | ".join(parts)

    @staticmethod
    def _format_mermaid_edge(edge: CFGEdge) -> str:
        """Chooses edge style and annotation based on CFGEdgeType."""
        lbl = ""
        if edge.condition:
            lbl = f"|{edge.condition}|"
        elif edge.edge_type == CFGEdgeType.JUMP:
            lbl = "|goto|"
        elif edge.edge_type == CFGEdgeType.CALL:
            lbl = f"|call :{edge.metadata.get('subroutine', '')}|"
        elif edge.edge_type == CFGEdgeType.RETURN:
            lbl = "|return|"
        elif edge.edge_type == CFGEdgeType.BACK_EDGE:
            lbl = "|loop|"
        elif edge.edge_type == CFGEdgeType.DYNAMIC_JUMP:
            lbl = f"|dynamic:{edge.metadata.get('raw_target', '')}|"

        if edge.edge_type in (CFGEdgeType.CALL, CFGEdgeType.RETURN, CFGEdgeType.DYNAMIC_JUMP):
            return f"-.->{lbl}"
        elif edge.edge_type == CFGEdgeType.BACK_EDGE:
            return f"==>{lbl}"
        else:
            return f"-->{lbl}"

    @staticmethod
    def to_dot(cfg: ControlFlowGraph) -> str:
        """Generates Graphviz DOT syntax representation."""
        lines = ["digraph ControlFlowGraph {"]
        lines.append('    graph [rankdir=TB, bgcolor="#0f172a", fontname="Helvetica"];')
        lines.append('    node [shape=box, style=filled, fontname="Helvetica", fontcolor="#f8fafc"];')
        lines.append('    edge [fontname="Helvetica", fontcolor="#94a3b8", color="#64748b"];')

        for nid, node in cfg.nodes.items():
            color = "#1e293b"
            if node.is_entry:
                color = "#1e1b4b"
            elif node.is_exit:
                color = "#064e3b"
            elif node.is_dead:
                color = "#450a0a"
            elif node.label:
                color = "#0369a1"

            label_escaped = CFGVisualizer._format_block_label(node).replace('"', '\\"')
            lines.append(f'    "{nid}" [label="{label_escaped}", fillcolor="{color}"];')

        for edge in cfg.edges:
            style = "solid"
            color = "#64748b"
            label = edge.condition or ""

            if edge.edge_type in (CFGEdgeType.CALL, CFGEdgeType.RETURN):
                style = "dashed"
                color = "#38bdf8"
            elif edge.edge_type == CFGEdgeType.BACK_EDGE:
                style = "bold"
                color = "#fbbf24"
            elif edge.edge_type == CFGEdgeType.DYNAMIC_JUMP:
                style = "dotted"
                color = "#f43f5e"

            lbl_attr = f', label="{label}"' if label else ""
            lines.append(f'    "{edge.source}" -> "{edge.target}" [style={style}, color="{color}"{lbl_attr}];')

        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def to_ascii(cfg: ControlFlowGraph) -> str:
        """Produces a clean ASCII tabular layout of blocks and connections."""
        lines = ["=" * 70, f"CONTROL FLOW GRAPH SUMMARY (Blocks: {len(cfg.nodes)}, Edges: {len(cfg.edges)})", "=" * 70]
        metrics = cfg.compute_metrics()
        lines.append(f"Cyclomatic Complexity : {metrics.cyclomatic_complexity}")
        lines.append(f"Reachable Blocks      : {metrics.reachable_blocks} / {metrics.block_count}")
        lines.append(f"Dead Code Ratio       : {metrics.dead_block_ratio * 100:.1f}%")
        lines.append(f"Detected Loops        : {metrics.loop_count}")
        lines.append(f"Dynamic Jumps         : {metrics.dynamic_jump_count}")
        lines.append("-" * 70)

        for nid, node in cfg.nodes.items():
            dead_tag = " [DEAD]" if node.is_dead else ""
            label_tag = f" (:{node.label})" if node.label else ""
            lines.append(f"BLOCK: {nid}{label_tag}{dead_tag}")

            succs = cfg.get_successors(nid)
            succ_strs = [f"{s[0].id} ({s[1].edge_type.name})" for s in succs]
            lines.append(f"  -> Successors : {', '.join(succ_strs) if succ_strs else 'None'}")

            preds = cfg.get_predecessors(nid)
            pred_strs = [f"{p[0].id} ({p[1].edge_type.name})" for p in preds]
            lines.append(f"  <- Predecessors: {', '.join(pred_strs) if pred_strs else 'None'}")

            lines.append(f"  # Statements  : {len(node.statements)}")
            for st in node.statements[:3]:
                desc = getattr(st, 'target', None) or getattr(st, 'name', None) or st.__class__.__name__
                lines.append(f"     - {st.__class__.__name__}: {desc}")
            if len(node.statements) > 3:
                lines.append(f"     ... ({len(node.statements) - 3} more)")
            lines.append("")

        return "\n".join(lines)
