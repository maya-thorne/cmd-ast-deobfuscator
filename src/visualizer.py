"""
AST Visualizer & Diagnostics Renderer for cmd.exe scripts.
Generates ASCII tree representations, Mermaid graph definitions, and JSON AST dumps.
"""

import json
from typing import List, Dict, Any
from .ast_nodes import (
    ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, CommentNode
)


class ASTVisualizer:
    """
    Renders Abstract Syntax Trees into human-readable visual representations.
    """
    @staticmethod
    def render_ascii_tree(node: ASTNode, prefix: str = "", is_last: bool = True) -> str:
        """Renders the AST node hierarchy into a Unicode box-drawing tree."""
        connector = "└── " if is_last else "├── "
        node_label = ASTVisualizer._format_node_label(node)
        lines = [f"{prefix}{connector}{node_label}"]

        child_prefix = prefix + ("    " if is_last else "│   ")
        children = ASTVisualizer._get_children(node)

        for i, child in enumerate(children):
            last_child = (i == len(children) - 1)
            lines.append(ASTVisualizer.render_ascii_tree(child, child_prefix, last_child))

        return "\n".join(lines)

    @staticmethod
    def render_mermaid(node: ASTNode) -> str:
        """Generates Mermaid flowchart TD code representing the AST topology."""
        lines = ["flowchart TD"]
        counter = {"id": 0}

        def build_mermaid_node(n: ASTNode, parent_id: str = None):
            counter["id"] += 1
            cur_id = f"node_{counter['id']}"
            label = ASTVisualizer._format_node_label(n).replace('"', "'")
            lines.append(f'    {cur_id}["{label}"]')
            if parent_id:
                lines.append(f"    {parent_id} --> {cur_id}")

            for child in ASTVisualizer._get_children(n):
                build_mermaid_node(child, cur_id)

        build_mermaid_node(node)
        return "\n".join(lines)

    @staticmethod
    def render_json(node: ASTNode, indent: int = 2) -> str:
        """Serializes the AST node hierarchy into pretty-printed JSON."""
        return json.dumps(node.to_dict(), indent=indent, ensure_ascii=False)

    @staticmethod
    def _format_node_label(node: ASTNode) -> str:
        name = node.__class__.__name__
        if isinstance(node, CommandNode):
            return f"CommandNode(target={node.target!r})"
        if isinstance(node, AssignmentNode):
            return f"AssignmentNode(var={node.var_name!r}, val={node.raw_value!r})"
        if isinstance(node, VarExpandNode):
            attrs = [f"name={node.name!r}"]
            if node.slice_start is not None:
                attrs.append(f"slice=[{node.slice_start}:{node.slice_len}]")
            if node.sub_search is not None:
                attrs.append(f"sub=[{node.sub_search}->{node.sub_replace}]")
            return f"VarExpandNode({', '.join(attrs)})"
        if isinstance(node, LiteralNode):
            return f"LiteralNode(val={node.value!r})"
        if isinstance(node, ChainNode):
            return f"ChainNode(op={node.operator!r})"
        if isinstance(node, PipeNode):
            return "PipeNode(|)"
        if isinstance(node, BlockNode):
            return "BlockNode()"
        if isinstance(node, ScriptNode):
            return f"ScriptNode(count={len(node.statements)})"
        if isinstance(node, CommentNode):
            preview = (node.text[:28] + '...') if len(node.text) > 30 else node.text
            return f"CommentNode({preview!r})"
        return name

    @staticmethod
    def _get_children(node: ASTNode) -> List[ASTNode]:
        if isinstance(node, ScriptNode):
            return node.statements
        if isinstance(node, BlockNode):
            return node.statements
        if isinstance(node, ChainNode):
            return [node.left, node.right]
        if isinstance(node, PipeNode):
            return [node.left, node.right]
        if isinstance(node, CommandNode):
            return node.arguments
        if isinstance(node, AssignmentNode):
            return node.value_nodes
        return []
