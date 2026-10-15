"""
Colored AST Tree Renderer for terminal inspection.
Produces colorized Unicode box-drawing AST hierarchies with sequential node IDs,
attribute highlights, and depth-bounded navigation.
"""

from typing import List, Dict, Optional, Tuple, Any
from ..ast_nodes import (
    ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, CommentNode,
    ParamExpandNode, ForNode, LabelNode, GotoNode, CallNode, ExitNode,
    RedirectNode, IfNode
)
from .models import ANSI, ColorMode, should_color


class ColoredASTTreeRenderer:
    """
    Renders AST hierarchies with ANSI styling and indexable node identifiers.
    """

    def __init__(self, color_mode: ColorMode = ColorMode.AUTO):
        self.color_mode = color_mode
        self._node_registry: Dict[int, ASTNode] = {}

    def render(
        self,
        node: ASTNode,
        color: Optional[bool] = None,
        show_ids: bool = True,
        max_depth: Optional[int] = None,
    ) -> str:
        """Renders the entire AST hierarchy into a formatted string."""
        use_color = should_color(self.color_mode) if color is None else color
        self._node_registry.clear()
        counter = {"id": 0}

        lines = self._build_tree_lines(
            node,
            prefix="",
            is_last=True,
            depth=0,
            max_depth=max_depth,
            counter=counter,
            color=use_color,
            show_ids=show_ids,
        )
        return "\n".join(lines)

    def get_node_by_id(self, node_id: int) -> Optional[ASTNode]:
        """Retrieves an AST node previously registered during rendering."""
        return self._node_registry.get(node_id)

    def format_node_details(self, node: ASTNode, color: Optional[bool] = None) -> str:
        """Formats detailed attributes of an individual AST node for inspection."""
        use_color = should_color(self.color_mode) if color is None else color
        cls_name = node.__class__.__name__

        header = f"=== Node Details: {cls_name} ==="
        lines = [f"{ANSI.BOLD}{ANSI.CYAN}{header}{ANSI.RESET}" if use_color else header]

        fields: List[Tuple[str, str]] = []
        if isinstance(node, CommandNode):
            fields.append(("target", repr(node.target)))
            fields.append(("arg_count", str(len(node.arguments))))
            fields.append(("target_nodes", str(len(node.target_nodes))))
        elif isinstance(node, AssignmentNode):
            fields.append(("var_name", repr(node.var_name)))
            fields.append(("raw_value", repr(node.raw_value)))
            fields.append(("is_arithmetic", str(node.is_arithmetic)))
            fields.append(("value_nodes", str(len(node.value_nodes))))
        elif isinstance(node, VarExpandNode):
            fields.append(("name", repr(node.name)))
            fields.append(("is_delayed", str(node.is_delayed)))
            if node.slice_start is not None or node.slice_start_expr:
                fields.append(("slice_start", str(node.slice_start if node.slice_start is not None else node.slice_start_expr)))
            if node.slice_len is not None or node.slice_len_expr:
                fields.append(("slice_len", str(node.slice_len if node.slice_len is not None else node.slice_len_expr)))
            if node.sub_search is not None:
                fields.append(("sub_search", repr(node.sub_search)))
                fields.append(("sub_replace", repr(node.sub_replace)))
        elif isinstance(node, LiteralNode):
            fields.append(("value", repr(node.value)))
            fields.append(("is_quoted", str(node.is_quoted)))
        elif isinstance(node, ForNode):
            fields.append(("iterator", repr(node.iterator)))
            fields.append(("flags", repr(node.flags)))
            fields.append(("options", repr(node.options)))
            fields.append(("in_clause", repr(node.in_clause)))
        elif isinstance(node, IfNode):
            fields.append(("condition", repr(node.condition)))
            fields.append(("has_else", str(node.else_block is not None)))
        elif isinstance(node, GotoNode):
            fields.append(("target", repr(node.target)))
            fields.append(("is_dynamic", str(node.is_dynamic)))
            fields.append(("is_eof", str(node.is_eof)))
        elif isinstance(node, CallNode):
            fields.append(("target", repr(node.target)))
            fields.append(("is_subroutine", str(node.is_subroutine)))
            fields.append(("is_dynamic", str(node.is_dynamic)))
            fields.append(("arguments", str(len(node.arguments))))
        elif isinstance(node, RedirectNode):
            fields.append(("stream", repr(node.stream)))
            fields.append(("destination", repr(node.destination)))
            fields.append(("source_fd", str(node.source_fd)))
        elif isinstance(node, CommentNode):
            fields.append(("text", repr(node.text)))
        elif isinstance(node, ExitNode):
            fields.append(("is_batch_return", str(node.is_batch_return)))
            fields.append(("exit_code", repr(node.exit_code)))

        if hasattr(node, "span") and node.span:
            fields.append(("span", f"[{node.span[0]}:{node.span[1]}]"))

        for key, val in fields:
            if use_color:
                lines.append(f"  {ANSI.YELLOW}{key:<16}{ANSI.RESET}: {ANSI.GREEN}{val}{ANSI.RESET}")
            else:
                lines.append(f"  {key:<16}: {val}")

        return "\n".join(lines)

    def _build_tree_lines(
        self,
        node: ASTNode,
        prefix: str,
        is_last: bool,
        depth: int,
        max_depth: Optional[int],
        counter: Dict[str, int],
        color: bool,
        show_ids: bool,
    ) -> List[str]:
        counter["id"] += 1
        node_id = counter["id"]
        self._node_registry[node_id] = node

        connector = "└── " if is_last else "├── "
        label = self._format_node(node, node_id, color, show_ids)

        tree_prefix = f"{ANSI.DIM}{prefix}{connector}{ANSI.RESET}" if color else f"{prefix}{connector}"
        lines = [f"{tree_prefix}{label}"]

        if max_depth is not None and depth >= max_depth:
            child_prefix = prefix + ("    " if is_last else "│   ")
            ellipsis_str = f"{ANSI.GRAY}... (children truncated){ANSI.RESET}" if color else "... (children truncated)"
            lines.append(f"{child_prefix}└── {ellipsis_str}")
            return lines

        child_prefix = prefix + ("    " if is_last else "│   ")
        children = self._get_children(node)

        for i, child in enumerate(children):
            last_child = (i == len(children) - 1)
            child_lines = self._build_tree_lines(
                child,
                child_prefix,
                last_child,
                depth + 1,
                max_depth,
                counter,
                color,
                show_ids,
            )
            lines.extend(child_lines)

        return lines

    def _format_node(self, node: ASTNode, node_id: int, color: bool, show_ids: bool) -> str:
        id_badge = f"[#{node_id}] " if show_ids else ""
        cls_name = node.__class__.__name__

        if color:
            id_str = f"{ANSI.DIM}{ANSI.GRAY}{id_badge}{ANSI.RESET}" if show_ids else ""
            cls_str = f"{ANSI.BOLD}{ANSI.CYAN}{cls_name}{ANSI.RESET}"
            content = self._format_summary(node, color=True)
            return f"{id_str}{cls_str}({content})"
        else:
            content = self._format_summary(node, color=False)
            return f"{id_badge}{cls_name}({content})"

    def _format_summary(self, node: ASTNode, color: bool) -> str:
        def c_attr(k: str, v: str) -> str:
            if color:
                return f"{ANSI.YELLOW}{k}{ANSI.RESET}={ANSI.GREEN}{v}{ANSI.RESET}"
            return f"{k}={v}"

        if isinstance(node, CommandNode):
            return c_attr("target", repr(node.target))
        if isinstance(node, AssignmentNode):
            val_prev = (node.raw_value[:24] + "…") if len(node.raw_value) > 26 else node.raw_value
            return f"{c_attr('var', repr(node.var_name))}, {c_attr('val', repr(val_prev))}"
        if isinstance(node, VarExpandNode):
            parts = [c_attr("name", repr(node.name))]
            if node.is_delayed:
                parts.append("delayed=True")
            if node.slice_start is not None or node.slice_start_expr:
                s = node.slice_start if node.slice_start is not None else node.slice_start_expr
                l = node.slice_len if node.slice_len is not None else (node.slice_len_expr or "")
                parts.append(c_attr("slice", f"[{s}:{l}]"))
            if node.sub_search is not None:
                parts.append(c_attr("sub", f"{node.sub_search}->{node.sub_replace}"))
            return ", ".join(parts)
        if isinstance(node, LiteralNode):
            val_prev = (node.value[:28] + "…") if len(node.value) > 30 else node.value
            return c_attr("val", repr(val_prev))
        if isinstance(node, ChainNode):
            return c_attr("op", repr(node.operator))
        if isinstance(node, PipeNode):
            return c_attr("op", "'|'")
        if isinstance(node, ParamExpandNode):
            return f"{c_attr('name', repr(node.name))}, {c_attr('mod', repr(node.modifiers))}"
        if isinstance(node, ForNode):
            return f"{c_attr('iter', repr(node.iterator))}, {c_attr('in', repr(node.in_clause))}"
        if isinstance(node, LabelNode):
            return c_attr("name", f":{node.name}")
        if isinstance(node, GotoNode):
            return f"{c_attr('target', repr(node.target))}, dynamic={node.is_dynamic}"
        if isinstance(node, CallNode):
            return f"{c_attr('target', repr(node.target))}, sub={node.is_subroutine}"
        if isinstance(node, ExitNode):
            return f"batch_return={node.is_batch_return}, {c_attr('code', repr(node.exit_code))}"
        if isinstance(node, RedirectNode):
            return f"{c_attr('op', repr(node.stream))}, {c_attr('dst', repr(node.destination))}"
        if isinstance(node, CommentNode):
            prev = (node.text[:20] + "…") if len(node.text) > 22 else node.text
            return c_attr("text", repr(prev))
        if isinstance(node, ScriptNode):
            return f"statements={len(node.statements)}"
        if isinstance(node, BlockNode):
            return f"statements={len(node.statements)}"
        return ""

    @staticmethod
    def _get_children(node: ASTNode) -> List[ASTNode]:
        if isinstance(node, (ScriptNode, BlockNode)):
            return node.statements
        if isinstance(node, (ChainNode, PipeNode)):
            return [node.left, node.right]
        if isinstance(node, CommandNode):
            targets = [t for t in node.target_nodes if isinstance(t, (VarExpandNode, ParamExpandNode))]
            return targets + node.arguments
        if isinstance(node, AssignmentNode):
            return node.value_nodes
        if isinstance(node, ForNode):
            return [node.body] if node.body else []
        if isinstance(node, IfNode):
            kids = [node.then_block]
            if node.else_block:
                kids.append(node.else_block)
            return kids
        if isinstance(node, (GotoNode, CallNode)):
            return node.target_nodes + getattr(node, "arguments", [])
        if isinstance(node, RedirectNode):
            return [node.command]
        return []
