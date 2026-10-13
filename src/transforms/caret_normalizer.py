"""
Caret Normalization AST Transform Pass for cmd-ast-deobfuscator.
Normalizes cmd.exe caret (^) escape sequences across AST hierarchies, resolving single-pass
and nested/multi-level caret obfuscation while strictly preserving quotes and escapes.
"""

from typing import Dict, List, Optional, Tuple
from ..ast_nodes import (
    ASTNode, LiteralNode, CommandNode, AssignmentNode, VarExpandNode,
    RedirectNode, IfNode, ForNode, BlockNode, ChainNode, PipeNode, ScriptNode
)
from .base import TransformPass


def normalize_carets(
    text: str,
    in_quote: bool = False,
    multi_level: bool = True,
    max_passes: int = 10,
    collapse_redundant: bool = False,
    strip_trailing: bool = True,
    preserve_escaped_carets: bool = True
) -> str:
    """
    Normalizes cmd.exe caret escape sequences in a string with quotation boundary awareness.

    Features:
      - Single-level caret unmasking (^c -> c outside quotes).
      - Quoted string preservation ("hello^world" remains "hello^world").
      - Escaped double quote handling (^" emits a literal " outside quotes without toggling quote state).
      - Escaped caret resolution (^^ -> ^).
      - Multi-level nested caret reduction (c^^^a -> ca, ^^^^c -> c).
      - Redundant caret collapsing options.
      - Trailing unescaped caret handling.
    """
    if not text:
        return ""

    def _single_pass(s: str, start_quote: bool, strip_trailing_flag: bool) -> Tuple[str, bool, bool]:
        res: List[str] = []
        i = 0
        n = len(s)
        curr_quote = start_quote
        has_changed = False

        while i < n:
            ch = s[i]

            # Escaped quote outside quotation marks: ^"
            if not curr_quote and ch == '^' and i + 1 < n and s[i + 1] == '"':
                res.append('"')
                i += 2
                has_changed = True
                continue

            # Quotation boundary transition
            if ch == '"':
                curr_quote = not curr_quote
                res.append(ch)
                i += 1
                continue

            if ch == '^':
                if curr_quote:
                    # Inside quotes: carets are literal
                    res.append(ch)
                    i += 1
                else:
                    # Outside quotes: caret escapes following character
                    if i + 1 < n:
                        next_ch = s[i + 1]
                        res.append(next_ch)
                        i += 2
                        has_changed = True
                    else:
                        # Trailing caret at end of string
                        if strip_trailing_flag:
                            has_changed = True
                        else:
                            res.append(ch)
                        i += 1
            else:
                res.append(ch)
                i += 1

        return "".join(res), curr_quote, has_changed

    curr = text
    curr_quote = in_quote

    # First pass unmasks caret escapes
    curr, curr_quote, changed = _single_pass(curr, curr_quote, strip_trailing_flag=strip_trailing)
    if not changed or not multi_level:
        if collapse_redundant:
            curr = _collapse_redundant_carets(curr)
        return curr

    # Multi-level iterative reduction for nested escapes (e.g. ^^^c -> c, ^^^^^^^c -> c)
    pass_count = 1
    while pass_count < max_passes:
        # Check if any unquoted caret escape is present
        if not _has_unquoted_carets(curr, curr_quote):
            break

        prev = curr
        # In subsequent passes, do not strip trailing single carets to preserve literal carets
        curr, curr_quote, changed = _single_pass(curr, curr_quote, strip_trailing_flag=False)
        pass_count += 1

        if not changed or curr == prev:
            break

    if collapse_redundant:
        curr = _collapse_redundant_carets(curr)

    return curr


def _has_unquoted_carets(s: str, in_quote: bool = False) -> bool:
    """Checks whether the string contains carets outside double quotes that can escape characters."""
    curr_quote = in_quote
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == '"':
            curr_quote = not curr_quote
        elif ch == '^' and not curr_quote:
            # Check if followed by character that can be unmasked
            if i + 1 < n:
                return True
        i += 1
    return False


def _collapse_redundant_carets(s: str) -> str:
    """Collapses runs of multiple consecutive unquoted carets into a single caret."""
    res: List[str] = []
    in_quote = False
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == '"':
            in_quote = not in_quote
            res.append(ch)
            i += 1
        elif ch == '^' and not in_quote:
            # Consume all consecutive carets
            while i < n and s[i] == '^':
                i += 1
            res.append('^')
        else:
            res.append(ch)
            i += 1
    return "".join(res)


class CaretNormalizerPass(TransformPass):
    """
    Caret Normalization AST Transform Pass.
    Traverses the AST and resolves single and nested caret escape sequences,
    merging adjacent literal fragments while strictly preserving quotation boundaries.
    """
    def __init__(
        self,
        env: Optional[Dict[str, str]] = None,
        multi_level: bool = True,
        max_passes: int = 10,
        collapse_redundant: bool = False,
        strip_trailing: bool = True
    ):
        super().__init__(name="CaretNormalizerPass", env=env)
        self.multi_level = multi_level
        self.max_passes = max_passes
        self.collapse_redundant = collapse_redundant
        self.strip_trailing = strip_trailing

    def normalize_text(self, text: str, in_quote: bool = False) -> str:
        """Helper to normalize carets in text strings according to pass settings."""
        return normalize_carets(
            text=text,
            in_quote=in_quote,
            multi_level=self.multi_level,
            max_passes=self.max_passes,
            collapse_redundant=self.collapse_redundant,
            strip_trailing=self.strip_trailing
        )

    def _coalesce_nodes(
        self,
        nodes: List[ASTNode],
        is_target: bool = False,
        is_value: bool = False
    ) -> List[ASTNode]:
        """Visits child nodes and coalesces adjacent unquoted literal fragments."""
        result: List[ASTNode] = []
        for n in nodes:
            cleaned_node = self.visit(n)
            result.append(cleaned_node)

        final_nodes: List[ASTNode] = []
        for curr in result:
            if not final_nodes:
                final_nodes.append(curr)
                continue
            prev = final_nodes[-1]
            if isinstance(prev, LiteralNode) and isinstance(curr, LiteralNode):
                # Fuse unquoted literal nodes
                if not prev.is_quoted and not curr.is_quoted:
                    should_fuse = False
                    if is_target or is_value:
                        should_fuse = True
                    elif prev.span != (0, 0) and curr.span != (0, 0):
                        should_fuse = (prev.span[1] == curr.span[0])
                    elif prev.span == (0, 0) and curr.span == (0, 0):
                        should_fuse = True

                    if should_fuse:
                        merged_val = prev.value + curr.value
                        merged_span = (prev.span[0], curr.span[1]) if prev.span != (0, 0) and curr.span != (0, 0) else (0, 0)
                        fused = LiteralNode(
                            value=merged_val,
                            is_quoted=False,
                            is_folded_slice=getattr(prev, 'is_folded_slice', False) or getattr(curr, 'is_folded_slice', False),
                            span=merged_span
                        )
                        final_nodes[-1] = fused
                        self.modified = True
                        continue
            final_nodes.append(curr)
        return final_nodes

    def visit_LiteralNode(self, node: LiteralNode) -> LiteralNode:
        if not node.is_quoted:
            cleaned = self.normalize_text(node.value, in_quote=False)
            if cleaned != node.value:
                self.modified = True
                return LiteralNode(
                    value=cleaned,
                    is_quoted=False,
                    is_folded_slice=node.is_folded_slice,
                    span=node.span
                )
        return node

    def visit_CommandNode(self, node: CommandNode) -> CommandNode:
        new_targets = self._coalesce_nodes(node.target_nodes, is_target=True) if node.target_nodes else []
        new_args = self._coalesce_nodes(node.arguments, is_target=False)

        new_target = node.target
        if new_targets:
            new_target = "".join(
                n.value if isinstance(n, LiteralNode) else self.to_source(n)
                for n in new_targets
            )
        else:
            new_target = self.normalize_text(node.target)
        if new_target.lower() == 'set' and new_args:
            arg_text = " ".join(n.value if isinstance(n, LiteralNode) else self.to_source(n) for n in new_args).strip()
            if arg_text.startswith('"') and arg_text.endswith('"'):
                arg_text = arg_text[1:-1]
            if '=' in arg_text:
                vname, vval = arg_text.split('=', 1)
                vname = vname.strip()
                self.env[vname.lower()] = vval
                self.modified = True
                return AssignmentNode(
                    var_name=vname,
                    raw_value=vval,
                    value_nodes=[LiteralNode(value=vval, is_quoted=False)],
                    span=node.span
                )

        changed = (new_targets != node.target_nodes) or (new_args != node.arguments) or (new_target != node.target)
        if changed:
            self.modified = True
            return CommandNode(
                target=new_target,
                target_nodes=new_targets,
                arguments=new_args,
                span=node.span
            )
        return node


    def visit_AssignmentNode(self, node: AssignmentNode) -> AssignmentNode:
        new_vals = self._coalesce_nodes(node.value_nodes, is_value=True) if node.value_nodes else []
        new_raw = node.raw_value
        if new_vals:
            new_raw = "".join(
                n.value if isinstance(n, LiteralNode) else self.to_source(n)
                for n in new_vals
            )
        else:
            new_raw = self.normalize_text(node.raw_value)

        cleaned_name = self.normalize_text(node.var_name)
        var_key = cleaned_name.lower()
        self.env[var_key] = new_raw

        changed = (new_vals != node.value_nodes) or (new_raw != node.raw_value) or (cleaned_name != node.var_name)
        if changed:
            self.modified = True
            return AssignmentNode(
                var_name=cleaned_name,
                value_nodes=new_vals,
                raw_value=new_raw,
                is_arithmetic=node.is_arithmetic,
                span=node.span
            )
        return node

    def visit_RedirectNode(self, node: RedirectNode) -> RedirectNode:
        new_cmd = self.visit(node.command)
        new_dest = self.normalize_text(node.destination)
        if new_cmd is not node.command or new_dest != node.destination:
            self.modified = True
            return RedirectNode(
                command=new_cmd,
                stream=node.stream,
                destination=new_dest,
                span=node.span
            )
        return node

    def visit_VarExpandNode(self, node: VarExpandNode) -> VarExpandNode:
        changed = False
        new_name = node.name
        if '^' in new_name and not node.is_delayed:
            new_name = self.normalize_text(node.name)
            if new_name != node.name:
                changed = True

        new_search = node.sub_search
        if node.sub_search is not None and '^' in node.sub_search:
            new_search = self.normalize_text(node.sub_search)
            if new_search != node.sub_search:
                changed = True

        new_replace = node.sub_replace
        if node.sub_replace is not None and '^' in node.sub_replace:
            new_replace = self.normalize_text(node.sub_replace)
            if new_replace != node.sub_replace:
                changed = True

        new_start_expr = node.slice_start_expr
        if node.slice_start_expr is not None and '^' in node.slice_start_expr:
            new_start_expr = self.normalize_text(node.slice_start_expr)
            if new_start_expr != node.slice_start_expr:
                changed = True

        new_len_expr = node.slice_len_expr
        if node.slice_len_expr is not None and '^' in node.slice_len_expr:
            new_len_expr = self.normalize_text(node.slice_len_expr)
            if new_len_expr != node.slice_len_expr:
                changed = True

        if changed:
            self.modified = True
            return VarExpandNode(
                name=new_name,
                is_delayed=node.is_delayed,
                slice_start=node.slice_start,
                slice_len=node.slice_len,
                sub_search=new_search,
                sub_replace=new_replace,
                slice_start_expr=new_start_expr,
                slice_len_expr=new_len_expr,
                span=node.span
            )
        return node

    def visit_IfNode(self, node: IfNode) -> IfNode:
        new_cond = self.normalize_text(node.condition)
        new_then = self.visit(node.then_block)
        new_else = self.visit(node.else_block) if node.else_block else None
        if new_cond != node.condition or new_then is not node.then_block or new_else is not node.else_block:
            self.modified = True
            return IfNode(
                condition=new_cond,
                then_block=new_then,
                else_block=new_else,
                span=node.span
            )
        return node

    def visit_ForNode(self, node: ForNode) -> ForNode:
        new_in = self.normalize_text(node.in_clause)
        new_body = self.visit(node.body)
        if new_in != node.in_clause or new_body is not node.body:
            self.modified = True
            return ForNode(
                iterator=node.iterator,
                in_clause=new_in,
                body=new_body,
                span=node.span
            )
        return node
