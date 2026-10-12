"""
High-Precision Substring Slicing Constant Folding Optimization Pass.
Folds %VAR:~start,length% and !VAR:~start,length! AST nodes and coalesces
contiguous slices into consolidated LiteralNode representations.
"""

import re
from typing import Dict, List, Optional
from ..ast_nodes import (
    ASTNode, LiteralNode, VarExpandNode, CommandNode,
    AssignmentNode, BlockNode, ChainNode, PipeNode,
    RedirectNode, ScriptNode, IfNode, ForNode
)
from .base import TransformPass


class SlicingFolderPass(TransformPass):
    """
    Sub-expression AST Constant Folding pass specializing in cmd.exe Substring Slicing.
    Handles:
      - Positive and negative start offsets (with negative clamp to 0 if -start >= len).
      - Positive and negative length counts (negative length leaves off abs(length) from end).
      - Omitted start (%VAR:~,len% -> start=0), omitted length (%VAR:~start,% -> length=0 -> empty string),
        and omitted both (%VAR:~,% -> empty string).
      - Explicit plus signs (+2, +3).
      - Whitespace around slice delimiters (%VAR:~ 2 , 3 %).
      - Nested variable resolution in slice parameters (%VAR:~%OFF%,%LEN%%).
      - Contiguous slice fusion/coalescing across adjacent nodes.
      - Full AST rewriting across CommandNode, AssignmentNode, BlockNode, ChainNode, PipeNode, RedirectNode.
    """
    def __init__(self, env: Optional[Dict[str, str]] = None, fold_all_vars: bool = False):
        super().__init__(name="SlicingFolderPass", env=env)
        self.fold_all_vars = fold_all_vars

    def _calculate_slice(self, val: str, start: int, length: Optional[int]) -> str:
        """
        Computes substring slice according to Windows cmd.exe semantics:
          - start >= 0: 0-based offset from start of string.
          - start < 0: offset from end of string; clamped to 0 if -start >= len(val).
          - length is None: slice to end of string.
          - length == 0: empty string.
          - length > 0: count of characters to extract.
          - length < 0: leave off abs(length) characters from the end of string.
        """
        n = len(val)
        if start < 0:
            offset = 0 if -start >= n else max(0, n + start)
        else:
            offset = start

        if offset >= n:
            return ""

        if length is None:
            return val[offset:]

        if length == 0:
            return ""

        if length < 0:
            end_offset = n + length
        else:
            end_offset = offset + length

        if end_offset <= offset:
            return ""

        if end_offset > n:
            end_offset = n

        return val[offset:end_offset]

    def _resolve_env_str(self, text: str) -> str:
        """Resolves nested %VAR% and !VAR! references against current environment."""
        if not text:
            return ""

        def _repl_pct(m):
            k = m.group(1).lower()
            return self.env.get(k, m.group(0))

        def _repl_exc(m):
            k = m.group(1).lower()
            return self.env.get(k, m.group(0))

        prev = None
        res = text
        for _ in range(5):
            if res == prev:
                break
            prev = res
            res = re.sub(r'%([a-zA-Z0-9_\-\.\:\$]+)%', _repl_pct, res)
            res = re.sub(r'!([a-zA-Z0-9_\-\.\:\$]+)!', _repl_exc, res)
        return res

    def _try_parse_int(self, s: Optional[str]) -> Optional[int]:
        """Parses an integer slice parameter handling whitespace and explicit signs."""
        if s is None:
            return None
        s_clean = re.sub(r'\s+', '', s)
        if not s_clean:
            return 0
        if s_clean.startswith('+'):
            s_clean = s_clean[1:]
        try:
            return int(s_clean)
        except ValueError:
            return None

    def _resolve_nested_params(self, node: VarExpandNode) -> None:
        """Resolves nested variable expressions in slice start and length parameters."""
        if node.slice_start_expr is not None:
            resolved_s = self._resolve_env_str(node.slice_start_expr)
            val = self._try_parse_int(resolved_s)
            if val is not None:
                node.slice_start = val
                node.slice_start_expr = None
                self.modified = True

        if node.slice_len_expr is not None:
            resolved_l = self._resolve_env_str(node.slice_len_expr)
            val = self._try_parse_int(resolved_l)
            if val is not None:
                node.slice_len = val
                node.slice_len_expr = None
                self.modified = True

    def _fold_slice_in_str(self, text: str) -> str:
        """Folds any inline slice patterns (%VAR:~s,l% or !VAR:~s,l!) in a raw string."""
        if not text or ':~' not in text:
            return text

        def _repl(match):
            delim = match.group(1)
            inner = match.group(2)
            from ..parser import CmdASTParser
            var_node = CmdASTParser.parse_var_content(inner, is_delayed=(delim == '!'))
            folded = self.visit_VarExpandNode(var_node)
            if isinstance(folded, LiteralNode):
                return folded.value
            return match.group(0)

        pattern = r'([%!])([a-zA-Z0-9_\-\.\:\$]+:~[^%!\r\n]*)\1'
        return re.sub(pattern, _repl, text)

    def visit_VarExpandNode(self, node: VarExpandNode) -> ASTNode:
        """Folds variable expansion node if slice is computable from environment."""
        # Resolve nested percent/exclam variables in variable name if present
        if ('%' in node.name or '!' in node.name):
            resolved_name = self._resolve_env_str(node.name)
            if resolved_name != node.name:
                node.name = resolved_name
                self.modified = True

        is_slice = (
            node.slice_start is not None or
            node.slice_len is not None or
            node.slice_start_expr is not None or
            node.slice_len_expr is not None
        )

        if is_slice:
            self._resolve_nested_params(node)
            # If start and len are concrete and fully resolved
            if node.slice_start_expr is None and node.slice_len_expr is None:
                start = node.slice_start if node.slice_start is not None else 0
                vkey = node.name.lower()
                if vkey in self.env:
                    raw_val = self.env[vkey]
                    sliced = self._calculate_slice(raw_val, start, node.slice_len)
                    self.modified = True
                    return LiteralNode(
                        value=sliced,
                        is_quoted=False,
                        is_folded_slice=True,
                        span=node.span
                    )

        # Plain variable folding if enabled
        if self.fold_all_vars and not is_slice and node.sub_search is None:
            vkey = node.name.lower()
            if vkey in self.env:
                self.modified = True
                return LiteralNode(
                    value=self.env[vkey],
                    is_quoted=False,
                    span=node.span
                )

        return node

    def _coalesce_nodes(
        self,
        nodes: List[ASTNode],
        is_target: bool = False,
        is_value: bool = False
    ) -> List[ASTNode]:
        """
        Transforms a sequence of AST nodes and coalesces contiguous LiteralNode items.
        Fuses adjacent folded slice nodes into single consolidated LiteralNode instances.
        """
        if not nodes:
            return []

        visited: List[ASTNode] = []
        for n in nodes:
            trans = self.visit(n)
            if trans is not None:
                visited.append(trans)

        coalesced: List[ASTNode] = []
        for curr in visited:
            if not coalesced:
                coalesced.append(curr)
                continue

            prev = coalesced[-1]
            if isinstance(prev, LiteralNode) and isinstance(curr, LiteralNode):
                # Check whether these two adjacent literals should fuse
                should_fuse = False
                if is_target or is_value:
                    # Target and assignment values form single contiguous tokens
                    should_fuse = True
                elif prev.span != (0, 0) and curr.span != (0, 0):
                    # Contiguous in source tokens without intervening whitespace
                    should_fuse = (prev.span[1] == curr.span[0])
                elif prev.span == (0, 0) and curr.span == (0, 0):
                    # AST-constructed adjacent folded slices
                    should_fuse = (getattr(prev, 'is_folded_slice', False) and getattr(curr, 'is_folded_slice', False))

                if should_fuse:
                    merged_span = (prev.span[0], curr.span[1]) if prev.span != (0, 0) and curr.span != (0, 0) else (0, 0)
                    is_folded = getattr(prev, 'is_folded_slice', False) or getattr(curr, 'is_folded_slice', False)
                    fused = LiteralNode(
                        value=prev.value + curr.value,
                        is_quoted=(prev.is_quoted and curr.is_quoted),
                        is_folded_slice=is_folded,
                        span=merged_span
                    )
                    coalesced[-1] = fused
                    self.modified = True
                    continue

            coalesced.append(curr)

        return coalesced

    def visit_CommandNode(self, node: CommandNode) -> CommandNode:
        new_targets = self._coalesce_nodes(node.target_nodes, is_target=True) if node.target_nodes else []
        new_args = self._coalesce_nodes(node.arguments, is_target=False)

        new_target_str = node.target
        if new_targets:
            new_target_str = "".join(
                n.value if isinstance(n, LiteralNode) else self.to_source(n)
                for n in new_targets
            )
        else:
            folded_target = self._fold_slice_in_str(node.target)
            if folded_target != node.target:
                new_target_str = folded_target
                self.modified = True

        changed = (new_targets != node.target_nodes) or (new_args != node.arguments) or (new_target_str != node.target)
        if changed:
            self.modified = True
            return CommandNode(
                target=new_target_str,
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
            folded_raw = self._fold_slice_in_str(node.raw_value)
            if folded_raw != node.raw_value:
                new_raw = folded_raw
                self.modified = True

        var_key = node.var_name.lower()
        self.env[var_key] = new_raw

        changed = (new_vals != node.value_nodes) or (new_raw != node.raw_value)
        if changed:
            self.modified = True
            return AssignmentNode(
                var_name=node.var_name,
                value_nodes=new_vals,
                raw_value=new_raw,
                is_arithmetic=node.is_arithmetic,
                span=node.span
            )
        return node

    def visit_RedirectNode(self, node: RedirectNode) -> RedirectNode:
        new_cmd = self.visit(node.command)
        new_dest = self._fold_slice_in_str(node.destination)
        if new_cmd is not node.command or new_dest != node.destination:
            self.modified = True
            return RedirectNode(
                command=new_cmd,
                stream=node.stream,
                destination=new_dest,
                span=node.span
            )
        return node

    def visit_BlockNode(self, node: BlockNode) -> BlockNode:
        new_stmts = [self.visit(s) for s in node.statements if s is not None]
        if new_stmts != node.statements:
            self.modified = True
            return BlockNode(statements=new_stmts, span=node.span)
        return node

    def visit_ChainNode(self, node: ChainNode) -> ChainNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left is not node.left or new_right is not node.right:
            self.modified = True
            return ChainNode(
                left=new_left,
                operator=node.operator,
                right=new_right,
                span=node.span
            )
        return node

    def visit_PipeNode(self, node: PipeNode) -> PipeNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left is not node.left or new_right is not node.right:
            self.modified = True
            return PipeNode(left=new_left, right=new_right, span=node.span)
        return node

    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        new_stmts = [self.visit(s) for s in node.statements if s is not None]
        if new_stmts != node.statements:
            self.modified = True
            return ScriptNode(statements=new_stmts, span=node.span)
        return node
