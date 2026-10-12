"""
General Constant Folding Optimization Pass for cmd-ast-deobfuscator.
Combines substring slicing folding, caret escape removal, empty double quote normalization,
string substitution resolution, and literal coalescing.
"""

import re
from typing import Dict, List, Optional
from ..ast_nodes import (
    ASTNode, LiteralNode, VarExpandNode, CommandNode,
    AssignmentNode, BlockNode, ChainNode, PipeNode,
    RedirectNode, ScriptNode, IfNode, ForNode
)
from .base import TransformPass
from .slicing_folder import SlicingFolderPass


class ConstantFolderPass(TransformPass):
    """
    Comprehensive Constant Folding Pass combining:
      1. Substring Slicing Folding (%VAR:~s,l%, !VAR:~s,l!).
      2. Caret Unmasking (^c^a^l^c -> calc outside double quotes).
      3. Empty Double Quote Collapse (w""h""o -> who outside double quotes).
      4. String Substitution Resolution (%VAR:old=new%, !VAR:*old=new!).
      5. Constant Environment Variable Expansion (%VAR%, !VAR!).
      6. Adjacent Literal Node Coalescing.
    """
    def __init__(self, env: Optional[Dict[str, str]] = None):
        super().__init__(name="ConstantFolderPass", env=env)
        self.slicing_folder = SlicingFolderPass(env=self.env, fold_all_vars=True)

    def _strip_lexical_artifacts(self, text: str) -> str:
        """Removes carets and collapses empty double quotes outside quotes."""
        if not text:
            return ""

        # Collapse empty quotes ""
        text = text.replace('""', '')

        # Strip unescaped carets
        res = []
        i = 0
        n = len(text)
        while i < n:
            if text[i] == '^':
                if i + 1 < n:
                    res.append(text[i + 1])
                    i += 2
                else:
                    i += 1
            else:
                res.append(text[i])
                i += 1
        return "".join(res)

    def visit_LiteralNode(self, node: LiteralNode) -> ASTNode:
        if not node.is_quoted:
            cleaned = self._strip_lexical_artifacts(node.value)
            if cleaned != node.value:
                self.modified = True
                return LiteralNode(
                    value=cleaned,
                    is_quoted=False,
                    is_folded_slice=node.is_folded_slice,
                    span=node.span
                )
        return node

    def visit_VarExpandNode(self, node: VarExpandNode) -> ASTNode:
        # First, delegate to slicing folder pass
        self.slicing_folder.env = self.env
        folded = self.slicing_folder.visit_VarExpandNode(node)
        if folded is not node:
            self.modified = True
            if isinstance(folded, LiteralNode):
                return self.visit_LiteralNode(folded)
            return folded

        # If substitution is present: %VAR:search=replace%
        if node.sub_search is not None:
            vkey = node.name.lower()
            if vkey in self.env:
                raw_val = self.env[vkey]
                sub_search = self._strip_lexical_artifacts(node.sub_search)
                sub_replace = self._strip_lexical_artifacts(node.sub_replace or '')

                if sub_search and sub_search != '*':
                    if sub_search.startswith('*'):
                        target_str = sub_search[1:]
                        if target_str:
                            idx = raw_val.lower().find(target_str.lower())
                            if idx != -1:
                                raw_val = sub_replace + raw_val[idx + len(target_str):]
                    else:
                        pattern = re.compile(re.escape(sub_search), re.IGNORECASE)
                        raw_val = pattern.sub(lambda _: sub_replace, raw_val)

                    self.modified = True
                    return LiteralNode(
                        value=raw_val,
                        is_quoted=False,
                        span=node.span
                    )

        # Plain constant variable folding
        vkey = node.name.lower()
        if vkey in self.env and node.slice_start is None and node.sub_search is None:
            self.modified = True
            cleaned = self._strip_lexical_artifacts(self.env[vkey])
            return LiteralNode(
                value=cleaned,
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
        """Runs slicing pass coalescing then applies lexical artifact stripping."""
        self.slicing_folder.env = self.env
        coalesced = self.slicing_folder._coalesce_nodes(nodes, is_target=is_target, is_value=is_value)
        if self.slicing_folder.modified:
            self.modified = True

        result: List[ASTNode] = []
        for n in coalesced:
            cleaned_node = self.visit(n)
            result.append(cleaned_node)

        # Final pass over adjacent unquoted literals
        final_nodes: List[ASTNode] = []
        for curr in result:
            if not final_nodes:
                final_nodes.append(curr)
                continue
            prev = final_nodes[-1]
            if isinstance(prev, LiteralNode) and isinstance(curr, LiteralNode):
                should_fuse = False
                if is_target or is_value:
                    should_fuse = True
                elif prev.span != (0, 0) and curr.span != (0, 0):
                    should_fuse = (prev.span[1] == curr.span[0])
                elif prev.span == (0, 0) and curr.span == (0, 0):
                    should_fuse = (getattr(prev, 'is_folded_slice', False) and getattr(curr, 'is_folded_slice', False))

                if should_fuse:
                    merged_val = prev.value + curr.value
                    merged_span = (prev.span[0], curr.span[1]) if prev.span != (0, 0) and curr.span != (0, 0) else (0, 0)
                    fused = LiteralNode(
                        value=merged_val,
                        is_quoted=prev.is_quoted and curr.is_quoted,
                        is_folded_slice=getattr(prev, 'is_folded_slice', False) or getattr(curr, 'is_folded_slice', False),
                        span=merged_span
                    )
                    final_nodes[-1] = fused
                    self.modified = True
                    continue
            final_nodes.append(curr)

        return final_nodes

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
            new_target = self._strip_lexical_artifacts(node.target)
            if new_target.startswith('%') and new_target.endswith('%'):
                vkey = new_target[1:-1].lower()
                if vkey in self.env:
                    new_target = self.env[vkey]
            new_target = self._strip_lexical_artifacts(new_target)

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
            new_raw = self._strip_lexical_artifacts(node.raw_value)

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
        new_dest = self._strip_lexical_artifacts(node.destination)
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
