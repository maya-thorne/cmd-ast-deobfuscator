"""
Quote Normalization AST Transform Pass for cmd-ast-deobfuscator.
Traverses AST hierarchies, canonicalizing quote toggle boundaries, removing redundant
empty quote pairs, deobfuscating command targets and arguments, and normalizing SET assignments.
"""

from typing import Dict, List, Optional
from ..ast_nodes import (
    ASTNode, LiteralNode, CommandNode, AssignmentNode, VarExpandNode,
    RedirectNode, IfNode, ForNode, BlockNode, ChainNode, PipeNode, ScriptNode,
    GotoNode, CallNode
)
from ..quotes import QuoteNormalizer, QuoteNormalizerMetrics
from .base import TransformPass


class QuoteNormalizerPass(TransformPass):
    """
    AST Optimization Pass for quote toggle boundary and nested quote normalization:
      1. Command target quote stripping and caret unmasking ("c"m"d" -> cmd).
      2. Argument token canonicalization and empty quote collapse.
      3. Assignment variable name and value quote normalization (set "k=v" -> k=v).
      4. Adjacent literal node coalescing across quotation transitions.
    """

    def __init__(self, env: Optional[Dict[str, str]] = None):
        super().__init__(name="QuoteNormalizerPass", env=env)
        self.normalizer = QuoteNormalizer()

    @property
    def metrics(self) -> QuoteNormalizerMetrics:
        return self.normalizer.metrics

    def visit_LiteralNode(self, node: LiteralNode) -> ASTNode:
        if '""' in node.value:
            new_val = self.normalizer.automaton.collapse_empty_quotes(node.value)
            if new_val != node.value:
                self.modified = True
                self.normalizer.metrics.literals_normalized += 1
                return LiteralNode(
                    value=new_val,
                    is_quoted=node.is_quoted,
                    is_folded_slice=node.is_folded_slice,
                    span=node.span
                )
        return node

    def visit_CommandNode(self, node: CommandNode) -> ASTNode:
        # 1. Normalize target name
        new_target = self.normalizer.normalize_target(node.target)
        target_changed = (new_target != node.target)

        # 2. Normalize target nodes if present
        new_target_nodes = []
        if node.target_nodes:
            visited_targets = [self.visit(t) for t in node.target_nodes]
            new_target_nodes = self.normalizer.coalesce_literal_nodes(visited_targets)
            if new_target_nodes != node.target_nodes:
                target_changed = True

        # 3. Normalize arguments: first fuse contiguous tokens within the same argument
        fused_raw_args: List[ASTNode] = []
        args_changed = False
        for curr in node.arguments:
            if not fused_raw_args:
                fused_raw_args.append(curr)
                continue
            prev = fused_raw_args[-1]
            if isinstance(prev, LiteralNode) and isinstance(curr, LiteralNode):
                if prev.span != (0, 0) and curr.span != (0, 0) and prev.span[1] == curr.span[0]:
                    merged_val = prev.value + curr.value
                    merged_span = (prev.span[0], curr.span[1])
                    fused_raw_args[-1] = LiteralNode(
                        value=merged_val,
                        is_quoted=prev.is_quoted and curr.is_quoted,
                        is_folded_slice=getattr(prev, 'is_folded_slice', False) or getattr(curr, 'is_folded_slice', False),
                        span=merged_span
                    )
                    args_changed = True
                    continue
            fused_raw_args.append(curr)

        new_args: List[ASTNode] = []
        for arg in fused_raw_args:
            if isinstance(arg, LiteralNode):
                norm_val = self.normalizer.normalize_argument(arg.value)
                if norm_val != arg.value:
                    args_changed = True
                    new_args.append(LiteralNode(
                        value=norm_val,
                        is_quoted=arg.is_quoted,
                        is_folded_slice=arg.is_folded_slice,
                        span=arg.span
                    ))
                else:
                    new_args.append(arg)
            else:
                visited_arg = self.visit(arg)
                if visited_arg is not arg:
                    args_changed = True
                new_args.append(visited_arg)

        if target_changed or args_changed:
            self.modified = True
            return CommandNode(
                target=new_target,
                target_nodes=new_target_nodes if new_target_nodes else node.target_nodes,
                arguments=new_args,
                span=node.span
            )

        return node

    def visit_AssignmentNode(self, node: AssignmentNode) -> ASTNode:
        clean_var, clean_val, _ = self.normalizer.normalize_assignment(node.var_name, node.raw_value)
        changed = (clean_var != node.var_name) or (clean_val != node.raw_value)

        # Visit and coalesce value nodes
        new_val_nodes = [self.visit(v) for v in node.value_nodes]
        coalesced_val_nodes = self.normalizer.coalesce_literal_nodes(new_val_nodes)
        if coalesced_val_nodes != node.value_nodes:
            changed = True

        self.env[clean_var.lower()] = clean_val

        if changed:
            self.modified = True
            return AssignmentNode(
                var_name=clean_var,
                value_nodes=coalesced_val_nodes,
                raw_value=clean_val,
                is_arithmetic=node.is_arithmetic,
                span=node.span
            )

        return node

    def visit_CallNode(self, node: CallNode) -> ASTNode:
        new_target = self.normalizer.normalize_target(node.target)
        target_changed = (new_target != node.target)

        new_targets = [self.visit(t) for t in node.target_nodes]
        new_args = [self.visit(a) for a in node.arguments]
        args_changed = (new_args != node.arguments) or (new_targets != node.target_nodes)

        if target_changed or args_changed:
            self.modified = True
            return CallNode(
                target=new_target,
                target_nodes=new_targets,
                arguments=new_args,
                is_subroutine=node.is_subroutine,
                is_dynamic=node.is_dynamic,
                span=node.span
            )
        return node

    def visit_GotoNode(self, node: GotoNode) -> ASTNode:
        new_target = self.normalizer.normalize_target(node.target)
        if new_target != node.target:
            self.modified = True
            return GotoNode(
                target=new_target,
                target_nodes=node.target_nodes,
                is_eof=node.is_eof,
                is_dynamic=node.is_dynamic,
                span=node.span
            )
        return node

    def visit_IfNode(self, node: IfNode) -> ASTNode:
        new_then = self.visit(node.then_block)
        new_else = self.visit(node.else_block) if node.else_block else None
        if new_then is not node.then_block or new_else is not node.else_block:
            self.modified = True
            return IfNode(condition=node.condition, then_block=new_then, else_block=new_else, span=node.span)
        return node

    def visit_ForNode(self, node: ForNode) -> ASTNode:
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

    def visit_BlockNode(self, node: BlockNode) -> ASTNode:
        new_stmts = [self.visit(s) for s in node.statements]
        if new_stmts != node.statements:
            self.modified = True
            return BlockNode(statements=new_stmts, span=node.span)
        return node

    def visit_ChainNode(self, node: ChainNode) -> ASTNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left is not node.left or new_right is not node.right:
            self.modified = True
            return ChainNode(left=new_left, operator=node.operator, right=new_right, span=node.span)
        return node

    def visit_PipeNode(self, node: PipeNode) -> ASTNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left is not node.left or new_right is not node.right:
            self.modified = True
            return PipeNode(left=new_left, right=new_right, span=node.span)
        return node

    def visit_RedirectNode(self, node: RedirectNode) -> ASTNode:
        new_cmd = self.visit(node.command)
        if new_cmd is not node.command:
            self.modified = True
            return RedirectNode(command=new_cmd, stream=node.stream, destination=node.destination, span=node.span)
        return node

    def visit_ScriptNode(self, node: ScriptNode) -> ASTNode:
        new_stmts = [self.visit(s) for s in node.statements]
        if new_stmts != node.statements:
            self.modified = True
            return ScriptNode(statements=new_stmts, span=node.span)
        return node

    def zeroize(self) -> None:
        """Secure memory clearing."""
        self.normalizer.zeroize()
