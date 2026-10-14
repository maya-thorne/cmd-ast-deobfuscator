#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Invoke-DOSfuscation Concatenation AST Transform Pass
Integrates with the PassManager pipeline to AST-rewrite:
- Concatenated command targets and arguments
- Multi-statement assignment chains (&, &&)
- FOR token accumulation loops folded into constant assignments
- Scrambled delimiters normalized into canonical command structures
- Junk variable elimination across AST nodes
"""

from typing import Dict, List, Optional, Set, Any
import re

from .base import TransformPass
from ..ast_nodes import (
    ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode,
    CommentNode, IfNode, ForNode, ParamExpandNode, LabelNode, GotoNode,
    CallNode, ExitNode
)
from ..dosfuscation.models import DosfuscationMetrics, ConcatenationType
from ..dosfuscation.concatenation import DosfuscationConcatenationDecoder


class DosfuscationPass(TransformPass):
    """
    AST Optimization pass specialized in resolving Invoke-DOSfuscation
    concatenation patterns across the entire syntax tree.
    """

    def __init__(self, env: Optional[Dict[str, str]] = None):
        super().__init__(name="DosfuscationPass", env=env)
        self.decoder = DosfuscationConcatenationDecoder(env=self.env)
        self.metrics = DosfuscationMetrics()

    def transform(self, root: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v
                self.decoder.env[k.lower()] = v
        self.modified = False
        return self.visit(root)

    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        new_stmts: List[ASTNode] = []
        changed = False

        for stmt in node.statements:
            new_stmt = self.visit(stmt)
            if new_stmt is not None:
                new_stmts.append(new_stmt)
            if new_stmt is not stmt:
                changed = True

        if changed:
            self.modified = True
            return ScriptNode(statements=new_stmts, span=node.span)
        return node

    def visit_ChainNode(self, node: ChainNode) -> ASTNode:
        # Sequential left-to-right evaluation with environment state propagation
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)

        if new_left is not node.left or new_right is not node.right:
            self.modified = True
            return ChainNode(left=new_left, operator=node.operator, right=new_right, span=node.span)
        return node

    def visit_AssignmentNode(self, node: AssignmentNode) -> ASTNode:
        # Resolve variables in assignment value
        var_name = node.var_name.lower()
        raw_val = node.raw_value

        # Decode concatenation in the raw value
        fused_val, fused_count = self.decoder.fuse_variable_chains(raw_val, self.env)
        fused_val, stripped_junk = self.decoder.strip_junk_variables(fused_val, self.env)

        self.metrics.var_chains_fused += fused_count
        self.metrics.junk_vars_stripped += stripped_junk

        # Update environment symbol table
        self.env[var_name] = fused_val
        self.decoder.env[var_name] = fused_val

        if fused_val != raw_val:
            self.modified = True
            # Recreate node with clean literal value
            new_val_nodes = [LiteralNode(value=fused_val, span=node.span)]
            return AssignmentNode(
                var_name=node.var_name,
                raw_value=fused_val,
                value_nodes=new_val_nodes,
                span=node.span
            )

        return node

    def visit_CommandNode(self, node: CommandNode) -> ASTNode:
        # Normalize target
        changed = False
        new_target = node.target
        fused_target, fused_count = self.decoder.fuse_variable_chains(node.target, self.env)
        fused_target, junk_count = self.decoder.strip_junk_variables(fused_target, self.env)
        norm_target, delim_count = self.decoder.normalize_delimiters(fused_target)

        self.metrics.var_chains_fused += fused_count
        self.metrics.junk_vars_stripped += junk_count
        self.metrics.delimiters_normalized += delim_count

        if norm_target != node.target:
            new_target = norm_target.strip()
            changed = True

        # Normalize target nodes if present
        new_target_nodes = []
        if node.target_nodes:
            # If target resolved to a plain literal, simplify target nodes
            if new_target != node.target and not ('%' in new_target or '!' in new_target):
                new_target_nodes = [LiteralNode(value=new_target, span=node.span)]
                changed = True
            else:
                for tn in node.target_nodes:
                    visited_tn = self.visit(tn)
                    new_target_nodes.append(visited_tn)
                    if visited_tn is not tn:
                        changed = True
        elif new_target != node.target:
            new_target_nodes = [LiteralNode(value=new_target, span=node.span)]

        # Normalize arguments
        new_args = []
        for arg in node.arguments:
            if isinstance(arg, LiteralNode):
                arg_val = arg.value
                fused_arg, f_count = self.decoder.fuse_variable_chains(arg_val, self.env)
                fused_arg, j_count = self.decoder.strip_junk_variables(fused_arg, self.env)
                norm_arg, d_count = self.decoder.normalize_delimiters(fused_arg)

                self.metrics.var_chains_fused += f_count
                self.metrics.junk_vars_stripped += j_count
                self.metrics.delimiters_normalized += d_count

                if norm_arg != arg_val:
                    new_args.append(LiteralNode(value=norm_arg, span=arg.span))
                    changed = True
                else:
                    new_args.append(arg)
            elif isinstance(arg, VarExpandNode):
                vname = arg.name.lower()
                if vname in self.env:
                    resolved_val = self.env[vname]
                    new_args.append(LiteralNode(value=resolved_val, span=arg.span))
                    changed = True
                    self.metrics.var_chains_fused += 1
                else:
                    new_args.append(arg)
            else:
                visited_arg = self.visit(arg)
                new_args.append(visited_arg)
                if visited_arg is not arg:
                    changed = True

        # Coalesce adjacent literal arguments if delimiters were stripped
        coalesced_args = self._coalesce_adjacent_literals(new_args)
        if len(coalesced_args) != len(new_args):
            changed = True
            new_args = coalesced_args

        if changed:
            self.modified = True
            return CommandNode(
                target=new_target,
                arguments=new_args,
                target_nodes=new_target_nodes,
                span=node.span
            )

        return node

    def visit_ForNode(self, node: ForNode) -> ASTNode:
        # Check if this FOR node is a token accumulator loop
        # e.g., for %x in (c a l c) do set out=!out!%x
        if isinstance(node.body, AssignmentNode):
            target_var = node.body.var_name
            raw_val = node.body.raw_value.strip()
            targ_ref = re.escape(target_var)

            append_pat = re.compile(
                r'^(?:[%!]' + targ_ref + r'[%!])\s*(?:(?:%|%%)[a-zA-Z0-9_])$',
                re.IGNORECASE
            )
            prepend_pat = re.compile(
                r'^(?:(?:%|%%)[a-zA-Z0-9_])\s*(?:[%!]' + targ_ref + r'[%!])$',
                re.IGNORECASE
            )

            is_app = bool(append_pat.match(raw_val))
            is_prep = bool(prepend_pat.match(raw_val))

            if is_app or is_prep:
                # Extract items from in_clause
                raw_clause = node.in_clause.strip('() \t')
                raw_tokens = [tok.strip(' ",\t;') for tok in re.split(r'[,;\s]+', raw_clause) if tok.strip(' ",\t;')]
                if raw_tokens:
                    current_val = self.env.get(target_var.lower(), "")
                    if is_app:
                        for tok in raw_tokens:
                            current_val += tok
                    else:
                        for tok in raw_tokens:
                            current_val = tok + current_val

                    self.env[target_var.lower()] = current_val
                    self.metrics.loops_accumulated += 1
                    self.modified = True
                    return AssignmentNode(
                        var_name=target_var,
                        raw_value=current_val,
                        value_nodes=[LiteralNode(value=current_val, span=node.span)],
                        span=node.span
                    )

        elif isinstance(node.body, CommandNode):
            body_src = self.to_source(node.body)
            full_for_src = f"for {node.iterator} in ({node.in_clause}) do {body_src}"
            resolved_for, accum_count = self.decoder.resolve_token_accumulation_loops(full_for_src, self.env)

            if accum_count > 0:
                self.metrics.loops_accumulated += accum_count
                self.modified = True
                m = re.match(r'^set\s+"?([a-zA-Z0-9_\-\.\$]+)=([^"\r\n]*)"?$', resolved_for.strip(), re.IGNORECASE)
                if m:
                    var_name = m.group(1)
                    val = m.group(2)
                    self.env[var_name.lower()] = val
                    return AssignmentNode(
                        var_name=var_name,
                        raw_value=val,
                        value_nodes=[LiteralNode(value=val, span=node.span)],
                        span=node.span
                    )

        # Default recursive traversal
        new_body = self.visit(node.body) if node.body else None
        if new_body is not node.body:
            self.modified = True
            return ForNode(
                iterator=node.iterator,
                in_clause=node.in_clause,
                body=new_body,
                flags=node.flags,
                options=node.options,
                span=node.span
            )
        return node

    def visit_CallNode(self, node: CallNode) -> ASTNode:
        # If target has variables or is dynamic trampoline, unroll
        if not node.is_subroutine:
            fused_target, count = self.decoder.fuse_variable_chains(node.target, self.env)
            if fused_target != node.target:
                self.modified = True
                self.metrics.trampolines_unrolled += 1
                # If target resolved to a standard binary, we can convert CallNode to CommandNode
                new_args = [self.visit(a) for a in node.arguments]
                return CommandNode(
                    target=fused_target,
                    arguments=new_args,
                    target_nodes=[LiteralNode(value=fused_target, span=node.span)],
                    span=node.span
                )

        new_args = [self.visit(a) for a in node.arguments]
        if new_args != node.arguments:
            self.modified = True
            return CallNode(
                target=node.target,
                arguments=new_args,
                is_subroutine=node.is_subroutine,
                span=node.span
            )
        return node

    def _coalesce_adjacent_literals(self, args: List[ASTNode]) -> List[ASTNode]:
        """Fuses adjacent literal nodes ONLY if they have contiguous character spans."""
        if len(args) <= 1:
            return args
        coalesced: List[ASTNode] = []
        i = 0
        while i < len(args):
            cur = args[i]
            if isinstance(cur, LiteralNode) and cur.span:
                combined_val = cur.value
                end_span = cur.span[1]
                j = i + 1
                while j < len(args):
                    nxt = args[j]
                    if isinstance(nxt, LiteralNode) and nxt.span and nxt.span[0] == end_span:
                        combined_val += nxt.value
                        end_span = nxt.span[1]
                        j += 1
                    else:
                        break
                if j > i + 1:
                    coalesced.append(LiteralNode(value=combined_val, span=(cur.span[0], end_span)))
                    i = j
                    continue
            coalesced.append(cur)
            i += 1
        return coalesced
