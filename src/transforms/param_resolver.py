"""
Parameter and FOR Variable Resolver Transform Pass for cmd-ast-deobfuscator.
Evaluates positional script arguments (%0..%9, %*) and FOR loop variables (%%i..%%z)
with full Windows path modifier semantics (~dp, ~f, ~nx, ~s, ~$PATH:).
"""

import os
from typing import Dict, List, Optional
from ..ast_nodes import (
    ASTNode, CommandNode, AssignmentNode, ParamExpandNode,
    LiteralNode, BlockNode, ChainNode, PipeNode, RedirectNode,
    IfNode, ForNode, ScriptNode
)
from ..modifiers import parse_modifiers, PathModifierResolver
from .base import TransformPass


class ParamResolverPass(TransformPass):
    """
    AST Optimization Pass that resolves positional parameters (%0..%9) and
    FOR loop variables (%%i..%%z) into evaluated path literals when supplied
    or known statically.
    """
    def __init__(
        self,
        params: Optional[Dict[str, str]] = None,
        for_vars: Optional[Dict[str, str]] = None,
        base_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        name: Optional[str] = None
    ):
        super().__init__(name=name or "ParamResolverPass", env=env)
        self.params: Dict[str, str] = dict(params) if params else {}
        self.for_vars: Dict[str, str] = dict(for_vars) if for_vars else {}
        if base_dir:
            self.base_dir = base_dir
        elif '0' in self.params and self.params['0']:
            p0 = self.params['0'].replace('/', '\\')
            self.base_dir = os.path.dirname(p0) if '\\' in p0 else r"C:\Windows\System32"
        else:
            self.base_dir = r"C:\Windows\System32"

    def set_param(self, key: str, value: str):
        """Sets a positional parameter value (e.g. '0' -> 'C:\\run.bat')."""
        self.params[key] = value

    def set_for_var(self, key: str, value: str):
        """Sets a FOR loop variable value (e.g. 'i' -> 'C:\\file.txt')."""
        self.for_vars[key] = value

    def visit_ParamExpandNode(self, node: ParamExpandNode) -> ASTNode:
        """Evaluates a parameter expansion token into a LiteralNode if resolved."""
        var_key = node.name
        val: Optional[str] = None

        if node.is_for_var:
            if var_key in self.for_vars:
                val = self.for_vars[var_key]
            elif var_key.lower() in self.for_vars:
                val = self.for_vars[var_key.lower()]
        else:
            if var_key in self.params:
                val = self.params[var_key]

        if val is None:
            return node

        spec = parse_modifiers(node.modifiers)
        resolved = PathModifierResolver.resolve(
            spec=spec,
            target_val=val,
            base_dir=self.base_dir,
            env=self.env
        )

        self.modified = True
        return LiteralNode(value=resolved, is_quoted=False, span=node.span)

    def visit_CommandNode(self, node: CommandNode) -> CommandNode:
        changed = False

        # Transform target_nodes
        new_target_nodes = []
        for t in node.target_nodes:
            new_t = self.visit(t)
            new_target_nodes.append(new_t)
            if new_t is not t:
                changed = True

        new_target = node.target
        if changed and new_target_nodes:
            new_target = "".join(self.to_source(t) for t in new_target_nodes)

        # Transform arguments
        new_args = []
        for a in node.arguments:
            new_a = self.visit(a)
            new_args.append(new_a)
            if new_a is not a:
                changed = True

        # Coalesce adjacent unquoted literals
        coalesced_args = self._coalesce_nodes(new_args)
        if len(coalesced_args) != len(new_args):
            changed = True
            new_args = coalesced_args

        if changed:
            self.modified = True
            return CommandNode(
                target=new_target,
                target_nodes=new_target_nodes,
                arguments=new_args,
                span=node.span
            )
        return node

    def visit_AssignmentNode(self, node: AssignmentNode) -> AssignmentNode:
        changed = False
        new_val_nodes = []
        for v in node.value_nodes:
            new_v = self.visit(v)
            new_val_nodes.append(new_v)
            if new_v is not v:
                changed = True

        new_raw = node.raw_value
        if changed and new_val_nodes:
            new_raw = "".join(self.to_source(v) for v in new_val_nodes)
            self.env[node.var_name.lower()] = new_raw

        coalesced = self._coalesce_nodes(new_val_nodes)
        if len(coalesced) != len(new_val_nodes):
            changed = True
            new_val_nodes = coalesced

        if changed:
            self.modified = True
            return AssignmentNode(
                var_name=node.var_name,
                value_nodes=new_val_nodes,
                raw_value=new_raw,
                is_arithmetic=node.is_arithmetic,
                span=node.span
            )
        return node

    def visit_ForNode(self, node: ForNode) -> ForNode:
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

    def _coalesce_nodes(self, nodes: List[ASTNode]) -> List[ASTNode]:
        """Fuses consecutive unquoted LiteralNodes into single LiteralNodes."""
        if not nodes:
            return []
        merged: List[ASTNode] = []
        for n in nodes:
            if merged and isinstance(merged[-1], LiteralNode) and isinstance(n, LiteralNode):
                if not merged[-1].is_quoted and not n.is_quoted:
                    prev = merged[-1]
                    merged[-1] = LiteralNode(
                        value=prev.value + n.value,
                        is_quoted=False,
                        span=(prev.span[0], n.span[1]) if prev.span and n.span else prev.span
                    )
                    continue
            merged.append(n)
        return merged
