"""
I/O Redirection and Stream Routing AST Transform Pass for cmd-ast-deobfuscator.
Traverses AST hierarchies, canonicalizing redirection targets, unmasking escape sequences,
folding constant destination paths, and simulating stream routes.
"""

import re
from typing import Dict, List, Optional
from ..ast_nodes import (
    ASTNode, LiteralNode, CommandNode, AssignmentNode, VarExpandNode,
    RedirectNode, IfNode, ForNode, BlockNode, ChainNode, PipeNode, ScriptNode,
    GotoNode, CallNode
)
from ..redirection import (
    StreamRouter, RedirectEntry, RedirectMetrics, DestinationType,
    classify_destination, is_device_destination
)
from .base import TransformPass


class RedirectionPass(TransformPass):
    """
    AST Optimization Pass for I/O Redirection:
      1. Canonicalizes destination filenames and devices (unmasking carets and folding quotes).
      2. Resolves environment variable substitutions in destination paths.
      3. Simulates stream routing and tracks handle duplication / stealth suppression.
      4. Detects unparsed redirection tokens in arguments and lifts them into RedirectNodes.
    """

    def __init__(self, env: Optional[Dict[str, str]] = None):
        super().__init__(name="RedirectionPass", env=env)
        self.router = StreamRouter()

    @property
    def metrics(self) -> RedirectMetrics:
        return self.router.metrics

    def _unmask_destination(self, text: str) -> str:
        """Removes carets and collapses empty quotes from a destination string."""
        if not text:
            return ""
        # Remove empty quotes
        text = text.replace('""', '')
        # Unmask caret sequences e.g. ^x -> x
        res = []
        i = 0
        n = len(text)
        while i < n:
            if text[i] == '^':
                if i + 1 < n:
                    res.append(text[i + 1])
                    i += 2
                    continue
                else:
                    i += 1
                    continue
            res.append(text[i])
            i += 1
        return "".join(res)

    def _resolve_variables_in_destination(self, text: str) -> str:
        """Resolves known environment variables in a destination path."""
        if not text or not self.env:
            return text

        def _sub_pct(m):
            vname = m.group(1).lower()
            return self.env.get(vname, m.group(0))

        def _sub_exc(m):
            vname = m.group(1).lower()
            return self.env.get(vname, m.group(0))

        prev = None
        result = text
        iterations = 0
        while prev != result and iterations < 5:
            prev = result
            iterations += 1
            result = re.sub(r'%([a-zA-Z0-9_]+)%', _sub_pct, result)
            result = re.sub(r'!([a-zA-Z0-9_]+)!', _sub_exc, result)

        return result

    def visit_RedirectNode(self, node: RedirectNode) -> ASTNode:
        new_cmd = self.visit(node.command)
        orig_dest = node.destination

        # Unmask carets and resolve variables
        norm_dest = self._unmask_destination(orig_dest)
        norm_dest = self._resolve_variables_in_destination(norm_dest)

        dest_changed = (norm_dest != orig_dest)
        if dest_changed or new_cmd != node.command:
            self.modified = True

        # Classify destination
        dest_type, is_suppressed = classify_destination(norm_dest)

        # Update metrics through router
        entry = RedirectEntry(
            source_fd=node.source_fd if node.source_fd is not None else 1,
            operator=node.stream,
            destination=norm_dest,
            target_fd=node.target_fd,
            dest_type=dest_type,
            is_append=node.is_append,
            is_input=node.is_input,
            is_dup=node.is_dup,
            is_suppressed=is_suppressed,
            raw=f"{node.stream}{norm_dest}",
            span=node.span
        )
        self.router.metrics.record(entry)

        return RedirectNode(
            command=new_cmd,
            stream=node.stream,
            destination=norm_dest,
            source_fd=node.source_fd,
            target_fd=node.target_fd,
            is_append=node.is_append,
            is_input=node.is_input,
            is_dup=node.is_dup,
            span=node.span
        )

    def visit_CommandNode(self, node: CommandNode) -> ASTNode:
        new_target_nodes = [self.visit(t) for t in node.target_nodes] if node.target_nodes else []
        new_arguments = [self.visit(a) for a in node.arguments]

        # Check for unparsed literal redirect tokens in arguments
        clean_args: List[ASTNode] = []
        found_redirects: List[RedirectEntry] = []

        for arg in new_arguments:
            if isinstance(arg, LiteralNode) and not arg.is_quoted:
                val = arg.value
                # Match trailing redirects e.g. >out.txt or 2>&1
                m = re.search(r'([0-9]?)(>>|>|<|>&|<&)(\S+)?$', val)
                if m:
                    src_str, op, dest = m.groups()
                    dest_str = dest if dest else ""
                    src_fd = int(src_str) if src_str else (0 if op in ('<', '<&') else 1)
                    is_dup = (op in ('>&', '<&'))
                    target_fd = None
                    if is_dup and dest_str.startswith('&'):
                        digits = dest_str[1:]
                        if digits.isdigit():
                            target_fd = int(digits)
                    elif is_dup and dest_str.isdigit():
                        target_fd = int(dest_str)
                        dest_str = f"&{dest_str}"

                    d_type, is_sup = classify_destination(dest_str)
                    found_redirects.append(RedirectEntry(
                        source_fd=src_fd,
                        operator=op,
                        destination=dest_str,
                        target_fd=target_fd,
                        dest_type=d_type,
                        is_append=(op == '>>'),
                        is_input=(op in ('<', '<&')),
                        is_dup=is_dup,
                        is_suppressed=is_sup,
                        raw=m.group(0)
                    ))
                    # Retain prefix argument text if any
                    prefix = val[:m.start()].strip()
                    if prefix:
                        clean_args.append(LiteralNode(value=prefix, span=arg.span))
                    continue

            clean_args.append(arg)

        clean_cmd = CommandNode(
            target=node.target,
            target_nodes=new_target_nodes,
            arguments=clean_args,
            span=node.span
        )

        if found_redirects:
            self.modified = True
            current_node: ASTNode = clean_cmd
            for r in found_redirects:
                current_node = RedirectNode(
                    command=current_node,
                    stream=r.operator,
                    destination=r.destination,
                    source_fd=r.source_fd,
                    target_fd=r.target_fd,
                    is_append=r.is_append,
                    is_input=r.is_input,
                    is_dup=r.is_dup
                )
            return current_node

        if new_target_nodes != node.target_nodes or new_arguments != node.arguments:
            self.modified = True

        return clean_cmd

    def visit_BlockNode(self, node: BlockNode) -> BlockNode:
        new_stmts = [self.visit(s) for s in node.statements]
        if new_stmts != node.statements:
            self.modified = True
        return BlockNode(statements=new_stmts, span=node.span)

    def visit_IfNode(self, node: IfNode) -> IfNode:
        new_then = self.visit(node.then_block)
        new_else = self.visit(node.else_block) if node.else_block else None
        if new_then != node.then_block or new_else != node.else_block:
            self.modified = True
        return IfNode(condition=node.condition, then_block=new_then, else_block=new_else, span=node.span)

    def visit_ForNode(self, node: ForNode) -> ForNode:
        new_body = self.visit(node.body)
        if new_body != node.body:
            self.modified = True
        return ForNode(
            iterator=node.iterator,
            flags=node.flags,
            options=node.options,
            in_clause=node.in_clause,
            body=new_body,
            span=node.span
        )

    def visit_ChainNode(self, node: ChainNode) -> ChainNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left != node.left or new_right != node.right:
            self.modified = True
        return ChainNode(left=new_left, operator=node.operator, right=new_right, span=node.span)

    def visit_PipeNode(self, node: PipeNode) -> PipeNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left != node.left or new_right != node.right:
            self.modified = True
        return PipeNode(left=new_left, right=new_right, span=node.span)

    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        new_stmts = [self.visit(s) for s in node.statements]
        if new_stmts != node.statements:
            self.modified = True
        return ScriptNode(statements=new_stmts, span=node.span)

    def zeroize(self) -> None:
        """Securely zeroes internal router state and metrics."""
        self.router.zeroize()


RedirectNormalizerPass = RedirectionPass
