"""
Base AST Transform Visitor and Pass Manager for cmd-ast-deobfuscator.
Provides the foundational transformation interface, AST traversal defaults,
environment table tracking, and fixed-point iteration pass management.
"""

from typing import Dict, List, Optional, Any
from ..ast_nodes import (
    ASTVisitor, ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode,
    CommentNode, IfNode, ForNode
)

DEFAULT_ENV: Dict[str, str] = {
    'comspec': r'C:\Windows\system32\cmd.exe',
    'systemroot': r'C:\Windows',
    'windir': r'C:\Windows',
    'pathext': '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
    'path': r'C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem',
    'os': 'Windows_NT',
    'programdata': r'C:\ProgramData',
    'public': r'C:\Users\Public',
    'allusersprofile': r'C:\ProgramData',
    'commonprogramfiles': r'C:\Program Files\Common Files',
}


class TransformPass(ASTVisitor):
    """
    Abstract base class for all AST optimization and normalization passes.
    Tracks modification state and maintains an environment symbol table.
    """
    def __init__(self, name: Optional[str] = None, env: Optional[Dict[str, str]] = None):
        self.name = name or self.__class__.__name__
        self.env: Dict[str, str] = {k.lower(): v for k, v in DEFAULT_ENV.items()}
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v
        self.modified: bool = False

    def transform(self, root: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        """Runs the transform pass on the given root AST node."""
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v
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

    def visit_ChainNode(self, node: ChainNode) -> ChainNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left is not node.left or new_right is not node.right:
            self.modified = True
            return ChainNode(left=new_left, operator=node.operator, right=new_right, span=node.span)
        return node

    def visit_PipeNode(self, node: PipeNode) -> PipeNode:
        new_left = self.visit(node.left)
        new_right = self.visit(node.right)
        if new_left is not node.left or new_right is not node.right:
            self.modified = True
            return PipeNode(left=new_left, right=new_right, span=node.span)
        return node

    def visit_BlockNode(self, node: BlockNode) -> BlockNode:
        new_stmts: List[ASTNode] = []
        changed = False
        for s in node.statements:
            new_s = self.visit(s)
            if new_s is not None:
                new_stmts.append(new_s)
            if new_s is not s:
                changed = True
        if changed:
            self.modified = True
            return BlockNode(statements=new_stmts, span=node.span)
        return node

    def visit_CommandNode(self, node: CommandNode) -> CommandNode:
        new_target_nodes = [self.visit(t) for t in node.target_nodes] if node.target_nodes else []
        new_args = [self.visit(a) for a in node.arguments]
        changed = (new_target_nodes != node.target_nodes) or (new_args != node.arguments)
        if changed:
            self.modified = True
            return CommandNode(
                target=node.target,
                target_nodes=new_target_nodes,
                arguments=new_args,
                span=node.span
            )
        return node

    def visit_AssignmentNode(self, node: AssignmentNode) -> AssignmentNode:
        new_val_nodes = [self.visit(v) for v in node.value_nodes]
        changed = (new_val_nodes != node.value_nodes)
        var_key = node.var_name.lower()
        self.env[var_key] = node.raw_value
        if changed:
            self.modified = True
            return AssignmentNode(
                var_name=node.var_name,
                value_nodes=new_val_nodes,
                raw_value=node.raw_value,
                is_arithmetic=node.is_arithmetic,
                span=node.span
            )
        return node

    def visit_RedirectNode(self, node: RedirectNode) -> RedirectNode:
        new_cmd = self.visit(node.command)
        if new_cmd is not node.command:
            self.modified = True
            return RedirectNode(command=new_cmd, stream=node.stream, destination=node.destination, span=node.span)
        return node

    def visit_IfNode(self, node: IfNode) -> IfNode:
        new_then = self.visit(node.then_block)
        new_else = self.visit(node.else_block) if node.else_block else None
        if new_then is not node.then_block or new_else is not node.else_block:
            self.modified = True
            return IfNode(condition=node.condition, then_block=new_then, else_block=new_else, span=node.span)
        return node

    def visit_ForNode(self, node: ForNode) -> ForNode:
        new_body = self.visit(node.body)
        if new_body is not node.body:
            self.modified = True
            return ForNode(iterator=node.iterator, in_clause=node.in_clause, body=new_body, span=node.span)
        return node

    def visit_LiteralNode(self, node: LiteralNode) -> ASTNode:
        return node

    def visit_VarExpandNode(self, node: VarExpandNode) -> ASTNode:
        return node

    def visit_CommentNode(self, node: CommentNode) -> ASTNode:
        return node

    def generic_visit(self, node: ASTNode) -> ASTNode:
        return node

    def to_source(self, node: ASTNode) -> str:
        """Serializes an AST hierarchy into canonical batch script representation."""
        if isinstance(node, ScriptNode):
            lines = [self.to_source(s) for s in node.statements]
            return "\n".join(l for l in lines if l.strip())

        if isinstance(node, ChainNode):
            return f"{self.to_source(node.left)} {node.operator} {self.to_source(node.right)}"

        if isinstance(node, PipeNode):
            return f"{self.to_source(node.left)} | {self.to_source(node.right)}"

        if isinstance(node, BlockNode):
            inner = " & ".join(self.to_source(s) for s in node.statements)
            return f"({inner})"

        if isinstance(node, AssignmentNode):
            return f"set {node.var_name}={node.raw_value}"

        if isinstance(node, CommandNode):
            if node.arguments:
                args_str = " " + " ".join(self.to_source(a) for a in node.arguments)
            else:
                args_str = ""
            return f"{node.target}{args_str}".strip()

        if isinstance(node, LiteralNode):
            return node.value

        if isinstance(node, VarExpandNode):
            delim = "!" if node.is_delayed else "%"
            if node.slice_start is not None or node.slice_start_expr is not None:
                s = str(node.slice_start) if node.slice_start is not None else (node.slice_start_expr or "")
                if node.slice_len is not None or node.slice_len_expr is not None:
                    l = str(node.slice_len) if node.slice_len is not None else (node.slice_len_expr or "")
                    slice_str = f":~{s},{l}"
                else:
                    slice_str = f":~{s}"
                return f"{delim}{node.name}{slice_str}{delim}"
            if node.sub_search is not None:
                sub_replace = node.sub_replace if node.sub_replace is not None else ""
                return f"{delim}{node.name}:{node.sub_search}={sub_replace}{delim}"
            return f"{delim}{node.name}{delim}"

        if isinstance(node, CommentNode):
            return node.text

        return ""


class PassManager:
    """
    Manages and executes an optimization pipeline of AST passes
    using fixed-point iteration until convergence or max iterations reached.
    """
    def __init__(self, passes: Optional[List[TransformPass]] = None, max_iterations: int = 20):
        self.passes: List[TransformPass] = list(passes) if passes else []
        self.max_iterations = max_iterations

    def add_pass(self, transform_pass: TransformPass) -> 'PassManager':
        self.passes.append(transform_pass)
        return self

    def run(self, ast: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        current_ast = ast
        for _ in range(self.max_iterations):
            any_modified = False
            for p in self.passes:
                current_ast = p.transform(current_ast, env=env)
                if p.modified:
                    any_modified = True
            if not any_modified:
                break
        return current_ast


def run_transforms(
    ast: ASTNode,
    passes: Optional[List[TransformPass]] = None,
    env: Optional[Dict[str, str]] = None,
    max_iterations: int = 20
) -> ASTNode:
    """Convenience entry point to execute transforms with fixed-point iteration."""
    if passes is None:
        from .slicing_folder import SlicingFolderPass
        from .constant_folder import ConstantFolderPass
        passes = [SlicingFolderPass(env=env), ConstantFolderPass(env=env)]
    pm = PassManager(passes=passes, max_iterations=max_iterations)
    return pm.run(ast, env=env)
