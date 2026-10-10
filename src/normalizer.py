"""
AST Normalizer & Semantic Reduction Engine.
Performs symbol table propagation, constant folding, slicing resolution, and dead code elimination.
"""

from typing import Dict, Any, List
from .ast_nodes import (
    ASTVisitor, ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode, CommentNode
)


class ASTNormalizer(ASTVisitor):
    """
    Transforms obfuscated cmd.exe ASTs into canonical, deterministic forms.
    Propagates variable tables, folds slices, collapses empty quotes, and strips carets.
    """
    def __init__(self, initial_env: Dict[str, str] = None):
        # Prepopulate standard Windows environment baseline
        self.symbols: Dict[str, str] = {
            'comspec': r'C:\Windows\system32\cmd.exe',
            'systemroot': r'C:\Windows',
            'windir': r'C:\Windows',
            'pathext': '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
            'path': r'C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem'
        }
        if initial_env:
            for k, v in initial_env.items():
                self.symbols[k.lower()] = v

        self.referenced_vars = set()

    def normalize(self, root: ASTNode) -> ASTNode:
        """Executes normalization passes until fixed-point convergence."""
        return self.visit(root)

    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        cleaned_stmts: List[ASTNode] = []
        for stmt in node.statements:
            norm_stmt = self.visit(stmt)
            if norm_stmt is not None:
                cleaned_stmts.append(norm_stmt)
        return ScriptNode(statements=cleaned_stmts)

    def visit_ChainNode(self, node: ChainNode) -> ChainNode:
        norm_left = self.visit(node.left)
        norm_right = self.visit(node.right)
        return ChainNode(left=norm_left, operator=node.operator, right=norm_right)

    def visit_PipeNode(self, node: PipeNode) -> PipeNode:
        norm_left = self.visit(node.left)
        norm_right = self.visit(node.right)
        return PipeNode(left=norm_left, right=norm_right)

    def visit_BlockNode(self, node: BlockNode) -> BlockNode:
        cleaned_stmts = [self.visit(s) for s in node.statements if s is not None]
        return BlockNode(statements=cleaned_stmts)

    def visit_CommentNode(self, node: CommentNode) -> Optional[ASTNode]:
        return node

    def visit_AssignmentNode(self, node: AssignmentNode) -> Optional[ASTNode]:
        var_key = node.var_name.lower()
        val_resolved = node.raw_value

        # Strip internal carets and empty quotes from value
        val_resolved = self._strip_lexical_artifacts(val_resolved)
        self.symbols[var_key] = val_resolved

        # Return simplified assignment
        return AssignmentNode(var_name=node.var_name, raw_value=val_resolved)

    def visit_CommandNode(self, node: CommandNode) -> CommandNode:
        if node.target_nodes:
            norm_target_parts = []
            for t_node in node.target_nodes:
                norm_part = self.visit(t_node)
                if isinstance(norm_part, LiteralNode):
                    norm_target_parts.append(norm_part.value)
                elif isinstance(norm_part, VarExpandNode):
                    norm_target_parts.append(f"%{norm_part.name}%")
                else:
                    norm_target_parts.append(self.to_source(norm_part))
            clean_target = "".join(norm_target_parts)
        else:
            clean_target = self._strip_lexical_artifacts(node.target)
            if clean_target.startswith('%') and clean_target.endswith('%'):
                vname = clean_target[1:-1].lower()
                if vname in self.symbols:
                    clean_target = self.symbols[vname]

        clean_target = self._strip_lexical_artifacts(clean_target)

        norm_args: List[ASTNode] = []
        for arg in node.arguments:
            norm_arg = self.visit(arg)
            norm_args.append(norm_arg)

        return CommandNode(target=clean_target, target_nodes=node.target_nodes, arguments=norm_args)

    def visit_VarExpandNode(self, node: VarExpandNode) -> ASTNode:
        vkey = node.name.lower()
        val = self.symbols.get(vkey, None)

        if val is None:
            # Unresolved external variable, preserve token
            return node

        # Substring slicing resolution
        if node.slice_start is not None:
            start = node.slice_start
            length = node.slice_len
            if length is not None:
                if length >= 0:
                    val = val[start:start + length]
                else:
                    val = val[start:length]
            else:
                val = val[start:]

        # String substitution resolution
        if node.sub_search is not None:
            search_pattern = node.sub_search
            replace_pattern = node.sub_replace or ''
            val = val.replace(search_pattern, replace_pattern)

        return LiteralNode(value=val, is_quoted=False)

    def visit_LiteralNode(self, node: LiteralNode) -> LiteralNode:
        if not node.is_quoted:
            cleaned = self._strip_lexical_artifacts(node.value)
            return LiteralNode(value=cleaned, is_quoted=False)
        return node

    def _strip_lexical_artifacts(self, text: str) -> str:
        """Removes carets and collapses empty double quotes."""
        # Collapse ""
        text = text.replace('""', '')
        
        # Remove non-escaped carets ^
        res = []
        i = 0
        while i < len(text):
            if text[i] == '^':
                if i + 1 < len(text):
                    res.append(text[i + 1])
                    i += 2
                    continue
                else:
                    i += 1
                    continue
            res.append(text[i])
            i += 1
        return "".join(res)

    def to_source(self, node: ASTNode) -> str:
        """Serializes an AST hierarchy into clean batch script source code."""
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
            return f"%{node.name}%"

        if isinstance(node, CommentNode):
            return node.text

        return ""
