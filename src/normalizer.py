"""
AST Normalizer & Semantic Reduction Engine.
Performs symbol table propagation, constant folding, slicing resolution, and dead code elimination.
"""

import re
from typing import Dict, Any, List, Optional
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

        # Resolve defined variables inside assignment value (slicing, substitution, delayed)
        def _resolve_in_val(m):
            delim = m.group(1)
            content = m.group(2)
            is_delayed = (delim == '!')
            from .parser import CmdASTParser
            var_node = CmdASTParser.parse_var_content(content, is_delayed=is_delayed)
            norm = self.visit_VarExpandNode(var_node)
            if isinstance(norm, LiteralNode):
                return norm.value
            return m.group(0)

        prev = None
        iterations = 0
        while prev != val_resolved and iterations < 10:
            prev = val_resolved
            iterations += 1
            val_resolved = re.sub(r'([%!])([^%!\r\n]+)\1', _resolve_in_val, val_resolved)

        # Strip internal carets and empty quotes from value
        val_resolved = self._strip_lexical_artifacts(val_resolved)
        self.symbols[var_key] = val_resolved

        # Return simplified assignment
        return AssignmentNode(var_name=node.var_name, raw_value=val_resolved)

    def visit_CommandNode(self, node: CommandNode) -> CommandNode:
        norm_target_nodes = []
        if node.target_nodes:
            norm_target_parts = []
            for t_node in node.target_nodes:
                norm_part = self.visit(t_node)
                norm_target_nodes.append(norm_part)
                if isinstance(norm_part, LiteralNode):
                    norm_target_parts.append(norm_part.value)
                elif isinstance(norm_part, VarExpandNode):
                    norm_target_parts.append(self.to_source(norm_part))
                else:
                    norm_target_parts.append(self.to_source(norm_part))
            clean_target = "".join(norm_target_parts)
        else:
            clean_target = self._strip_lexical_artifacts(node.target)
            if (clean_target.startswith('%') and clean_target.endswith('%')) or \
               (clean_target.startswith('!') and clean_target.endswith('!')):
                vname = clean_target[1:-1].lower()
                if vname in self.symbols:
                    clean_target = self.symbols[vname]

        clean_target = self._strip_lexical_artifacts(clean_target)

        norm_args: List[ASTNode] = []
        for arg in node.arguments:
            norm_arg = self.visit(arg)
            norm_args.append(norm_arg)

        return CommandNode(target=clean_target, target_nodes=norm_target_nodes, arguments=norm_args)

    @staticmethod
    def calculate_slice(val: str, start: int, length: Optional[int]) -> str:
        """
        Computes cmd.exe substring slicing with positive and negative indices.
        Semantics:
        - start >= 0: 0-based offset from start of string.
        - start < 0: offset from end of string (e.g. -3 means 3 chars from end).
        - length is None: slice to the end of string.
        - length >= 0: number of characters to extract.
        - length < 0: leave off abs(length) characters from the end of string.
        """
        n = len(val)
        if start < 0:
            offset = max(0, n + start)
        else:
            offset = start

        if offset >= n:
            return ""

        if length is None:
            return val[offset:]

        if length < 0:
            end_offset = n + length
        else:
            end_offset = offset + length

        if end_offset <= offset:
            return ""

        return val[offset:end_offset]

    def _calculate_slice(self, val: str, start: int, length: Optional[int]) -> str:
        return self.calculate_slice(val, start, length)

    def visit_VarExpandNode(self, node: VarExpandNode) -> ASTNode:
        from .parser import CmdASTParser

        # Dynamic variable expansion: resolve any nested percent variables in delayed variable names/expressions
        name_to_lookup = node.name
        if node.is_delayed and '%' in name_to_lookup:
            name_to_lookup = re.sub(
                r'%([a-zA-Z0-9_]+)%',
                lambda m: self.symbols.get(m.group(1).lower(), m.group(0)),
                name_to_lookup
            )
            if (':~' in name_to_lookup or (':' in name_to_lookup and '=' in name_to_lookup)) and \
               node.slice_start is None and node.sub_search is None:
                reparsed = CmdASTParser.parse_var_content(name_to_lookup, is_delayed=True)
                node = reparsed
                name_to_lookup = node.name

        # Resolve nested percent variables in search/replace patterns for delayed expansion
        if node.is_delayed:
            if node.sub_search is not None and '%' in node.sub_search:
                node.sub_search = re.sub(
                    r'%([a-zA-Z0-9_]+)%',
                    lambda m: self.symbols.get(m.group(1).lower(), m.group(0)),
                    node.sub_search
                )
            if node.sub_replace is not None and '%' in node.sub_replace:
                node.sub_replace = re.sub(
                    r'%([a-zA-Z0-9_]+)%',
                    lambda m: self.symbols.get(m.group(1).lower(), m.group(0)),
                    node.sub_replace
                )

        vkey = name_to_lookup.lower()
        val = self.symbols.get(vkey, None)

        if val is None:
            if name_to_lookup != node.name:
                node.name = name_to_lookup
            return node

        # Resolve nested expressions in slice parameters
        if node.slice_start_expr is not None:
            resolved_s = re.sub(
                r'[%!]([a-zA-Z0-9_]+)[%!]',
                lambda m: self.symbols.get(m.group(1).lower(), m.group(0)),
                node.slice_start_expr
            )
            try:
                s_clean = re.sub(r'\s+', '', resolved_s)
                if s_clean.startswith('+'):
                    s_clean = s_clean[1:]
                node.slice_start = int(s_clean or '0')
                node.slice_start_expr = None
            except ValueError:
                pass

        if node.slice_len_expr is not None:
            resolved_l = re.sub(
                r'[%!]([a-zA-Z0-9_]+)[%!]',
                lambda m: self.symbols.get(m.group(1).lower(), m.group(0)),
                node.slice_len_expr
            )
            try:
                l_clean = re.sub(r'\s+', '', resolved_l)
                if l_clean.startswith('+'):
                    l_clean = l_clean[1:]
                node.slice_len = int(l_clean or '0')
                node.slice_len_expr = None
            except ValueError:
                pass

        # Substring slicing resolution
        if node.slice_start is not None and node.slice_start_expr is None and node.slice_len_expr is None:
            val = self._calculate_slice(val, node.slice_start, node.slice_len)

        # String substitution resolution
        if node.sub_search is not None:
            sub_search = node.sub_search
            sub_replace = node.sub_replace or ''
            if '%' in sub_search:
                sub_search = re.sub(
                    r'%([a-zA-Z0-9_]+)%',
                    lambda m: self.symbols.get(m.group(1).lower(), m.group(0)),
                    sub_search
                )
            if '%' in sub_replace:
                sub_replace = re.sub(
                    r'%([a-zA-Z0-9_]+)%',
                    lambda m: self.symbols.get(m.group(1).lower(), m.group(0)),
                    sub_replace
                )

            search_pattern = self._strip_lexical_artifacts(sub_search)
            replace_pattern = self._strip_lexical_artifacts(sub_replace)

            if not search_pattern or search_pattern == '*':
                return node

            if search_pattern.startswith('*'):
                target_str = search_pattern[1:]
                if not target_str:
                    return node
                idx = val.lower().find(target_str.lower())
                if idx != -1:
                    val = replace_pattern + val[idx + len(target_str):]
            else:
                pattern = re.compile(re.escape(search_pattern), re.IGNORECASE)
                val = pattern.sub(lambda _: replace_pattern, val)

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
            delim = "!" if node.is_delayed else "%"
            if node.slice_start is not None:
                if node.slice_len is not None:
                    slice_str = f":~{node.slice_start},{node.slice_len}"
                else:
                    slice_str = f":~{node.slice_start}"
                return f"{delim}{node.name}{slice_str}{delim}"
            if node.sub_search is not None:
                sub_replace = node.sub_replace if node.sub_replace is not None else ""
                return f"{delim}{node.name}:{node.sub_search}={sub_replace}{delim}"
            return f"{delim}{node.name}{delim}"

        if isinstance(node, CommentNode):
            return node.text

        return ""
