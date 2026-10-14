"""
Abstract Syntax Tree (AST) Parser for Windows cmd.exe scripts.
Translates token stream into structured hierarchy of AST nodes.
"""

import re
from typing import List, Optional, Tuple
from .lexer import CmdToken, CmdTokenType, CmdLexer
from .ast_nodes import (
    ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode,
    CommentNode, ParamExpandNode, ForNode, IfNode, LabelNode, GotoNode,
    CallNode, ExitNode
)
from .automaton import PushdownAutomaton
from .statement_parsers import (
    parse_for_statement,
    parse_if_statement,
    parse_set_assignment,
    parse_goto_statement,
    parse_call_statement,
    parse_exit_statement
)


class CmdASTParser:
    """
    Recursive descent parser constructing Abstract Syntax Trees from cmd.exe tokens.
    Handles command chaining (&, &&, ||), pipes (|), and block expressions ( ... ).
    """
    def __init__(self, tokens: List[CmdToken]):
        self.tokens = list(tokens)
        if not self.tokens or self.tokens[-1].type != CmdTokenType.EOF:
            self.tokens.append(CmdToken(CmdTokenType.EOF, '', (0, 0), False))
        self.pos = 0
        self.pda = PushdownAutomaton()

    @classmethod
    def from_source(cls, source: str) -> 'CmdASTParser':
        lexer = CmdLexer(source)
        return cls(lexer.tokenize())

    def peek(self, offset: int = 0) -> CmdToken:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]  # Return EOF

    def advance(self) -> CmdToken:
        if self.pos < len(self.tokens):
            tok = self.tokens[self.pos]
            self.pos += 1
            self.pda.transition(tok)
            return tok
        return self.tokens[-1]

    def match(self, *token_types: CmdTokenType) -> bool:
        if self.peek().type in token_types:
            self.advance()
            return True
        return False

    def skip_whitespace(self):
        """Consumes consecutive whitespace tokens."""
        while self.peek().type == CmdTokenType.WHITESPACE:
            self.advance()

    def parse(self) -> ScriptNode:
        """Parses the entire token stream into a ScriptNode."""
        statements: List[ASTNode] = []

        while self.peek().type != CmdTokenType.EOF:
            # Skip empty newlines and whitespace
            if self.peek().type in (CmdTokenType.NEWLINE, CmdTokenType.WHITESPACE):
                self.advance()
                continue

            # Handle :: or REM comment lines
            val_lower = self.peek().value.strip().lower()
            if val_lower.startswith('::') or val_lower == 'rem':
                comment_parts = []
                while self.peek().type not in (CmdTokenType.NEWLINE, CmdTokenType.EOF):
                    comment_parts.append(self.advance().value)
                statements.append(CommentNode(text="".join(comment_parts).strip()))
                continue

            # Handle label definition lines starting with single ':'
            if val_lower.startswith(':') and not val_lower.startswith('::'):
                label_parts = []
                while self.peek().type not in (CmdTokenType.NEWLINE, CmdTokenType.EOF):
                    label_parts.append(self.advance().value)
                raw_lbl = "".join(label_parts).strip()
                clean_name = raw_lbl.lstrip(':').strip().split()[0] if raw_lbl.lstrip(':').strip() else ""
                statements.append(LabelNode(
                    name=clean_name,
                    is_eof=(clean_name.lower() == 'eof'),
                    raw=raw_lbl
                ))
                continue

            stmt = self.parse_statement()
            if stmt:
                statements.append(stmt)
            else:
                self.advance()

        return ScriptNode(statements=statements)

    def parse_statement(self) -> Optional[ASTNode]:
        """Parses a statement, handling sequential and conditional chaining (&, &&, ||)."""
        self.skip_whitespace()
        left = self.parse_pipeline()
        if not left:
            return None

        while True:
            self.skip_whitespace()
            if self.peek().type in (CmdTokenType.AMP, CmdTokenType.DOUBLE_AMP, CmdTokenType.DOUBLE_PIPE):
                op_tok = self.advance()
                self.skip_whitespace()
                right = self.parse_pipeline()
                if right:
                    left = ChainNode(left=left, operator=op_tok.value, right=right)
            else:
                break

        return left

    def parse_pipeline(self) -> Optional[ASTNode]:
        """Parses piped commands: command | command."""
        self.skip_whitespace()
        left = self.parse_command_or_block()
        if not left:
            return None

        while True:
            self.skip_whitespace()
            if self.peek().type == CmdTokenType.PIPE:
                self.advance()  # Consume '|'
                self.skip_whitespace()
                right = self.parse_command_or_block()
                if right:
                    left = PipeNode(left=left, right=right)
            else:
                break

        return left

    def parse_command_or_block(self) -> Optional[ASTNode]:
        """Parses either a parenthesized block or an individual command."""
        self.skip_whitespace()
        # Block: ( stmt & stmt )
        if self.peek().type == CmdTokenType.LPAREN:
            self.advance()  # Consume '('
            block_statements = []
            while self.peek().type not in (CmdTokenType.RPAREN, CmdTokenType.EOF):
                if self.peek().type in (CmdTokenType.NEWLINE, CmdTokenType.WHITESPACE):
                    self.advance()
                    continue
                stmt = self.parse_statement()
                if stmt:
                    block_statements.append(stmt)
            if self.peek().type == CmdTokenType.RPAREN:
                self.advance()  # Consume ')'
            block_node = BlockNode(statements=block_statements)

            # Check for trailing redirection on block: ( ... ) > out.txt
            trailing_tokens: List[CmdToken] = []
            while self.peek().type not in (
                CmdTokenType.AMP, CmdTokenType.DOUBLE_AMP, CmdTokenType.DOUBLE_PIPE,
                CmdTokenType.PIPE, CmdTokenType.NEWLINE, CmdTokenType.EOF, CmdTokenType.RPAREN
            ):
                trailing_tokens.append(self.advance())
            if trailing_tokens:
                from .redirection.extractor import extract_redirections, build_redirect_tree
                _, block_redirects = extract_redirections(trailing_tokens)
                if block_redirects:
                    return build_redirect_tree(block_node, block_redirects)
            return block_node

        return self.parse_atomic_command()

    def parse_atomic_command(self) -> Optional[ASTNode]:
        """Parses an individual command or variable assignment."""
        self.skip_whitespace()
        tokens_in_cmd: List[CmdToken] = []

        paren_depth = 0
        while True:
            tok = self.peek()
            if paren_depth == 0 and tok.type in (
                CmdTokenType.AMP, CmdTokenType.DOUBLE_AMP, CmdTokenType.DOUBLE_PIPE,
                CmdTokenType.PIPE, CmdTokenType.NEWLINE, CmdTokenType.EOF
            ):
                break
            if tok.type == CmdTokenType.EOF:
                break
            if tok.type == CmdTokenType.LPAREN:
                paren_depth += 1
                tokens_in_cmd.append(self.advance())
                continue
            if tok.type == CmdTokenType.RPAREN:
                if paren_depth > 0:
                    paren_depth -= 1
                    tokens_in_cmd.append(self.advance())
                    continue
                else:
                    break
            tokens_in_cmd.append(self.advance())

        # Strip trailing whitespace tokens
        while tokens_in_cmd and tokens_in_cmd[-1].type == CmdTokenType.WHITESPACE:
            tokens_in_cmd.pop()

        if not tokens_in_cmd:
            return None

        # Check for I/O redirections in command tokens
        from .redirection.extractor import extract_redirections, build_redirect_tree
        clean_tokens, redirect_entries = extract_redirections(tokens_in_cmd)
        while clean_tokens and clean_tokens[0].type == CmdTokenType.WHITESPACE:
            clean_tokens.pop(0)
        while clean_tokens and clean_tokens[-1].type == CmdTokenType.WHITESPACE:
            clean_tokens.pop()

        if not clean_tokens and not redirect_entries:
            return None
        if not clean_tokens:
            return build_redirect_tree(CommandNode(target=""), redirect_entries)

        # Check if this command is a label definition (e.g. inside a block or chain)
        first_val = clean_tokens[0].value.strip().lower()
        if first_val.startswith(':') and not first_val.startswith('::'):
            raw_text = "".join(t.value for t in clean_tokens).strip()
            clean_name = raw_text.lstrip(':').strip().split()[0] if raw_text.lstrip(':').strip() else ""
            base_lbl = LabelNode(
                name=clean_name,
                is_eof=(clean_name.lower() == 'eof'),
                raw=raw_text
            )
            return build_redirect_tree(base_lbl, redirect_entries)

        # Check if this command is a 'SET' statement
        if first_val == 'set' and len(clean_tokens) > 1:
            base_set = self._parse_set_assignment(clean_tokens)
            return build_redirect_tree(base_set, redirect_entries)

        # Check if this command is a 'FOR' loop statement
        if first_val == 'for' and len(clean_tokens) > 1:
            for_node = self._parse_for_statement(clean_tokens)
            if for_node:
                return build_redirect_tree(for_node, redirect_entries)

        # Check if this command is an 'IF' statement
        if first_val == 'if' and len(clean_tokens) > 1:
            if_node = self._parse_if_statement(clean_tokens)
            if if_node:
                return build_redirect_tree(if_node, redirect_entries)

        # Check if this command is a 'GOTO' statement
        if first_val == 'goto' and len(clean_tokens) > 1:
            goto_node = self._parse_goto_statement(clean_tokens)
            if goto_node:
                return build_redirect_tree(goto_node, redirect_entries)

        # Check if this command is a 'CALL' statement
        if first_val == 'call' and len(clean_tokens) > 1:
            call_node = self._parse_call_statement(clean_tokens)
            if call_node:
                return build_redirect_tree(call_node, redirect_entries)

        # Check if this command is an 'EXIT' statement
        if first_val == 'exit':
            base_exit = self._parse_exit_statement(clean_tokens)
            return build_redirect_tree(base_exit, redirect_entries)

        # Separate tokens before first whitespace as target_nodes, and after as arguments
        target_tokens: List[CmdToken] = []
        arg_tokens: List[CmdToken] = []
        seen_whitespace = False

        for tok in clean_tokens:
            if not seen_whitespace:
                if tok.type == CmdTokenType.WHITESPACE:
                    seen_whitespace = True
                else:
                    target_tokens.append(tok)
            else:
                arg_tokens.append(tok)

        target_nodes = [self._token_to_ast_node(t) for t in target_tokens]
        arg_nodes = [self._token_to_ast_node(t) for t in arg_tokens if t.type != CmdTokenType.WHITESPACE or t.in_quote]

        raw_target = "".join(t.value for t in target_tokens)
        base_cmd = CommandNode(target=raw_target, target_nodes=target_nodes, arguments=arg_nodes)
        return build_redirect_tree(base_cmd, redirect_entries)

    def _parse_for_statement(self, tokens: List[CmdToken]) -> Optional[ForNode]:
        """Parses 'FOR [/F | /R | /D | /L] %%i IN (...) DO (...)' statements."""
        return parse_for_statement(tokens, CmdASTParser)

    def _parse_set_assignment(self, tokens: List[CmdToken]) -> AssignmentNode:
        """Parses 'set VAR=VAL' statements with slicing/quote resolution."""
        return parse_set_assignment(tokens, self._token_to_ast_node)

    def _token_to_ast_node(self, tok: CmdToken) -> ASTNode:
        """Converts lexical tokens into AST nodes."""
        if tok.type == CmdTokenType.PERCENT_VAR:
            node = self._parse_var_content(tok.value[1:-1], is_delayed=False)
        elif tok.type == CmdTokenType.EXCLAM_VAR:
            node = self._parse_var_content(tok.value[1:-1], is_delayed=True)
        elif tok.type == CmdTokenType.PARAM_VAR:
            node = self.parse_param_content(tok.value, is_for_var=False)
        elif tok.type == CmdTokenType.FOR_VAR:
            node = self.parse_param_content(tok.value, is_for_var=True)
        elif tok.type == CmdTokenType.CARET:
            # ^x -> x
            unmasked = tok.value[1:] if len(tok.value) > 1 else ''
            node = LiteralNode(value=unmasked, is_quoted=tok.in_quote)
        elif tok.type == CmdTokenType.QUOTE and tok.value == '""':
            # Empty quote collapse
            node = LiteralNode(value='', is_quoted=False)
        else:
            node = LiteralNode(value=tok.value, is_quoted=tok.in_quote)

        node.span = tok.span
        return node

    @staticmethod
    def _split_slice_expr(expr: str) -> List[str]:
        """Splits a slice expression on commas outside nested % or ! variables."""
        parts: List[str] = []
        current: List[str] = []
        in_pct = False
        in_exc = False
        for ch in expr:
            if ch == '%':
                in_pct = not in_pct
                current.append(ch)
            elif ch == '!':
                in_exc = not in_exc
                current.append(ch)
            elif ch == ',' and not in_pct and not in_exc:
                parts.append(''.join(current))
                current = []
            else:
                current.append(ch)
        parts.append(''.join(current))
        return parts

    @staticmethod
    def _parse_slice_param(s_raw: Optional[str], is_start: bool) -> Tuple[Optional[int], Optional[str]]:
        """
        Parses a single slice parameter (start or length).
        Returns (integer_value, raw_expr_if_unresolved).
        """
        if s_raw is None:
            return None, None
        s = s_raw.strip()
        if s == '':
            # Omitted start -> 0, omitted len -> 0
            return (0, None)
        if '%' in s or '!' in s:
            return None, s
        s_clean = re.sub(r'\s+', '', s)
        if s_clean.startswith('+'):
            s_clean = s_clean[1:]
        try:
            return int(s_clean), None
        except ValueError:
            return None, s

    @staticmethod
    def parse_var_content(content: str, is_delayed: bool = False) -> VarExpandNode:
        """Parses variable content into VarExpandNode supporting slicing and substitution."""
        # Substring Slicing: %VAR:~start,len% or !VAR:~start,len!
        if ':~' in content:
            vname, slice_expr = content.split(':~', 1)
            slice_parts = CmdASTParser._split_slice_expr(slice_expr)
            if len(slice_parts) <= 2:
                s_raw = slice_parts[0] if len(slice_parts) > 0 else ""
                has_comma = len(slice_parts) > 1
                l_raw = slice_parts[1] if has_comma else None

                start_val, start_expr = CmdASTParser._parse_slice_param(s_raw, is_start=True)
                if has_comma:
                    len_val, len_expr = CmdASTParser._parse_slice_param(l_raw, is_start=False)
                else:
                    len_val, len_expr = None, None

                return VarExpandNode(
                    name=vname,
                    is_delayed=is_delayed,
                    slice_start=start_val,
                    slice_len=len_val,
                    slice_start_expr=start_expr,
                    slice_len_expr=len_expr
                )

        # String Substitution: %VAR:search=replace% or !VAR:search=replace!
        if ':' in content and '=' in content:
            vname, rest = content.split(':', 1)
            s_search, s_replace = rest.split('=', 1)
            if s_search and s_search != '*':
                return VarExpandNode(name=vname, is_delayed=is_delayed, sub_search=s_search, sub_replace=s_replace)

        return VarExpandNode(name=content, is_delayed=is_delayed)

    def _parse_var_content(self, content: str, is_delayed: bool = False) -> VarExpandNode:
        return self.parse_var_content(content, is_delayed=is_delayed)

    @staticmethod
    def parse_param_content(val: str, is_for_var: bool) -> ParamExpandNode:
        """Parses parameter (%1, %~dp0, %~$PATH:1) or FOR variable (%%i, %%~dpi)."""
        prefix = '%%' if is_for_var else '%'
        raw = val[len(prefix):] if val.startswith(prefix) else val

        if '~' in raw:
            var_name = raw[-1]
            mod_part = raw[:-1]
            from .modifiers import parse_modifiers
            spec = parse_modifiers(mod_part)
            return ParamExpandNode(
                name=var_name,
                is_for_var=is_for_var,
                modifiers=mod_part,
                path_var=spec.search_var,
                strip_quotes=spec.strip_quotes
            )
        else:
            return ParamExpandNode(
                name=raw,
                is_for_var=is_for_var,
                modifiers="",
                path_var=None,
                strip_quotes=False
            )

    def _parse_goto_statement(self, tokens: List[CmdToken]) -> Optional[GotoNode]:
        """Parses 'goto :label' or dynamic 'goto %VAR%' statement."""
        return parse_goto_statement(tokens, self._token_to_ast_node)

    def _parse_call_statement(self, tokens: List[CmdToken]) -> Optional[CallNode]:
        """Parses 'call :label [args...]' or 'call script.bat [args...]'."""
        return parse_call_statement(tokens, self._token_to_ast_node)

    def _parse_exit_statement(self, tokens: List[CmdToken]) -> ExitNode:
        """Parses 'exit [/b] [code]' statement."""
        return parse_exit_statement(tokens)

    def _parse_if_statement(self, tokens: List[CmdToken]) -> Optional[IfNode]:
        """Parses 'IF [NOT] condition ( then ) ELSE ( else )' or single-command IF."""
        return parse_if_statement(tokens, CmdASTParser)


