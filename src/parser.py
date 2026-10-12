"""
Abstract Syntax Tree (AST) Parser for Windows cmd.exe scripts.
Translates token stream into structured hierarchy of AST nodes.
"""

import re
from typing import List, Optional, Tuple
from .lexer import CmdToken, CmdTokenType, CmdLexer
from .ast_nodes import (
    ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode, CommentNode
)
from .automaton import PushdownAutomaton


class CmdASTParser:
    """
    Recursive descent parser constructing Abstract Syntax Trees from cmd.exe tokens.
    Handles command chaining (&, &&, ||), pipes (|), and block expressions ( ... ).
    """
    def __init__(self, tokens: List[CmdToken]):
        self.tokens = tokens
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
        tok = self.tokens[self.pos]
        self.pos += 1
        self.pda.transition(tok)
        return tok

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
            return BlockNode(statements=block_statements)

        return self.parse_atomic_command()

    def parse_atomic_command(self) -> Optional[ASTNode]:
        """Parses an individual command or variable assignment."""
        self.skip_whitespace()
        tokens_in_cmd: List[CmdToken] = []

        terminators = {
            CmdTokenType.AMP, CmdTokenType.DOUBLE_AMP, CmdTokenType.DOUBLE_PIPE,
            CmdTokenType.PIPE, CmdTokenType.NEWLINE, CmdTokenType.EOF, CmdTokenType.RPAREN
        }

        while self.peek().type not in terminators:
            tokens_in_cmd.append(self.advance())

        # Strip trailing whitespace tokens
        while tokens_in_cmd and tokens_in_cmd[-1].type == CmdTokenType.WHITESPACE:
            tokens_in_cmd.pop()

        if not tokens_in_cmd:
            return None

        # Check if this command is a 'SET' statement
        first_val = tokens_in_cmd[0].value.strip().lower()
        if first_val == 'set' and len(tokens_in_cmd) > 1:
            return self._parse_set_assignment(tokens_in_cmd)

        # Separate tokens before first whitespace as target_nodes, and after as arguments
        target_tokens: List[CmdToken] = []
        arg_tokens: List[CmdToken] = []
        seen_whitespace = False

        for tok in tokens_in_cmd:
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
        return CommandNode(target=raw_target, target_nodes=target_nodes, arguments=arg_nodes)

    def _parse_set_assignment(self, tokens: List[CmdToken]) -> AssignmentNode:
        """Parses 'set VAR=VAL' statements with slicing/quote resolution."""
        # Combine all subsequent tokens into raw assignment text
        raw_tail = "".join(t.value for t in tokens[1:]).strip()
        
        # Strip outer quotes if format is set "VAR=VAL"
        is_enclosed_quotes = False
        if raw_tail.startswith('"') and raw_tail.endswith('"'):
            raw_tail = raw_tail[1:-1]
            is_enclosed_quotes = True

        if '=' in raw_tail:
            var_name, var_val = raw_tail.split('=', 1)
        else:
            var_name, var_val = raw_tail, ""

        # Extract tokens occurring after '='
        val_tokens: List[CmdToken] = []
        found_eq = False
        for t in tokens[1:]:
            if found_eq:
                val_tokens.append(t)
            elif t.type == CmdTokenType.EQUALS:
                found_eq = True
            elif '=' in t.value:
                found_eq = True
                _, after_eq = t.value.split('=', 1)
                if after_eq:
                    val_tokens.append(CmdToken(CmdTokenType.LITERAL, after_eq, t.span, t.in_quote))

        if is_enclosed_quotes:
            while val_tokens and (val_tokens[-1].type == CmdTokenType.QUOTE or val_tokens[-1].value == '"'):
                val_tokens.pop()

        value_nodes: List[ASTNode] = []
        for t in val_tokens:
            if t.type == CmdTokenType.EOF:
                continue
            if t.type == CmdTokenType.WHITESPACE and not t.in_quote:
                continue
            value_nodes.append(self._token_to_ast_node(t))

        if not value_nodes and var_val:
            value_nodes = [LiteralNode(value=var_val)]

        return AssignmentNode(
            var_name=var_name.strip(),
            raw_value=var_val,
            value_nodes=value_nodes
        )

    def _token_to_ast_node(self, tok: CmdToken) -> ASTNode:
        """Converts lexical tokens into AST nodes."""
        if tok.type == CmdTokenType.PERCENT_VAR:
            node = self._parse_var_content(tok.value[1:-1], is_delayed=False)
        elif tok.type == CmdTokenType.EXCLAM_VAR:
            node = self._parse_var_content(tok.value[1:-1], is_delayed=True)
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
