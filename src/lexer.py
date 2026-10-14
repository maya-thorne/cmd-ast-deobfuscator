"""
Lexical Analyzer (Lexer) for cmd.exe Batch Scripts.
Emulates Phase 1 and Phase 2 character scanning with quote and escape tracking.
"""

import re
from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional


class CmdTokenType(Enum):
    LITERAL = auto()
    CARET = auto()
    QUOTE = auto()
    PERCENT_VAR = auto()
    PARAM_VAR = auto()
    FOR_VAR = auto()
    EXCLAM_VAR = auto()
    PIPE = auto()
    AMP = auto()
    DOUBLE_AMP = auto()
    DOUBLE_PIPE = auto()
    LPAREN = auto()
    RPAREN = auto()
    REDIRECT_OUT = auto()
    REDIRECT_APPEND = auto()
    REDIRECT_IN = auto()
    REDIRECT_DUP = auto()
    EQUALS = auto()
    WHITESPACE = auto()
    NEWLINE = auto()
    EOF = auto()


@dataclass
class CmdToken:
    type: CmdTokenType
    value: str
    span: tuple  # (start, end)
    in_quote: bool = False

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, quote={self.in_quote})"


class CmdLexer:
    """
    Lexer for Windows Command Processor (cmd.exe) syntax.
    Accurately tracks quote transitions, caret escapes, and environment variable delimiters.
    """
    def __init__(self, source: str):
        # Preprocessing: Strip BOM and normalize line endings
        if source.startswith('\ufeff'):
            source = source[1:]
        self.source = source.replace('\r\n', '\n').replace('\r', '\n')
        self.pos = 0
        self.length = len(self.source)
        self.in_quote = False

    def peek(self, offset: int = 0) -> Optional[str]:
        idx = self.pos + offset
        if idx < self.length:
            return self.source[idx]
        return None

    def advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        return ch

    def tokenize(self) -> List[CmdToken]:
        tokens: List[CmdToken] = []

        while self.pos < self.length:
            start_pos = self.pos
            ch = self.peek()

            # Newlines
            if ch == '\n':
                self.advance()
                tokens.append(CmdToken(CmdTokenType.NEWLINE, '\n', (start_pos, self.pos), self.in_quote))
                self.in_quote = False  # Newline resets quote state in unclosed cmd line
                continue

            # Whitespace outside quotes
            if ch in (' ', '\t') and not self.in_quote:
                ws_chars = []
                while self.pos < self.length and self.peek() in (' ', '\t') and not self.in_quote:
                    ws_chars.append(self.advance())
                tokens.append(CmdToken(CmdTokenType.WHITESPACE, ''.join(ws_chars), (start_pos, self.pos), False))
                continue

            # Double Quotes toggle
            if ch == '"':
                self.advance()
                # Empty double quotes detection: ""
                if self.peek() == '"':
                    self.advance()
                    tokens.append(CmdToken(CmdTokenType.QUOTE, '""', (start_pos, self.pos), self.in_quote))
                else:
                    self.in_quote = not self.in_quote
                    tokens.append(CmdToken(CmdTokenType.QUOTE, '"', (start_pos, self.pos), self.in_quote))
                continue

            # Caret Escape (Phase 1)
            if ch == '^':
                if not self.in_quote or self.peek(1) == '!':
                    self.advance()
                    escaped_char = self.advance() if self.pos < self.length else ''
                    tokens.append(CmdToken(CmdTokenType.CARET, f"^{escaped_char}", (start_pos, self.pos), self.in_quote))
                    continue

            # Percent Environment Variable (Phase 2)
            if ch == '%':
                var_token = self._lex_percent_var()
                if var_token:
                    tokens.append(var_token)
                    continue

            # Delayed Expansion Variable (Phase 4)
            if ch == '!':
                var_token = self._lex_exclam_var()
                if var_token:
                    tokens.append(var_token)
                    continue

            # Delimiters and Operators outside quotes
            if not self.in_quote:
                if ch == '|':
                    self.advance()
                    if self.peek() == '|':
                        self.advance()
                        tokens.append(CmdToken(CmdTokenType.DOUBLE_PIPE, '||', (start_pos, self.pos), False))
                    else:
                        tokens.append(CmdToken(CmdTokenType.PIPE, '|', (start_pos, self.pos), False))
                    continue

                if ch == '&':
                    self.advance()
                    if self.peek() == '&':
                        self.advance()
                        tokens.append(CmdToken(CmdTokenType.DOUBLE_AMP, '&&', (start_pos, self.pos), False))
                    else:
                        tokens.append(CmdToken(CmdTokenType.AMP, '&', (start_pos, self.pos), False))
                    continue

                if ch == '(':
                    self.advance()
                    tokens.append(CmdToken(CmdTokenType.LPAREN, '(', (start_pos, self.pos), False))
                    continue

                if ch == ')':
                    self.advance()
                    tokens.append(CmdToken(CmdTokenType.RPAREN, ')', (start_pos, self.pos), False))
                    continue

                if ch == '>':
                    self.advance()
                    if self.peek() == '>':
                        self.advance()
                        tokens.append(CmdToken(CmdTokenType.REDIRECT_APPEND, '>>', (start_pos, self.pos), False))
                    elif self.peek() == '&':
                        self.advance()
                        tokens.append(CmdToken(CmdTokenType.REDIRECT_DUP, '>&', (start_pos, self.pos), False))
                    else:
                        tokens.append(CmdToken(CmdTokenType.REDIRECT_OUT, '>', (start_pos, self.pos), False))
                    continue

                if ch == '<':
                    self.advance()
                    if self.peek() == '&':
                        self.advance()
                        tokens.append(CmdToken(CmdTokenType.REDIRECT_DUP, '<&', (start_pos, self.pos), False))
                    elif self.peek() == '<':
                        self.advance()
                        tokens.append(CmdToken(CmdTokenType.REDIRECT_IN, '<<', (start_pos, self.pos), False))
                    else:
                        tokens.append(CmdToken(CmdTokenType.REDIRECT_IN, '<', (start_pos, self.pos), False))
                    continue

                if ch == '=':
                    self.advance()
                    tokens.append(CmdToken(CmdTokenType.EQUALS, '=', (start_pos, self.pos), False))
                    continue

            # Literals and whitespace
            literal = self._lex_literal()
            tokens.append(CmdToken(CmdTokenType.LITERAL, literal, (start_pos, self.pos), self.in_quote))

        tokens.append(CmdToken(CmdTokenType.EOF, '', (self.pos, self.pos), self.in_quote))
        return tokens

    def _lex_percent_var(self) -> Optional[CmdToken]:
        start = self.pos
        rem = self.source[start:]

        # 1. Double percent %%: FOR loop variable or escaped %%
        if rem.startswith('%%'):
            # Check for FOR variable with modifiers: %%~...
            m_for_mod = re.match(r'^%%~(?:\$[a-zA-Z0-9_]+:)?[fdpnxsatzFDPNXSATZ]*([a-zA-Z0-9])', rem)
            if m_for_mod:
                val = m_for_mod.group(0)
                self.pos += len(val)
                return CmdToken(CmdTokenType.FOR_VAR, val, (start, self.pos), self.in_quote)

            # Check for standard single-letter FOR variable: %%i, %%I, %%a
            if len(rem) >= 3 and rem[2].isalpha():
                val = rem[:3]
                self.pos += 3
                return CmdToken(CmdTokenType.FOR_VAR, val, (start, self.pos), self.in_quote)

            # Escaped literal %%
            self.pos += 2
            return CmdToken(CmdTokenType.LITERAL, '%%', (start, self.pos), self.in_quote)

        # 2. Positional parameter with modifiers: %~dp0, %~f1, %~$PATH:1, %~1
        m_param_mod = re.match(r'^%~(?:\$[a-zA-Z0-9_]+:)?[fdpnxsatzFDPNXSATZ]*([0-9*]|[a-zA-Z])', rem)
        if m_param_mod:
            val = m_param_mod.group(0)
            self.pos += len(val)
            return CmdToken(CmdTokenType.PARAM_VAR, val, (start, self.pos), self.in_quote)

        # 3. Positional parameter without modifiers: %0..%9, %*
        if len(rem) >= 2 and (rem[1].isdigit() or rem[1] == '*'):
            # Only treat as environment variable if format is %1abc% (alphanumeric name with closing %)
            is_env_var = False
            if len(rem) >= 3 and rem[2].isalnum() and '%' in rem[2:]:
                is_env_var = True

            if not is_env_var:
                val = rem[:2]
                self.pos += 2
                return CmdToken(CmdTokenType.PARAM_VAR, val, (start, self.pos), self.in_quote)

        # 4. Standard Environment Variable: %VAR%, %VAR:~s,l%, %VAR:search=replace%
        self.advance()  # Skip initial '%'
        var_content = []
        in_nested_var = False

        while self.pos < self.length:
            c = self.advance()
            if c == '%':
                content_str = ''.join(var_content)
                if in_nested_var:
                    # Closing a nested %VAR%
                    in_nested_var = False
                    var_content.append(c)
                    continue
                elif ':~' in content_str:
                    # Check if this % begins a nested variable parameter e.g. %OFF%
                    remainder = self.source[self.pos:]
                    m = re.match(r'^[a-zA-Z0-9_\-\.\:\$]+%(?:[,\s%&|<>!]|$)', remainder)
                    if m and '%' in remainder:
                        in_nested_var = True
                        var_content.append(c)
                        continue

                val = f"%{''.join(var_content)}%"
                return CmdToken(CmdTokenType.PERCENT_VAR, val, (start, self.pos), self.in_quote)
            if c == '\n' or c == '"':
                break
            if c in (' ', '\t') and not self.in_quote and ':' not in var_content:
                # Malformed percent, backtrack or treat as literal
                break
            var_content.append(c)

        # Unclosed %, rewind
        self.pos = start + 1
        return CmdToken(CmdTokenType.LITERAL, '%', (start, start + 1), self.in_quote)

    def _lex_exclam_var(self) -> Optional[CmdToken]:
        start = self.pos
        self.advance()  # Skip initial '!'

        var_content = []
        while self.pos < self.length:
            c = self.peek()
            if c == '\n' or c == '"':
                break
            if c == '^':
                self.advance()
                if self.pos < self.length:
                    next_c = self.advance()
                    if next_c == '\n':
                        break
                    var_content.append(f"^{next_c}")
                else:
                    var_content.append('^')
                continue
            if c == '!':
                self.advance()
                val = f"!{''.join(var_content)}!"
                return CmdToken(CmdTokenType.EXCLAM_VAR, val, (start, self.pos), self.in_quote)
            if not self.in_quote and c in ('&', '|', '<', '>', '(', ')'):
                break
            var_content.append(self.advance())

        self.pos = start + 1
        return CmdToken(CmdTokenType.LITERAL, '!', (start, start + 1), self.in_quote)

    def _lex_literal(self) -> str:
        chars = []
        special_chars = {'\n', '"', '^', '%', '!', '|', '&', '(', ')', '>', '<', '=', ' ', '\t'}

        while self.pos < self.length:
            ch = self.peek()
            if not self.in_quote and ch in special_chars:
                break
            if self.in_quote:
                if ch in ('\n', '"', '%', '!'):
                    break
                if ch == '^' and self.peek(1) == '!':
                    break
            chars.append(self.advance())

        return ''.join(chars)
