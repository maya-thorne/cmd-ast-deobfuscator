"""
Lexer and Recursive Descent Parser for cmd.exe Arithmetic Expressions.
Implements exact cmd.exe operator precedence, number formats (decimal, hex, octal),
unary operators, bitwise shifts, compound assignments, and comma sequencing.
"""

import re
from typing import List, Optional, Tuple
from .models import (
    ArithmeticNode, NumberNode, VariableNode, UnaryOpNode,
    BinaryOpNode, AssignmentOpNode, SequenceNode
)


class TokenType:
    NUMBER = "NUMBER"
    IDENT = "IDENT"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    COMMA = "COMMA"
    ASSIGN = "ASSIGN"          # =, +=, -=, *=, /=, %=, &=, ^=, |=, <<=, >>=
    BINARY_OP = "BINARY_OP"    # *, /, %, +, -, <<, >>, &, ^, |
    UNARY_OP = "UNARY_OP"      # ~, !
    EOF = "EOF"


class Token:
    __slots__ = ('type', 'value', 'pos')

    def __init__(self, type_: str, value: str, pos: int = 0):
        self.type = type_
        self.value = value
        self.pos = pos

    def __repr__(self) -> str:
        return f"Token({self.type}, {self.value!r})"


class ArithmeticLexer:
    """Tokenizes cmd.exe arithmetic expressions with caret and quote normalization."""

    ASSIGN_OPS = ('<<=', '>>=', '+=', '-=', '*=', '/=', '%=', '&=', '^=', '|=', '=')
    TWO_CHAR_OPS = ('<<', '>>')
    SINGLE_CHAR_OPS = ('+', '-', '*', '/', '%', '&', '^', '|', '~', '!', '(', ')', ',')

    def __init__(self, text: str):
        self.raw_text = text
        self.text = self._pre_process(text)
        self.pos = 0
        self.length = len(self.text)

    def _pre_process(self, text: str) -> str:
        """Strips surrounding quotes and unmasks carets outside literals."""
        cleaned = text.strip()
        # Collapse multiple carets: ^& -> &, ^| -> |, ^^ -> ^
        cleaned = re.sub(r'\^{2,}', '^', cleaned)
        cleaned = re.sub(r'\^([&|^<>()%+*~!=,])', r'\1', cleaned)
        # Strip enclosing double quotes if present
        if cleaned.startswith('"') and cleaned.endswith('"') and len(cleaned) >= 2:
            cleaned = cleaned[1:-1].strip()
        # Remove inner quotes around subexpressions
        cleaned = cleaned.replace('"', '')
        return cleaned

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while self.pos < self.length:
            ch = self.text[self.pos]

            if ch.isspace():
                self.pos += 1
                continue

            # Check multi-character assignment operators
            matched_assign = False
            for op in self.ASSIGN_OPS:
                if self.text.startswith(op, self.pos):
                    tokens.append(Token(TokenType.ASSIGN, op, self.pos))
                    self.pos += len(op)
                    matched_assign = True
                    break
            if matched_assign:
                continue

            # Check two-character shift operators (<<, >>)
            matched_shift = False
            for op in self.TWO_CHAR_OPS:
                if self.text.startswith(op, self.pos):
                    tokens.append(Token(TokenType.BINARY_OP, op, self.pos))
                    self.pos += len(op)
                    matched_shift = True
                    break
            if matched_shift:
                continue

            # Parentheses and comma
            if ch == '(':
                tokens.append(Token(TokenType.LPAREN, '(', self.pos))
                self.pos += 1
                continue
            if ch == ')':
                tokens.append(Token(TokenType.RPAREN, ')', self.pos))
                self.pos += 1
                continue
            if ch == ',':
                tokens.append(Token(TokenType.COMMA, ',', self.pos))
                self.pos += 1
                continue

            # Variable expansions (%VAR% or !VAR!)
            if ch in ('%', '!'):
                var_match = re.match(r'([%!])([a-zA-Z0-9_#$@.-]+)\1', self.text[self.pos:])
                if var_match:
                    var_name = var_match.group(2)
                    tokens.append(Token(TokenType.IDENT, var_name, self.pos))
                    self.pos += len(var_match.group(0))
                    continue

            # Bitwise unary ops: ~, !
            if ch in ('~', '!'):
                tokens.append(Token(TokenType.UNARY_OP, ch, self.pos))
                self.pos += 1
                continue

            # Standard arithmetic binary/unary candidates (+, -, *, /, %, &, ^, |)
            if ch in ('+', '-', '*', '/', '%', '&', '^', '|'):
                tokens.append(Token(TokenType.BINARY_OP, ch, self.pos))
                self.pos += 1
                continue

            # Numbers: Hex (0x/0X), Octal (0...), Decimal
            if ch.isdigit():
                start = self.pos
                if ch == '0' and self.pos + 1 < self.length and self.text[self.pos + 1] in 'xX':
                    self.pos += 2
                    while self.pos < self.length and self.text[self.pos] in '0123456789abcdefABCDEF':
                        self.pos += 1
                else:
                    while self.pos < self.length and (self.text[self.pos].isdigit() or self.text[self.pos] in 'xXabcdefABCDEF'):
                        self.pos += 1
                num_str = self.text[start:self.pos]
                tokens.append(Token(TokenType.NUMBER, num_str, start))
                continue

            # Identifiers and variable expansions (%VAR% or !VAR! or bare name)
            if ch == '%' or ch == '!':
                delim = ch
                start = self.pos
                self.pos += 1
                end = self.text.find(delim, self.pos)
                if end != -1:
                    var_name = self.text[self.pos:end]
                    self.pos = end + 1
                    tokens.append(Token(TokenType.IDENT, var_name, start))
                    continue
                else:
                    # Unclosed percent or exclam, treat bare
                    tokens.append(Token(TokenType.IDENT, ch, start))
                    continue

            if ch.isalpha() or ch in '_#$@.':
                start = self.pos
                while self.pos < self.length and (self.text[self.pos].isalnum() or self.text[self.pos] in '_#$@.'):
                    self.pos += 1
                var_name = self.text[start:self.pos]
                tokens.append(Token(TokenType.IDENT, var_name, start))
                continue

            # Fallback single unknown char
            tokens.append(Token(TokenType.BINARY_OP, ch, self.pos))
            self.pos += 1

        tokens.append(Token(TokenType.EOF, '', self.pos))
        return tokens


class ArithmeticParser:
    """
    Recursive descent parser constructing an ArithmeticNode AST hierarchy
    with exact cmd.exe operator precedence.
    """

    def __init__(self, text: str):
        lexer = ArithmeticLexer(text)
        self.tokens = lexer.tokenize()
        self.idx = 0

    @property
    def current(self) -> Token:
        if self.idx < len(self.tokens):
            return self.tokens[self.idx]
        return Token(TokenType.EOF, '')

    def peek(self, offset: int = 1) -> Token:
        pos = self.idx + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return Token(TokenType.EOF, '')

    def consume(self, expected_type: Optional[str] = None) -> Token:
        tok = self.current
        if expected_type and tok.type != expected_type:
            pass
        if self.idx < len(self.tokens):
            self.idx += 1
        return tok

    def parse(self) -> ArithmeticNode:
        """Parses the entire token stream into an ArithmeticNode tree."""
        if self.current.type == TokenType.EOF:
            return NumberNode(value=0, raw="0")
        node = self.parse_sequence()
        return node

    def parse_sequence(self) -> ArithmeticNode:
        """Parses comma-separated expressions (e.g., 'a=1, b=2, c=a+b')."""
        exprs: List[ArithmeticNode] = [self.parse_assignment()]
        while self.current.type == TokenType.COMMA:
            self.consume(TokenType.COMMA)
            exprs.append(self.parse_assignment())
        if len(exprs) == 1:
            return exprs[0]
        return SequenceNode(expressions=exprs)

    def parse_assignment(self) -> ArithmeticNode:
        """
        Parses assignment expressions (=, +=, -=, *=, /=, %=, &=, ^=, |=, <<=, >>=).
        Assignments in cmd.exe are right-associative (e.g., a = b = 10).
        """
        if self.current.type == TokenType.IDENT and self.peek().type == TokenType.ASSIGN:
            target_tok = self.consume(TokenType.IDENT)
            op_tok = self.consume(TokenType.ASSIGN)
            val_node = self.parse_assignment()
            return AssignmentOpNode(target=target_tok.value, operator=op_tok.value, value=val_node)

        return self.parse_bitwise_or()

    def parse_bitwise_or(self) -> ArithmeticNode:
        """Precedence level 1: | (bitwise OR)."""
        left = self.parse_bitwise_xor()
        while self.current.type == TokenType.BINARY_OP and self.current.value == '|':
            op = self.consume().value
            right = self.parse_bitwise_xor()
            left = BinaryOpNode(left=left, operator=op, right=right)
        return left

    def parse_bitwise_xor(self) -> ArithmeticNode:
        """Precedence level 2: ^ (bitwise XOR)."""
        left = self.parse_bitwise_and()
        while self.current.type == TokenType.BINARY_OP and self.current.value == '^':
            op = self.consume().value
            right = self.parse_bitwise_and()
            left = BinaryOpNode(left=left, operator=op, right=right)
        return left

    def parse_bitwise_and(self) -> ArithmeticNode:
        """Precedence level 3: & (bitwise AND)."""
        left = self.parse_shifts()
        while self.current.type == TokenType.BINARY_OP and self.current.value == '&':
            op = self.consume().value
            right = self.parse_shifts()
            left = BinaryOpNode(left=left, operator=op, right=right)
        return left

    def parse_shifts(self) -> ArithmeticNode:
        """Precedence level 4: <<, >> (bitwise shifts)."""
        left = self.parse_additive()
        while self.current.type == TokenType.BINARY_OP and self.current.value in ('<<', '>>'):
            op = self.consume().value
            right = self.parse_additive()
            left = BinaryOpNode(left=left, operator=op, right=right)
        return left

    def parse_additive(self) -> ArithmeticNode:
        """Precedence level 5: +, - (addition and subtraction)."""
        left = self.parse_multiplicative()
        while self.current.type == TokenType.BINARY_OP and self.current.value in ('+', '-'):
            op = self.consume().value
            right = self.parse_multiplicative()
            left = BinaryOpNode(left=left, operator=op, right=right)
        return left

    def parse_multiplicative(self) -> ArithmeticNode:
        """Precedence level 6: *, /, % (multiplication, division, modulus)."""
        left = self.parse_unary()
        while self.current.type == TokenType.BINARY_OP and self.current.value in ('*', '/', '%'):
            op = self.consume().value
            right = self.parse_unary()
            left = BinaryOpNode(left=left, operator=op, right=right)
        return left

    def parse_unary(self) -> ArithmeticNode:
        """Precedence level 7: unary +, -, ~, !."""
        if self.current.type == TokenType.UNARY_OP:
            op = self.consume().value
            operand = self.parse_unary()
            return UnaryOpNode(operator=op, operand=operand)
        if self.current.type == TokenType.BINARY_OP and self.current.value in ('+', '-'):
            op = self.consume().value
            operand = self.parse_unary()
            return UnaryOpNode(operator=op, operand=operand)
        return self.parse_primary()

    def parse_primary(self) -> ArithmeticNode:
        """Primary expressions: grouping '()', number literal, variable reference."""
        tok = self.current

        if tok.type == TokenType.LPAREN:
            self.consume(TokenType.LPAREN)
            node = self.parse_sequence()
            if self.current.type == TokenType.RPAREN:
                self.consume(TokenType.RPAREN)
            return node

        if tok.type == TokenType.NUMBER:
            self.consume(TokenType.NUMBER)
            val = self._parse_number(tok.value)
            return NumberNode(value=val, raw=tok.value)

        if tok.type == TokenType.IDENT:
            self.consume(TokenType.IDENT)
            return VariableNode(name=tok.value)

        # Fallback for unexpected or missing token
        self.consume()
        return NumberNode(value=0, raw="0")

    @staticmethod
    def _parse_number(raw: str) -> int:
        """Parses hex, octal, or decimal integer strings safely."""
        raw_s = raw.strip()
        if not raw_s:
            return 0
        try:
            if raw_s.startswith(('0x', '0X')):
                return int(raw_s, 16)
            if raw_s.startswith('0') and len(raw_s) > 1:
                # Octal validation
                if all(c in '01234567' for c in raw_s):
                    return int(raw_s, 8)
                return int(raw_s, 10)
            return int(raw_s, 10)
        except ValueError:
            return 0
