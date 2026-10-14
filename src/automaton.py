"""
Pushdown Automaton (PDA) State Machine Specification for cmd.exe.
Models state transitions, nested compound blocks, and token stream reduction.
"""

from enum import Enum, auto
from typing import List, Optional
from .lexer import CmdToken, CmdTokenType


class AutomatonState(Enum):
    START = auto()
    IN_COMMAND = auto()
    IN_ARGUMENTS = auto()
    IN_SET_NAME = auto()
    IN_SET_VALUE = auto()
    IN_BLOCK = auto()
    IN_PIPE = auto()
    IN_REDIRECT = auto()
    TERMINAL = auto()


class PushdownAutomaton:
    """
    Formal pushdown automaton maintaining a state machine and bracket stack
    for syntactically validated batch script parsing.
    """
    def __init__(self):
        self.state = AutomatonState.START
        self.stack: List[str] = []  # Stack for '(' markers and block frames
        self.history: List[AutomatonState] = []

    def current_state(self) -> AutomatonState:
        return self.state

    def depth(self) -> int:
        return len(self.stack)

    def transition(self, token: CmdToken) -> AutomatonState:
        """Computes next state given the current token and stack symbol."""
        prev = self.state
        self.history.append(prev)

        if token.type == CmdTokenType.WHITESPACE:
            return self.state

        if token.type == CmdTokenType.LPAREN:
            self.stack.append('(')
            self.state = AutomatonState.IN_BLOCK
            return self.state

        if token.type == CmdTokenType.RPAREN:
            if self.stack and self.stack[-1] == '(':
                self.stack.pop()
            self.state = AutomatonState.IN_COMMAND if not self.stack else AutomatonState.IN_BLOCK
            return self.state

        if token.type == CmdTokenType.PIPE:
            self.state = AutomatonState.IN_PIPE
            return self.state

        if token.type in (CmdTokenType.REDIRECT_OUT, CmdTokenType.REDIRECT_APPEND, CmdTokenType.REDIRECT_IN, CmdTokenType.REDIRECT_DUP):
            self.state = AutomatonState.IN_REDIRECT
            return self.state

        if token.type in (CmdTokenType.AMP, CmdTokenType.DOUBLE_AMP, CmdTokenType.DOUBLE_PIPE, CmdTokenType.NEWLINE):
            self.state = AutomatonState.START
            return self.state

        if token.type == CmdTokenType.EOF:
            self.state = AutomatonState.TERMINAL
            return self.state

        # Command & Arguments transitions
        if self.state in (AutomatonState.START, AutomatonState.IN_PIPE):
            cleaned = token.value.strip().lower()
            if cleaned == 'set':
                self.state = AutomatonState.IN_SET_NAME
            else:
                self.state = AutomatonState.IN_COMMAND
            return self.state

        if self.state == AutomatonState.IN_SET_NAME and token.type == CmdTokenType.EQUALS:
            self.state = AutomatonState.IN_SET_VALUE
            return self.state

        if self.state == AutomatonState.IN_COMMAND:
            self.state = AutomatonState.IN_ARGUMENTS
            return self.state

        return self.state
