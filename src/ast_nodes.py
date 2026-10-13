"""
Abstract Syntax Tree (AST) Node Hierarchy for cmd.exe Batch Scripts.
Implements the Visitor Pattern, structural hashing, and serialization.
"""

from typing import List, Optional, Any, Dict
from dataclasses import dataclass, field


class ASTVisitor:
    """Base visitor interface for traversing and transforming cmd.exe AST trees."""
    def visit(self, node: 'ASTNode') -> Any:
        method_name = f'visit_{node.__class__.__name__}'
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node: 'ASTNode') -> Any:
        raise NotImplementedError(f"No visit_{node.__class__.__name__} method defined.")


@dataclass
class ASTNode:
    """Base class for all Abstract Syntax Tree nodes."""
    span: tuple = (0, 0)  # (start_char, end_char)

    def accept(self, visitor: ASTVisitor) -> Any:
        return visitor.visit(self)

    def to_dict(self) -> Dict[str, Any]:
        result = {"node_type": self.__class__.__name__}
        for k, v in self.__dict__.items():
            if isinstance(v, ASTNode):
                result[k] = v.to_dict()
            elif isinstance(v, list) and all(isinstance(x, ASTNode) for x in v):
                result[k] = [x.to_dict() for x in v]
            else:
                result[k] = v
        return result


@dataclass
class LiteralNode(ASTNode):
    """Raw text literal token."""
    value: str = ""
    is_quoted: bool = False
    is_folded_slice: bool = False


@dataclass
class CommentNode(ASTNode):
    """Comment line starting with :: or REM."""
    text: str = ""


@dataclass
class VarExpandNode(ASTNode):
    """
    Environment variable expansion token.
    Supports %VAR%, !VAR!, slicing %VAR:~start,len%, and substitution %VAR:old=new%.
    """
    name: str = ""
    is_delayed: bool = False  # True if !VAR!
    slice_start: Optional[int] = None
    slice_len: Optional[int] = None
    sub_search: Optional[str] = None
    sub_replace: Optional[str] = None
    slice_start_expr: Optional[str] = None
    slice_len_expr: Optional[str] = None


@dataclass
class ParamExpandNode(ASTNode):
    """
    Positional script parameter (%0..%9, %*) or FOR loop variable (%%i..%%z).
    Supports cmd.exe path and attribute modifiers (e.g., %~dp0, %%~fI, %~$PATH:1).
    """
    name: str = ""
    is_for_var: bool = False
    modifiers: str = ""
    path_var: Optional[str] = None
    strip_quotes: bool = False


@dataclass
class AssignmentNode(ASTNode):
    """Represents a variable assignment statement (e.g., set VAR=VAL or set /a)."""
    var_name: str = ""
    value_nodes: List[ASTNode] = field(default_factory=list)
    raw_value: str = ""
    is_arithmetic: bool = False


@dataclass
class CommandNode(ASTNode):
    """Single executable command with arguments."""
    target: str = ""
    target_nodes: List[ASTNode] = field(default_factory=list)
    arguments: List[ASTNode] = field(default_factory=list)


@dataclass
class PipeNode(ASTNode):
    """Piped execution node: left | right."""
    left: ASTNode = field(default_factory=ASTNode)
    right: ASTNode = field(default_factory=ASTNode)


@dataclass
class ChainNode(ASTNode):
    """Chained statements: & (sequential), && (on-success), || (on-failure)."""
    left: ASTNode = field(default_factory=ASTNode)
    operator: str = "&"  # '&', '&&', '||'
    right: ASTNode = field(default_factory=ASTNode)


@dataclass
class RedirectNode(ASTNode):
    """Stream redirection: target_cmd > out.txt, 2>&1, < in.txt."""
    command: ASTNode = field(default_factory=ASTNode)
    stream: str = ">"  # '>', '>>', '<', '2>&1'
    destination: str = ""


@dataclass
class BlockNode(ASTNode):
    """Grouped compound block enclosed in parentheses: ( cmd1 & cmd2 )."""
    statements: List[ASTNode] = field(default_factory=list)


@dataclass
class IfNode(ASTNode):
    """Conditional branching statement: IF [NOT] condition ( ... ) ELSE ( ... )."""
    condition: str = ""
    then_block: ASTNode = field(default_factory=ASTNode)
    else_block: Optional[ASTNode] = None


@dataclass
class ForNode(ASTNode):
    """Iterative loop: FOR [/F | /R | /D | /L] %%i IN (...) DO (...)."""
    iterator: str = ""
    flags: str = ""
    options: str = ""
    in_clause: str = ""
    body: ASTNode = field(default_factory=ASTNode)


@dataclass
class LabelNode(ASTNode):
    """
    Batch script label definition (e.g., :label_name, :EOF).
    In cmd.exe, label names are case-insensitive.
    """
    name: str = ""
    is_eof: bool = False
    raw: str = ""


@dataclass
class GotoNode(ASTNode):
    """
    Batch jump statement (e.g., goto :label, goto %TARGET%, goto :EOF).
    Can target static labels or dynamic expressions.
    """
    target: str = ""
    target_nodes: List[ASTNode] = field(default_factory=list)
    is_eof: bool = False
    is_dynamic: bool = False


@dataclass
class CallNode(ASTNode):
    """
    Batch subroutine or script invocation (e.g., call :subroutine [args...], call other.bat [args...]).
    Distinguishes internal label calls from external script execution.
    """
    target: str = ""
    target_nodes: List[ASTNode] = field(default_factory=list)
    arguments: List[ASTNode] = field(default_factory=list)
    is_subroutine: bool = False
    is_dynamic: bool = False


@dataclass
class ExitNode(ASTNode):
    """
    Script termination or subroutine return statement (e.g., exit /b 0, exit 1).
    When is_batch_return is True (/b flag), exits the current subroutine or batch context.
    """
    is_batch_return: bool = False
    exit_code: Optional[str] = None


@dataclass
class ScriptNode(ASTNode):
    """Root node representing an entire batch file or script block."""
    statements: List[ASTNode] = field(default_factory=list)
