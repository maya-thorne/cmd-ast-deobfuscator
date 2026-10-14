"""
Intermediate Representation (IR) Models for cmd.exe Deobfuscation and Transpilation.
Provides a language-agnostic structured representation of batch scripts.
"""

from enum import Enum
from typing import List, Optional, Any, Dict
from dataclasses import dataclass, field


class IRNodeType(Enum):
    PROGRAM = "program"
    FUNCTION = "function"
    BLOCK = "block"
    ASSIGNMENT = "assignment"
    EXEC = "exec"
    REDIRECT = "redirect"
    IF = "if"
    FOR = "for"
    CALL = "call"
    RETURN = "return"
    LABEL = "label"
    GOTO = "goto"
    CHAIN = "chain"
    PIPE = "pipe"
    ECHO = "echo"
    COMMENT = "comment"
    CONSTANT = "constant"
    VARIABLE = "variable"
    PATH_MOD = "path_modifier"
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    SLICE = "slice"
    SUBST = "subst"


class IROpType(Enum):
    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"
    BIT_AND = "&"
    BIT_OR = "|"
    BIT_XOR = "^"
    SHL = "<<"
    SHR = ">>"
    EQ = "=="
    NEQ = "!="
    LT = "<"
    LTE = "<="
    GT = ">"
    GTE = ">="
    CONCAT = ".."


class IRStreamType(Enum):
    STDOUT = "stdout"
    STDERR = "stderr"
    STDIN = "stdin"
    BOTH = "both"
    DEVNULL = "devnull"


class IRNode:
    """Base class for all Intermediate Representation nodes."""
    span: tuple = (0, 0)

    def to_dict(self) -> Dict[str, Any]:
        result = {"node_type": self.__class__.__name__}
        for k, v in self.__dict__.items():
            if isinstance(v, IRNode):
                result[k] = v.to_dict()
            elif isinstance(v, Enum):
                result[k] = v.value
            elif isinstance(v, list) and all(isinstance(x, IRNode) for x in v):
                result[k] = [x.to_dict() for x in v]
            elif isinstance(v, dict):
                result[k] = {dk: (dv.to_dict() if isinstance(dv, IRNode) else dv) for dk, dv in v.items()}
            else:
                result[k] = v
        return result


# --- Expressions ---

class IRExpression(IRNode):
    """Base class for IR expressions."""
    pass


@dataclass
class IRConstant(IRExpression):
    """Literal constant value (string, integer, boolean)."""
    value: Any = ""
    type_hint: str = "str"  # "str", "int", "bool"


@dataclass
class IRVariable(IRExpression):
    """Variable reference (environment variable or positional/loop parameter)."""
    name: str = ""
    is_env: bool = True
    is_positional: bool = False
    pos_index: int = 0
    is_all_args: bool = False  # %*


@dataclass
class IRPathModifier(IRExpression):
    """Path attribute resolution (e.g., %~dp0 -> script dir, %~f0 -> script path)."""
    target_var: str = "0"
    modifier: str = "dp"  # "dp", "f", "nx", "n", "x", "s"
    is_script_dir: bool = False  # True if %~dp0
    is_script_path: bool = False  # True if %~f0


@dataclass
class IRBinaryOp(IRExpression):
    """Binary operation (arithmetic, comparison, concatenation)."""
    op: IROpType = IROpType.ADD
    left: IRExpression = field(default_factory=lambda: IRConstant(""))
    right: IRExpression = field(default_factory=lambda: IRConstant(""))


@dataclass
class IRUnaryOp(IRExpression):
    """Unary operation (negation, logical NOT)."""
    op: str = "-"
    operand: IRExpression = field(default_factory=lambda: IRConstant(0, "int"))


@dataclass
class IRSlice(IRExpression):
    """Substring slicing expression on an environment variable."""
    var_name: str = ""
    start: Optional[int] = None
    length: Optional[int] = None


@dataclass
class IRSubst(IRExpression):
    """String search-and-replace expression on an environment variable."""
    var_name: str = ""
    search: str = ""
    replace: str = ""


# --- Statements ---

class IRStatement(IRNode):
    """Base class for IR statements."""
    pass


@dataclass
class IRComment(IRStatement):
    """Preserved comment line."""
    text: str = ""


@dataclass
class IRAssignment(IRStatement):
    """Variable assignment statement (target = value)."""
    target: str = ""
    value: IRExpression = field(default_factory=lambda: IRConstant(""))
    is_env: bool = True
    is_arithmetic: bool = False


@dataclass
class IRRedirect(IRNode):
    """I/O Redirection specification for commands."""
    operator: str = ">"  # ">", ">>", "<", "2>&1"
    destination: str = ""
    is_devnull: bool = False
    source_stream: IRStreamType = IRStreamType.STDOUT


@dataclass
class IRExec(IRStatement):
    """Command invocation statement."""
    command: str = ""
    args: List[IRExpression] = field(default_factory=list)
    redirects: List[IRRedirect] = field(default_factory=list)
    is_builtin: bool = False
    builtin_kind: Optional[str] = None  # "echo", "cls", "pause", "mkdir", "del", "copy", "move", "timeout"


@dataclass
class IREcho(IRStatement):
    """Echo output statement."""
    content: List[IRExpression] = field(default_factory=list)
    newline: bool = True
    target_stream: IRStreamType = IRStreamType.STDOUT
    redirects: List[IRRedirect] = field(default_factory=list)


@dataclass
class IRBlock(IRNode):
    """Sequential sequence of statements."""
    statements: List[IRStatement] = field(default_factory=list)


@dataclass
class IRIf(IRStatement):
    """Conditional branching statement."""
    condition: IRExpression = field(default_factory=lambda: IRConstant(True, "bool"))
    then_body: IRBlock = field(default_factory=IRBlock)
    else_body: Optional[IRBlock] = None


@dataclass
class IRFor(IRStatement):
    """Iterative loop statement."""
    iterator: str = ""
    loop_type: str = "items"  # "items", "range", "files", "lines"
    items: List[IRExpression] = field(default_factory=list)
    range_start: int = 0
    range_step: int = 1
    range_end: int = 0
    file_pattern: str = ""
    is_recursive: bool = False
    body: IRBlock = field(default_factory=IRBlock)


@dataclass
class IRCall(IRStatement):
    """Subroutine or external batch invocation."""
    target: str = ""
    args: List[IRExpression] = field(default_factory=list)
    is_subroutine: bool = True


@dataclass
class IRReturn(IRStatement):
    """Return from subroutine or script exit."""
    exit_code: Optional[IRExpression] = None
    is_subroutine_return: bool = True


@dataclass
class IRLabel(IRStatement):
    """Jump target label."""
    name: str = ""


@dataclass
class IRGoto(IRStatement):
    """Unconditional jump to label."""
    target: str = ""


@dataclass
class IRChain(IRStatement):
    """Chained execution: left && right or left || right."""
    left: IRStatement = field(default_factory=IRStatement)
    operator: str = "&&"  # "&&", "||", "&"
    right: IRStatement = field(default_factory=IRStatement)


@dataclass
class IRPipe(IRStatement):
    """Piped execution: left | right."""
    left: IRStatement = field(default_factory=IRStatement)
    right: IRStatement = field(default_factory=IRStatement)


@dataclass
class IRFunction(IRNode):
    """Lifted batch subroutine."""
    name: str = ""
    params: List[str] = field(default_factory=list)
    body: IRBlock = field(default_factory=IRBlock)


@dataclass
class IRProgram(IRNode):
    """Top-level program intermediate representation."""
    entry_block: IRBlock = field(default_factory=IRBlock)
    functions: Dict[str, IRFunction] = field(default_factory=dict)
    env_vars: List[str] = field(default_factory=list)


# --- Telemetry & Security ---

@dataclass
class IRMetrics:
    """Compilation and transpilation telemetry."""
    statements_created: int = 0
    commands_translated: int = 0
    variables_mapped: int = 0
    functions_lifted: int = 0
    loops_structured: int = 0
    branches_created: int = 0
    transpile_time_ms: float = 0.0

    def zeroize(self) -> None:
        """Securely wipe metrics and internal counters."""
        self.statements_created = 0
        self.commands_translated = 0
        self.variables_mapped = 0
        self.functions_lifted = 0
        self.loops_structured = 0
        self.branches_created = 0
        self.transpile_time_ms = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "statements_created": self.statements_created,
            "commands_translated": self.commands_translated,
            "variables_mapped": self.variables_mapped,
            "functions_lifted": self.functions_lifted,
            "loops_structured": self.loops_structured,
            "branches_created": self.branches_created,
            "transpile_time_ms": round(self.transpile_time_ms, 3),
        }

    def summary(self) -> str:
        return (
            f"IR Metrics: {self.statements_created} statements, "
            f"{self.commands_translated} commands, {self.variables_mapped} vars, "
            f"{self.functions_lifted} functions lifted, {self.loops_structured} loops, "
            f"{self.branches_created} branches"
        )
