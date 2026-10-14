"""
Data models, enumerations, and telemetry structures for I/O redirection.
Represents stream descriptors, redirect operators, routing plans, and metrics.
"""

from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


class StreamType(IntEnum):
    """Standard file descriptors in cmd.exe environment."""
    STDIN = 0
    STDOUT = 1
    STDERR = 2
    CUSTOM = 3


class RedirectOperator(str, Enum):
    """Redirection stream operators."""
    OUTPUT = ">"
    APPEND = ">>"
    INPUT = "<"
    DUP_OUTPUT = ">&"
    DUP_INPUT = "<&"


class DestinationType(str, Enum):
    """Target destination classification for stream routing."""
    FILE = "file"
    DEVICE = "device"
    HANDLE = "handle"
    CLOSED = "closed"


@dataclass
class RedirectEntry:
    """Individual parsed redirection directive."""
    source_fd: int = 1
    operator: str = ">"
    destination: str = ""
    target_fd: Optional[int] = None
    dest_type: DestinationType = DestinationType.FILE
    is_append: bool = False
    is_input: bool = False
    is_dup: bool = False
    is_suppressed: bool = False
    raw: str = ""
    span: tuple = (0, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_fd": self.source_fd,
            "operator": self.operator,
            "destination": self.destination,
            "target_fd": self.target_fd,
            "dest_type": self.dest_type.value,
            "is_append": self.is_append,
            "is_input": self.is_input,
            "is_dup": self.is_dup,
            "is_suppressed": self.is_suppressed,
            "raw": self.raw,
            "span": self.span
        }


@dataclass
class StreamRoute:
    """Resolved active route for a single stream descriptor."""
    fd: int
    destination: str
    dest_type: DestinationType
    mode: str = "write"  # 'write', 'append', 'read', 'duplicate', 'close'
    target_fd: Optional[int] = None
    is_suppressed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fd": self.fd,
            "destination": self.destination,
            "dest_type": self.dest_type.value,
            "mode": self.mode,
            "target_fd": self.target_fd,
            "is_suppressed": self.is_suppressed
        }


@dataclass
class RedirectPlan:
    """Aggregate stream configuration after evaluating all redirections."""
    routes: Dict[int, StreamRoute] = field(default_factory=dict)
    entries: List[RedirectEntry] = field(default_factory=list)
    is_stealth: bool = False
    is_stdout_suppressed: bool = False
    is_stderr_suppressed: bool = False
    input_source: Optional[str] = None
    output_destinations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "routes": {str(k): v.to_dict() for k, v in self.routes.items()},
            "entries": [e.to_dict() for e in self.entries],
            "is_stealth": self.is_stealth,
            "is_stdout_suppressed": self.is_stdout_suppressed,
            "is_stderr_suppressed": self.is_stderr_suppressed,
            "input_source": self.input_source,
            "output_destinations": list(self.output_destinations)
        }


@dataclass
class RedirectMetrics:
    """Telemetry metrics tracking I/O redirection frequency and patterns."""
    total_redirects: int = 0
    stdout_redirects: int = 0
    stderr_redirects: int = 0
    stdin_redirects: int = 0
    handle_duplications: int = 0
    suppressed_streams: int = 0
    stealth_commands: int = 0
    custom_fd_redirects: int = 0

    def record(self, entry: RedirectEntry) -> None:
        self.total_redirects += 1
        if entry.is_input:
            self.stdin_redirects += 1
        elif entry.source_fd == 1:
            self.stdout_redirects += 1
        elif entry.source_fd == 2:
            self.stderr_redirects += 1
        else:
            self.custom_fd_redirects += 1

        if entry.is_dup:
            self.handle_duplications += 1
        if entry.is_suppressed:
            self.suppressed_streams += 1

    def record_plan(self, plan: RedirectPlan) -> None:
        if plan.is_stealth:
            self.stealth_commands += 1

    def zeroize(self) -> None:
        """Securely zero-out telemetry counters."""
        self.total_redirects = 0
        self.stdout_redirects = 0
        self.stderr_redirects = 0
        self.stdin_redirects = 0
        self.handle_duplications = 0
        self.suppressed_streams = 0
        self.stealth_commands = 0
        self.custom_fd_redirects = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "total_redirects": self.total_redirects,
            "stdout_redirects": self.stdout_redirects,
            "stderr_redirects": self.stderr_redirects,
            "stdin_redirects": self.stdin_redirects,
            "handle_duplications": self.handle_duplications,
            "suppressed_streams": self.suppressed_streams,
            "stealth_commands": self.stealth_commands,
            "custom_fd_redirects": self.custom_fd_redirects
        }
