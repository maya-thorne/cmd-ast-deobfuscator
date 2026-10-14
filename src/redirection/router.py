"""
Stream Routing Engine and Execution Simulator.
Evaluates sequential I/O redirection directives to determine effective handle destinations,
stealth execution patterns, and handle duplication chains.
"""

from typing import Dict, List, Optional, Set
from ..ast_nodes import ASTNode, RedirectNode
from .models import (
    RedirectEntry, StreamRoute, RedirectPlan, DestinationType,
    StreamType, RedirectMetrics
)

MAX_FORWARD_DEPTH: int = 10


class StreamRouter:
    """
    Simulates Windows cmd.exe stream redirection handle routing.
    Models handle duplication, file binding, device redirection, and stealth suppression.
    """
    def __init__(self):
        self.metrics = RedirectMetrics()
        self._last_plan: Optional[RedirectPlan] = None

    def route(self, entries: List[RedirectEntry]) -> RedirectPlan:
        """
        Simulates sequential stream redirection evaluation.
        cmd.exe evaluates redirections left-to-right, modifying handles in-place.
        """
        # Baseline descriptor state
        routes: Dict[int, StreamRoute] = {
            StreamType.STDIN: StreamRoute(
                fd=StreamType.STDIN,
                destination="CONIN$",
                dest_type=DestinationType.DEVICE,
                mode="read"
            ),
            StreamType.STDOUT: StreamRoute(
                fd=StreamType.STDOUT,
                destination="CONOUT$",
                dest_type=DestinationType.DEVICE,
                mode="write"
            ),
            StreamType.STDERR: StreamRoute(
                fd=StreamType.STDERR,
                destination="CONERR$",
                dest_type=DestinationType.DEVICE,
                mode="write"
            ),
        }

        output_dests: List[str] = []
        input_source: Optional[str] = None

        for entry in entries:
            self.metrics.record(entry)
            src = entry.source_fd

            if entry.is_dup:
                if entry.dest_type == DestinationType.CLOSED or entry.destination == '&-':
                    routes[src] = StreamRoute(
                        fd=src,
                        destination="CLOSED",
                        dest_type=DestinationType.CLOSED,
                        mode="close",
                        is_suppressed=True
                    )
                elif entry.target_fd is not None:
                    # Duplicate target descriptor route
                    target_fd = entry.target_fd
                    target_route = self._resolve_target(routes, target_fd)
                    if target_route:
                        routes[src] = StreamRoute(
                            fd=src,
                            destination=target_route.destination,
                            dest_type=target_route.dest_type,
                            mode=target_route.mode,
                            target_fd=target_fd,
                            is_suppressed=target_route.is_suppressed
                        )
                    else:
                        # Fallback for uninitialized descriptor
                        routes[src] = StreamRoute(
                            fd=src,
                            destination=f"&{target_fd}",
                            dest_type=DestinationType.HANDLE,
                            mode="duplicate",
                            target_fd=target_fd
                        )
            elif entry.is_input:
                input_source = entry.destination
                routes[src] = StreamRoute(
                    fd=src,
                    destination=entry.destination,
                    dest_type=entry.dest_type,
                    mode="read",
                    is_suppressed=False
                )
            else:
                mode = "append" if entry.is_append else "write"
                if entry.dest_type == DestinationType.FILE and entry.destination not in output_dests:
                    output_dests.append(entry.destination)

                routes[src] = StreamRoute(
                    fd=src,
                    destination=entry.destination,
                    dest_type=entry.dest_type,
                    mode=mode,
                    is_suppressed=entry.is_suppressed
                )

        # Assess stealth / suppression status
        stdout_route = routes.get(StreamType.STDOUT)
        stderr_route = routes.get(StreamType.STDERR)

        is_stdout_suppressed = bool(stdout_route and stdout_route.is_suppressed)
        is_stderr_suppressed = bool(stderr_route and stderr_route.is_suppressed)
        is_stealth = is_stdout_suppressed and is_stderr_suppressed

        plan = RedirectPlan(
            routes=routes,
            entries=list(entries),
            is_stealth=is_stealth,
            is_stdout_suppressed=is_stdout_suppressed,
            is_stderr_suppressed=is_stderr_suppressed,
            input_source=input_source,
            output_destinations=output_dests
        )

        self.metrics.record_plan(plan)
        self._last_plan = plan
        return plan

    def route_node(self, node: ASTNode) -> RedirectPlan:
        """Extracts redirection entries from an AST node hierarchy and evaluates routing."""
        entries: List[RedirectEntry] = []
        curr = node
        while isinstance(curr, RedirectNode):
            src_fd = curr.source_fd if curr.source_fd is not None else (0 if curr.is_input else 1)
            from .extractor import classify_destination
            dest_type, is_suppressed = classify_destination(curr.destination)
            entries.append(RedirectEntry(
                source_fd=src_fd,
                operator=curr.stream,
                destination=curr.destination,
                target_fd=curr.target_fd,
                dest_type=dest_type,
                is_append=curr.is_append,
                is_input=curr.is_input,
                is_dup=curr.is_dup,
                is_suppressed=is_suppressed,
                raw=f"{curr.stream}{curr.destination}",
                span=curr.span
            ))
            curr = curr.command

        entries.reverse()
        return self.route(entries)

    def _resolve_target(
        self,
        routes: Dict[int, StreamRoute],
        target_fd: int,
        visited: Optional[Set[int]] = None,
        depth: int = 0
    ) -> Optional[StreamRoute]:
        """Resolves target handle route with recursion and cycle protection."""
        if depth > MAX_FORWARD_DEPTH:
            return None
        if visited is None:
            visited = set()
        if target_fd in visited:
            return None  # Cycle detected
        visited.add(target_fd)

        route = routes.get(target_fd)
        if route is None:
            return None

        if route.target_fd is not None and route.mode == "duplicate":
            next_res = self._resolve_target(routes, route.target_fd, visited, depth + 1)
            return next_res if next_res else route

        return route

    def is_stealth(self, entries: List[RedirectEntry]) -> bool:
        """Determines if a sequence of redirections results in stealth execution."""
        plan = self.route(entries)
        return plan.is_stealth

    def zeroize(self) -> None:
        """Securely zeroes internal state, telemetry, and cached routing plans."""
        self.metrics.zeroize()
        if self._last_plan:
            self._last_plan.routes.clear()
            self._last_plan.entries.clear()
            self._last_plan.output_destinations.clear()
            self._last_plan = None
