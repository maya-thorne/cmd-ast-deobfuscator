"""
Control Flow Flattening (CFF) Loop Detector & Dominator Tree Analyzer.
Identifies natural loops, headers, latches, back-edges, and classifies loops
into deterministic unrollable cycles vs data-dependent while/for structures.
"""

import re
from typing import List, Dict, Set, Optional, Tuple, Any
from ..ast_nodes import ASTNode, AssignmentNode, IfNode, GotoNode, ExitNode
from .models import (
    CFFStateMachine, CFFBlockInfo, CFFLoopInfo, CFFLoopType,
    CFFUnrollConfig, UnrollMode
)

RE_COND_OP = re.compile(
    r'(?:/i\s+)?["\']?([^"\'\s)]+)["\']?\s*(==|equ|neq|lss|leq|gtr|geq)\s*["\']?([^"\'\s)]+)["\']?',
    re.IGNORECASE
)
RE_ARITH_ASSIGN = re.compile(r'([a-zA-Z0-9_#$]+)\s*(\+=|-=|\*=|/=|%=|=)\s*(.+)', re.IGNORECASE)
RE_VAR_REF = re.compile(r'[%!]([a-zA-Z0-9_#$]+)[%!]', re.IGNORECASE)


class CFFLoopDetector:
    """Computes reachability, dominators, and natural loops for CFF state machines."""

    def __init__(self):
        self._cache_dominators: Dict[str, Set[str]] = {}
        self._cache_edges: List[Tuple[str, str]] = []

    def detect(
        self,
        state_machine: CFFStateMachine,
        config: Optional[CFFUnrollConfig] = None
    ) -> Tuple[List[CFFLoopInfo], Set[str]]:
        """Analyzes state machine, detecting natural loops and unreachable dead states."""
        cfg = config or CFFUnrollConfig()
        blocks = state_machine.blocks
        if not blocks:
            return [], set()

        succ: Dict[str, Set[str]] = {s: set() for s in blocks}
        pred: Dict[str, Set[str]] = {s: set() for s in blocks}
        for s, blk in blocks.items():
            if blk.next_state and blk.next_state in blocks:
                succ[s].add(blk.next_state); pred[blk.next_state].add(s)
            for _, target in blk.conditional_transitions:
                if target in blocks:
                    succ[s].add(target); pred[target].add(s)

        # Reachability from initial_state
        reachable: Set[str] = set()
        queue = [state_machine.initial_state] if state_machine.initial_state in succ else []
        while queue:
            curr = queue.pop(0)
            if curr not in reachable:
                reachable.add(curr)
                queue.extend(nxt for nxt in succ.get(curr, set()) if nxt not in reachable)
        dead_states = set(blocks.keys()) - reachable

        if not cfg.detect_loops or len(reachable) < 1:
            return [], dead_states

        # Dominators
        dom: Dict[str, Set[str]] = {n: ({n} if n == state_machine.initial_state else set(reachable)) for n in reachable}
        changed = True
        while changed:
            changed = False
            for n in reachable:
                if n == state_machine.initial_state: continue
                preds = [p for p in pred.get(n, set()) if p in reachable]
                new_dom = {n} | (set.intersection(*(dom[p] for p in preds)) if preds else set())
                if new_dom != dom[n]:
                    dom[n] = new_dom; changed = True
        self._cache_dominators = dom

        # Back-edges (u -> v where v in Dom(u))
        back_edges = [(u, v) for u in reachable for v in succ.get(u, set()) if v in reachable and v in dom.get(u, set())]
        self._cache_edges = back_edges
        if not back_edges:
            return [], dead_states

        # Natural loop bodies
        grouped: Dict[str, Dict[str, Any]] = {}
        for u, v in back_edges:
            if v not in grouped:
                grouped[v] = {"header": v, "latches": set(), "back_edges": [], "body": {v}}
            grouped[v]["latches"].add(u); grouped[v]["back_edges"].append((u, v))

        for header, data in grouped.items():
            worklist = list(data["latches"])
            while worklist:
                m = worklist.pop()
                data["body"].add(m)
                for p in pred.get(m, set()):
                    if p in reachable and p not in data["body"]:
                        data["body"].add(p); worklist.append(p)

        detected_loops: List[CFFLoopInfo] = []
        for header, grp in grouped.items():
            loop_info = self._classify_loop(header, grp, state_machine, pred, cfg)
            detected_loops.append(loop_info)

        return detected_loops, dead_states

    def _classify_loop(
        self,
        header: str,
        group_info: Dict[str, Any],
        state_machine: CFFStateMachine,
        pred: Dict[str, Set[str]],
        config: CFFUnrollConfig
    ) -> CFFLoopInfo:
        """Determines loop exits, conditions, and simulates loop to check determinism."""
        body: Set[str] = group_info["body"]
        latches: Set[str] = group_info["latches"]
        back_edges: List[Tuple[str, str]] = group_info["back_edges"]
        exit_states: Set[str] = set()
        exit_conditions: List[str] = []
        continue_conditions: List[str] = []

        is_irreducible = any(
            p not in body and p in state_machine.blocks
            for node in body if node != header
            for p in pred.get(node, set())
        )

        for node in body:
            blk = state_machine.blocks.get(node)
            if not blk: continue
            if blk.is_terminal or (blk.next_state and blk.next_state not in body):
                exit_states.add(node)
            for cond, tgt in blk.conditional_transitions:
                if tgt not in body:
                    exit_states.add(node); exit_conditions.append(cond)
                else:
                    continue_conditions.append(cond)

        if is_irreducible:
            return CFFLoopInfo(
                header_state=header, latch_states=latches, body_states=body,
                exit_states=exit_states, back_edges=back_edges,
                loop_type=CFFLoopType.COMPLEX_IRREDUCIBLE, iteration_count=None,
                exit_conditions=exit_conditions, continue_conditions=continue_conditions
            )

        sim_count = self._simulate_loop(header, body, exit_states, state_machine, config.max_unroll_iterations)
        l_type = CFFLoopType.DETERMINISTIC_UNROLLED if (sim_count and sim_count > 0) else CFFLoopType.STRUCTURED_WHILE
        return CFFLoopInfo(
            header_state=header, latch_states=latches, body_states=body,
            exit_states=exit_states, back_edges=back_edges, loop_type=l_type,
            iteration_count=sim_count if l_type == CFFLoopType.DETERMINISTIC_UNROLLED else None,
            exit_conditions=exit_conditions, continue_conditions=continue_conditions
        )

    def _simulate_loop(
        self,
        header: str,
        body: Set[str],
        exit_states: Set[str],
        state_machine: CFFStateMachine,
        max_iters: int
    ) -> Optional[int]:
        """Simulates execution on integer env to identify bounded iteration counts."""
        env: Dict[str, int] = {}
        curr = header; iterations = 0; steps = 0
        max_steps = max_iters * max(len(body), 1) * 4

        while steps < max_steps:
            steps += 1
            if curr == header:
                iterations += 1
                if iterations > max_iters: return None
            blk = state_machine.blocks.get(curr)
            if not blk: return iterations if curr in exit_states or curr not in body else None

            for stmt in blk.statements:
                if isinstance(stmt, AssignmentNode):
                    var_raw = stmt.var_name.lower().strip()
                    op = "="
                    for compound_op in ("+=", "-=", "*=", "/=", "%="):
                        if var_raw.endswith(compound_op[:-1]):
                            op = compound_op
                            var_raw = var_raw[:-1]
                            break
                    if stmt.is_arithmetic:
                        val = self._eval_arithmetic(stmt.raw_value, env)
                        if val is not None:
                            curr_v = env.get(var_raw, 0)
                            ops = {"+=": curr_v + val, "-=": curr_v - val, "*=": curr_v * val,
                                   "/=": curr_v // val if val else 0, "%=": curr_v % val if val else 0}
                            env[var_raw] = ops.get(op, val)
                    else:
                        val = self._parse_int(stmt.raw_value)
                        if val is not None: env[var_raw] = val

            if blk.is_terminal: return max(iterations, 1)

            if blk.conditional_transitions:
                taken = None
                for cond, tgt in blk.conditional_transitions:
                    res = self._eval_condition(cond, env)
                    if res is True: taken = tgt; break
                    elif res is False: continue
                    else: return None  # Non-deterministic external variable
                taken = taken or blk.next_state
                if not taken or taken not in body: return max(iterations, 1)
                curr = taken
            elif blk.next_state:
                if blk.next_state not in body: return max(iterations, 1)
                curr = blk.next_state
            else:
                return max(iterations, 1)
        return None

    def _eval_arithmetic(self, expr_str: str, env: Dict[str, int]) -> Optional[int]:
        m = RE_ARITH_ASSIGN.match(expr_str.strip())
        if not m:
            return self._safe_eval(self._substitute_vars(expr_str, env))
        target_var, op, rhs = m.group(1).lower(), m.group(2), m.group(3)
        rhs_val = self._safe_eval(self._substitute_vars(rhs, env))
        if rhs_val is None: return None
        curr = env.get(target_var, 0)
        ops = {"+=": curr + rhs_val, "-=": curr - rhs_val, "*=": curr * rhs_val,
               "/=": curr // rhs_val if rhs_val else 0, "%=": curr % rhs_val if rhs_val else 0}
        return ops.get(op, rhs_val)

    def _eval_condition(self, cond: str, env: Dict[str, int]) -> Optional[bool]:
        c = cond.strip()
        is_not = False
        if c.upper().startswith("NOT "):
            is_not = True
            c = c[4:].strip()
            if c.startswith("(") and c.endswith(")"):
                c = c[1:-1].strip()
        m = RE_COND_OP.search(c)
        if not m: return None
        l_val, op, r_val = self._resolve(m.group(1), env), m.group(2).lower(), self._resolve(m.group(3), env)
        if l_val is None or r_val is None: return None
        cmp_map = {"==": l_val == r_val, "equ": l_val == r_val, "neq": l_val != r_val,
                   "lss": l_val < r_val, "leq": l_val <= r_val, "gtr": l_val > r_val, "geq": l_val >= r_val}
        res = cmp_map.get(op, False)
        return not res if is_not else res

    def _resolve(self, token: str, env: Dict[str, int]) -> Optional[int]:
        clean = RE_VAR_REF.sub(r'\1', token.strip(' "\'()')).lower()
        return env[clean] if clean in env else self._parse_int(clean)

    def _substitute_vars(self, s: str, env: Dict[str, int]) -> str:
        res = RE_VAR_REF.sub(lambda m: str(env.get(m.group(1).lower(), 0)), s)
        for k, v in env.items():
            res = re.sub(rf'\b{re.escape(k)}\b', str(v), res, flags=re.IGNORECASE)
        return res

    def _safe_eval(self, expr: str) -> Optional[int]:
        clean = re.sub(r'[^0-9+\-*/% ()]', '', expr).strip()
        if not clean: return None
        try: return int(eval(clean, {"__builtins__": None}, {}))
        except Exception: return None

    def _parse_int(self, s: str) -> Optional[int]:
        try: return int(s.strip(' "\''))
        except (ValueError, TypeError): return None

    def zeroize(self) -> None:
        """Securely clears internal detector caches."""
        self._cache_dominators.clear()
        self._cache_edges.clear()
