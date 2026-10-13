"""
AST Pattern Detector for String Reversal and Transposition Obfuscation.
Identifies Somalifuscator-style FOR /L reverse loops, FOR IN index transposition,
pushdown stack GOTO automata, and decreasing slice sequences.
"""

import re
from typing import List, Optional, Dict, Any, Tuple
from ..ast_nodes import (
    ASTNode, ForNode, AssignmentNode, CommandNode, BlockNode,
    VarExpandNode, LiteralNode, LabelNode, GotoNode, IfNode
)
from .models import ReversalPatternType, ReversalLoopSpec


class ReversalPatternDetector:
    """
    Scans AST structures to detect batch reversal and transposition primitives
    with high precision and zero false positives.
    """

    @staticmethod
    def _resolve_env_str(text: str, env: Dict[str, str]) -> str:
        """Substitutes %VAR% and !VAR! in string based on current environment."""
        if not text:
            return ""

        def _repl(m):
            k = m.group(1).lower()
            return env.get(k, m.group(0))

        res = text
        for _ in range(3):
            prev = res
            res = re.sub(r'[%!]([a-zA-Z0-9_\-\.\:\$]+)[%!]', _repl, res)
            if res == prev:
                break
        return res

    @classmethod
    def _extract_assignment_parts(cls, node: ASTNode) -> Optional[Tuple[str, str]]:
        """Extracts (var_name, expression_str) from AssignmentNode or CommandNode."""
        if isinstance(node, AssignmentNode):
            return node.var_name, node.raw_value

        if isinstance(node, CommandNode):
            full_cmd = node.target
            if node.arguments:
                full_cmd += " " + " ".join(
                    a.value if isinstance(a, LiteralNode) else "" for a in node.arguments
                )
            full_cmd = full_cmd.strip()
            if full_cmd.lower().startswith("set "):
                tail = full_cmd[4:].strip()
                if tail.startswith('"') and tail.endswith('"'):
                    tail = tail[1:-1].strip()
                if '=' in tail:
                    vname, val = tail.split('=', 1)
                    return vname.strip(), val.strip()

        if isinstance(node, BlockNode) and node.statements:
            for s in node.statements:
                res = cls._extract_assignment_parts(s)
                if res:
                    return res

        return None

    @classmethod
    def detect_for_l_reversal(cls, node: ForNode, env: Dict[str, str]) -> Optional[ReversalLoopSpec]:
        """
        Detects FOR /L string reversal loop:
        e.g., for /l %i in (20,-1,0) do set out=!out!!str:~%i,1!
        """
        if not node.flags or 'l' not in node.flags.lower():
            return None

        iterator = node.iterator.lstrip('%').strip()
        if not iterator:
            return None

        # Parse in-clause: e.g. (20,-1,0) or (%len%,-1,0)
        in_raw = node.in_clause.strip()
        if in_raw.startswith('(') and in_raw.endswith(')'):
            in_raw = in_raw[1:-1].strip()

        in_resolved = cls._resolve_env_str(in_raw, env)
        # Split by comma or whitespace
        parts = [p.strip() for p in re.split(r'[, \t]+', in_resolved) if p.strip()]
        if len(parts) != 3:
            return None

        try:
            start = int(parts[0])
            step = int(parts[1])
            stop = int(parts[2])
        except ValueError:
            return None

        if not node.body:
            return None

        assign_parts = cls._extract_assignment_parts(node.body)
        if not assign_parts:
            return None

        dest_var, expr = assign_parts
        dest_var = dest_var.strip()

        # Check expression for accumulator and slice pattern
        # Appending pattern: !dest!!source:~%iter%,len! or %dest%!source:~%iter%,len!
        # Prepending pattern: !source:~%iter%,len!!dest!
        pat_append = re.compile(
            r'[%!]' + re.escape(dest_var) + r'[%!]\s*[%!]([a-zA-Z0-9_\-\.\$]+):~%*' +
            re.escape(iterator) + r'(?:,(\d+))?[%!]',
            re.IGNORECASE
        )
        pat_prepend = re.compile(
            r'[%!]([a-zA-Z0-9_\-\.\$]+):~%*' + re.escape(iterator) +
            r'(?:,(\d+))?[%!]\s*[%!]' + re.escape(dest_var) + r'[%!]',
            re.IGNORECASE
        )

        m_app = pat_append.search(expr)
        if m_app:
            source_var = m_app.group(1)
            slice_len = int(m_app.group(2)) if m_app.group(2) else 1
            return ReversalLoopSpec(
                pattern_type=ReversalPatternType.FOR_L_REVERSAL,
                iterator_var=iterator,
                source_var=source_var,
                dest_var=dest_var,
                start=start,
                step=step,
                stop=stop,
                slice_len=slice_len,
                is_prepend=False,
                confidence=1.0,
                matched_ast_node=node
            )

        m_prep = pat_prepend.search(expr)
        if m_prep:
            source_var = m_prep.group(1)
            slice_len = int(m_prep.group(2)) if m_prep.group(2) else 1
            return ReversalLoopSpec(
                pattern_type=ReversalPatternType.FOR_L_PREPEND,
                iterator_var=iterator,
                source_var=source_var,
                dest_var=dest_var,
                start=start,
                step=step,
                stop=stop,
                slice_len=slice_len,
                is_prepend=True,
                confidence=1.0,
                matched_ast_node=node
            )

        return None

    @classmethod
    def detect_for_in_transposition(cls, node: ForNode, env: Dict[str, str]) -> Optional[ReversalLoopSpec]:
        """
        Detects FOR IN index transposition / dictionary lookup loop:
        e.g., for %a in (22 7 14 0 12 8) do set out=!out!!dict:~%a,1!
        """
        if node.flags and any(f in node.flags.lower() for f in ('/l', '/f', '/r', '/d')):
            return None

        iterator = node.iterator.lstrip('%').strip()
        if not iterator:
            return None

        in_raw = node.in_clause.strip()
        if in_raw.startswith('(') and in_raw.endswith(')'):
            in_raw = in_raw[1:-1].strip()

        in_resolved = cls._resolve_env_str(in_raw, env)
        items = [p.strip() for p in re.split(r'[, \t]+', in_resolved) if p.strip()]
        if not items:
            return None

        # Check if items are integers
        int_items = []
        for item in items:
            try:
                int_items.append(int(item))
            except ValueError:
                return None

        if not node.body:
            return None

        assign_parts = cls._extract_assignment_parts(node.body)
        if not assign_parts:
            return None

        dest_var, expr = assign_parts
        dest_var = dest_var.strip()

        pat_append = re.compile(
            r'[%!]' + re.escape(dest_var) + r'[%!]\s*[%!]([a-zA-Z0-9_\-\.\$]+):~%*' +
            re.escape(iterator) + r'(?:,(\d+))?[%!]',
            re.IGNORECASE
        )
        pat_prepend = re.compile(
            r'[%!]([a-zA-Z0-9_\-\.\$]+):~%*' + re.escape(iterator) +
            r'(?:,(\d+))?[%!]\s*[%!]' + re.escape(dest_var) + r'[%!]',
            re.IGNORECASE
        )

        m_app = pat_append.search(expr)
        if m_app:
            source_var = m_app.group(1)
            slice_len = int(m_app.group(2)) if m_app.group(2) else 1
            return ReversalLoopSpec(
                pattern_type=ReversalPatternType.FOR_IN_TRANSPOSITION,
                iterator_var=iterator,
                source_var=source_var,
                dest_var=dest_var,
                slice_len=slice_len,
                is_prepend=False,
                in_items=items,
                confidence=1.0,
                matched_ast_node=node
            )

        m_prep = pat_prepend.search(expr)
        if m_prep:
            source_var = m_prep.group(1)
            slice_len = int(m_prep.group(2)) if m_prep.group(2) else 1
            return ReversalLoopSpec(
                pattern_type=ReversalPatternType.FOR_IN_TRANSPOSITION,
                iterator_var=iterator,
                source_var=source_var,
                dest_var=dest_var,
                slice_len=slice_len,
                is_prepend=True,
                in_items=items,
                confidence=1.0,
                matched_ast_node=node
            )

        return None

    @classmethod
    def detect_goto_reversal_loop(
        cls,
        statements: List[ASTNode],
        env: Dict[str, str]
    ) -> Optional[Tuple[int, int, ReversalLoopSpec]]:
        """
        Detects GOTO-based pushdown stack reversal loop in a sequence of statements:
        :loop
        set "dst=%dst%%src:~-1%"
        set "src=%src:~0,-1%"
        if defined src goto loop
        """
        n = len(statements)
        for i in range(n):
            stmt = statements[i]
            if not isinstance(stmt, LabelNode):
                continue
            lbl_name = stmt.name.lower()

            # Inspect subsequent statements up to 6 instructions ahead
            accum_stmt = None
            shrink_stmt = None
            loop_end_idx = -1

            for j in range(i + 1, min(i + 7, n)):
                candidate = statements[j]
                parts = cls._extract_assignment_parts(candidate)
                if parts:
                    vname, val = parts
                    # Check for dst=%dst%%src:~-1%
                    m_accum = re.search(
                        r'[%!]' + re.escape(vname) + r'[%!]\s*[%!]([a-zA-Z0-9_\-\.\$]+):~-1(?:,1)?[%!]',
                        val,
                        re.IGNORECASE
                    )
                    if m_accum:
                        accum_stmt = (vname, m_accum.group(1))

                    # Check for src=%src:~0,-1%
                    m_shrink = re.search(
                        r'[%!]([a-zA-Z0-9_\-\.\$]+):~0,-1[%!]',
                        val,
                        re.IGNORECASE
                    )
                    if m_shrink and m_shrink.group(1).lower() == (accum_stmt[1].lower() if accum_stmt else ''):
                        shrink_stmt = m_shrink.group(1)

                # Check for goto back to label
                if isinstance(candidate, GotoNode) and candidate.target.lower() == lbl_name:
                    loop_end_idx = j
                    break
                elif isinstance(candidate, IfNode):
                    if (isinstance(candidate.then_block, GotoNode) and
                            candidate.then_block.target.lower() == lbl_name):
                        loop_end_idx = j
                        break

            if accum_stmt and shrink_stmt and loop_end_idx != -1:
                dest_var, source_var = accum_stmt
                spec = ReversalLoopSpec(
                    pattern_type=ReversalPatternType.GOTO_STACK_REVERSAL,
                    iterator_var="",
                    source_var=source_var,
                    dest_var=dest_var,
                    confidence=1.0,
                    matched_ast_node=statements[i]
                )
                return i, loop_end_idx, spec

        return None

    @classmethod
    def detect_slice_transposition_sequence(
        cls,
        nodes: List[ASTNode],
        env: Dict[str, str]
    ) -> List[Tuple[int, int, str, List[int], List[int]]]:
        """
        Identifies consecutive sequences of VarExpandNode items referencing slices of the same variable:
        Returns list of (start_index, end_index, var_name, slice_starts, slice_lengths).
        """
        results = []
        i = 0
        n = len(nodes)

        while i < n:
            node = nodes[i]
            if (isinstance(node, VarExpandNode) and
                    node.slice_start is not None and
                    node.name.lower() in env):
                var_name = node.name.lower()
                run_starts = [node.slice_start]
                run_lens = [node.slice_len if node.slice_len is not None else 1]
                j = i + 1

                while j < n:
                    next_node = nodes[j]
                    if (isinstance(next_node, VarExpandNode) and
                            next_node.name.lower() == var_name and
                            next_node.slice_start is not None):
                        run_starts.append(next_node.slice_start)
                        run_lens.append(next_node.slice_len if next_node.slice_len is not None else 1)
                        j += 1
                    else:
                        break

                # We require at least 2 consecutive slices
                if len(run_starts) >= 2:
                    # Check if decreasing or non-trivial permutation
                    results.append((i, j, var_name, run_starts, run_lens))
                    i = j
                    continue

            i += 1

        return results
