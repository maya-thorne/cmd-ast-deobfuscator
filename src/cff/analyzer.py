"""
Control Flow Flattening (CFF) AST and Graph Topology Analyzer.
Scans script statements, identifies central state dispatcher hubs,
extracts state variables, mappings, and state transition graphs.
"""

import re
from typing import List, Dict, Optional, Tuple, Set, Any
from ..ast_nodes import (
    ASTNode, ScriptNode, LabelNode, GotoNode, IfNode, AssignmentNode,
    CommandNode, BlockNode, ChainNode, ExitNode
)
from .models import (
    CFFPatternType, CFFBlockInfo, CFFStateMachine, CFFTransition
)

# Regular expressions for detecting state conditionals and computed jumps
RE_IF_STATE_EQ = re.compile(
    r'(?:/i\s+)?["\']?[!%]([a-zA-Z0-9_#$]+)[!%]["\']?\s*(?:==|equ)\s*["\']?([^"\'\s)]+)["\']?',
    re.IGNORECASE
)
RE_COMPUTED_TARGET = re.compile(
    r'([a-zA-Z0-9_]*)[!%]([a-zA-Z0-9_#$]+)[!%]([a-zA-Z0-9_]*)',
    re.IGNORECASE
)


class CFFAnalyzer:
    """
    Analyzes AST statement sequences to locate and extract CFF state machines.
    """

    def __init__(self):
        self.initial_env: Dict[str, str] = {}

    def analyze(self, ast: ASTNode) -> Optional[CFFStateMachine]:
        """
        Scans an AST tree (ScriptNode, BlockNode, or statement list)
        and returns a reconstructed CFFStateMachine if detected.
        """
        stmts = self._flatten_statements(ast)
        if len(stmts) < 4:
            return None

        # Step 1: Partition statements into labeled sections
        sections = self._partition_by_labels(stmts)
        if len(sections) < 2:
            return None

        # Step 2: Track initial environment variable assignments before labels
        entry_assignments = self._extract_entry_assignments(stmts)

        # Step 3: Scan each labeled section for dispatcher patterns
        for label_name, section_stmts in sections.items():
            if not label_name:
                continue

            state_machine = self._check_section_as_dispatcher(
                label_name=label_name,
                section_stmts=section_stmts,
                sections=sections,
                entry_assignments=entry_assignments
            )
            if state_machine:
                return state_machine

        return None

    def _flatten_statements(self, node: ASTNode) -> List[ASTNode]:
        """Extracts flat list of sequential statements from root AST."""
        if isinstance(node, ScriptNode):
            res: List[ASTNode] = []
            for s in node.statements:
                res.extend(self._flatten_statements(s))
            return res
        if isinstance(node, BlockNode):
            res: List[ASTNode] = []
            for s in node.statements:
                res.extend(self._flatten_statements(s))
            return res
        if isinstance(node, ChainNode):
            left = self._flatten_statements(node.left)
            right = self._flatten_statements(node.right)
            return left + right
        return [node]

    def _partition_by_labels(self, stmts: List[ASTNode]) -> Dict[str, List[ASTNode]]:
        """Splits statement list into sections keyed by label name."""
        sections: Dict[str, List[ASTNode]] = {}
        current_label = ""
        current_list: List[ASTNode] = []

        for s in stmts:
            if isinstance(s, LabelNode):
                sections[current_label] = current_list
                current_label = s.name.lower().lstrip(':')
                current_list = []
            else:
                current_list.append(s)

        sections[current_label] = current_list
        return sections

    def _extract_entry_assignments(self, stmts: List[ASTNode]) -> Dict[str, str]:
        """Extracts variable assignments prior to the first label."""
        env: Dict[str, str] = {}
        for s in stmts:
            if isinstance(s, LabelNode):
                break
            if isinstance(s, AssignmentNode):
                env[s.var_name.lower()] = s.raw_value.strip(' "\'')
        return env

    def _check_section_as_dispatcher(
        self,
        label_name: str,
        section_stmts: List[ASTNode],
        sections: Dict[str, List[ASTNode]],
        entry_assignments: Dict[str, str]
    ) -> Optional[CFFStateMachine]:
        """Inspects if label_name acts as a central CFF switch or computed dispatcher."""
        # 1. Check for SWITCH_DISPATCHER (IF %state%==X goto :lbl)
        switch_cases = self._extract_switch_cases(section_stmts)
        if len(switch_cases) >= 1:
            # Determine dominant state variable
            state_var_counts: Dict[str, int] = {}
            for var_name, _, _ in switch_cases:
                v = var_name.lower()
                state_var_counts[v] = state_var_counts.get(v, 0) + 1

            best_var = max(state_var_counts.keys(), key=lambda k: state_var_counts[k])
            initial_state = entry_assignments.get(best_var, "")
            state_map = {
                val: tgt_lbl for var, val, tgt_lbl in switch_cases
                if var.lower() == best_var
            }

            # Construct state handlers
            blocks = self._build_state_blocks(
                state_map=state_map,
                sections=sections,
                state_var=best_var,
                dispatcher_label=label_name
            )

            is_valid_cff = (len(blocks) >= 2) or (
                len(blocks) == 1 and any(
                    b.jumps_to_dispatcher or b.next_state or b.is_terminal
                    for b in blocks.values()
                )
            )

            if is_valid_cff and len(blocks) >= 1:
                # If initial_state wasn't set at entry, deduce from first switch case
                if not initial_state and switch_cases:
                    initial_state = switch_cases[0][1]

                all_labels = {label_name} | {b.label_name.lower() for b in blocks.values()}

                return CFFStateMachine(
                    state_var=best_var,
                    initial_state=initial_state,
                    dispatcher_label=label_name,
                    blocks=blocks,
                    pattern_type=CFFPatternType.SWITCH_DISPATCHER,
                    all_cff_labels=all_labels
                )

        # 2. Check for COMPUTED_GOTO (goto :prefix_%state%)
        computed_info = self._extract_computed_goto(section_stmts)
        if computed_info:
            prefix, var_name, suffix = computed_info
            initial_state = entry_assignments.get(var_name.lower(), "")
            # Find all labels matching prefix*suffix
            state_map = {}
            for lbl in sections.keys():
                if not lbl or lbl == label_name:
                    continue
                if lbl.startswith(prefix.lower()) and lbl.endswith(suffix.lower()):
                    state_val = lbl[len(prefix):len(lbl) - len(suffix) if suffix else len(lbl)]
                    if state_val:
                        state_map[state_val] = lbl

            if len(state_map) >= 2:
                blocks = self._build_state_blocks(
                    state_map=state_map,
                    sections=sections,
                    state_var=var_name.lower(),
                    dispatcher_label=label_name
                )
                if len(blocks) >= 2:
                    if not initial_state and state_map:
                        initial_state = list(state_map.keys())[0]

                    all_labels = {label_name} | {b.label_name.lower() for b in blocks.values()}

                    return CFFStateMachine(
                        state_var=var_name.lower(),
                        initial_state=initial_state,
                        dispatcher_label=label_name,
                        blocks=blocks,
                        pattern_type=CFFPatternType.COMPUTED_GOTO,
                        all_cff_labels=all_labels
                    )

        return None

    def _extract_switch_cases(self, stmts: List[ASTNode]) -> List[Tuple[str, str, str]]:
        """Extracts (state_var, state_val, target_label) from IfNodes."""
        cases: List[Tuple[str, str, str]] = []
        for s in stmts:
            if isinstance(s, IfNode):
                m = RE_IF_STATE_EQ.search(s.condition)
                if m:
                    var_name = m.group(1)
                    val = m.group(2).strip(' "\'')
                    tgt = self._extract_goto_target(s.then_block)
                    if tgt:
                        cases.append((var_name, val, tgt.lower()))
        return cases

    def _extract_computed_goto(self, stmts: List[ASTNode]) -> Optional[Tuple[str, str, str]]:
        """Finds computed goto target in statements."""
        for s in stmts:
            if isinstance(s, GotoNode):
                raw = s.target or "".join(getattr(n, 'value', '') for n in s.target_nodes)
                m = RE_COMPUTED_TARGET.search(raw.lstrip(':'))
                if m:
                    return m.group(1), m.group(2), m.group(3)
        return None

    def _extract_goto_target(self, node: ASTNode) -> Optional[str]:
        """Extracts the target label from a GotoNode or BlockNode containing a GotoNode."""
        if isinstance(node, GotoNode):
            return node.target.lstrip(':').strip()
        if isinstance(node, BlockNode):
            for child in node.statements:
                tgt = self._extract_goto_target(child)
                if tgt:
                    return tgt
        if isinstance(node, CommandNode):
            # Sometimes goto is parsed as CommandNode('goto', args=[...])
            if node.target.lower() == 'goto' and node.arguments:
                arg_str = "".join(getattr(a, 'value', str(a)) for a in node.arguments)
                return arg_str.lstrip(':').strip()
        return None

    def _build_state_blocks(
        self,
        state_map: Dict[str, str],
        sections: Dict[str, List[ASTNode]],
        state_var: str,
        dispatcher_label: str
    ) -> Dict[str, CFFBlockInfo]:
        """Analyzes each handler section to extract clean payload statements and state transitions."""
        blocks: Dict[str, CFFBlockInfo] = {}

        for state_val, lbl_name in state_map.items():
            section_stmts = sections.get(lbl_name.lower(), [])
            payload_stmts: List[ASTNode] = []
            next_state: Optional[str] = None
            cond_transitions: List[Tuple[str, str]] = []
            is_terminal = False
            jumps_to_dispatcher = False

            for s in section_stmts:
                # Check for terminal exit
                if isinstance(s, ExitNode):
                    payload_stmts.append(s)
                    is_terminal = True
                    continue

                # Check for goto :eof or goto dispatcher
                if isinstance(s, GotoNode):
                    tgt = s.target.lstrip(':').lower()
                    if tgt == 'eof':
                        is_terminal = True
                        payload_stmts.append(s)
                    elif tgt == dispatcher_label.lower():
                        jumps_to_dispatcher = True
                    else:
                        # Direct jump to another block
                        payload_stmts.append(s)
                    continue

                # Check for state variable mutation: set state=next_val
                if isinstance(s, AssignmentNode):
                    if s.var_name.lower() == state_var.lower():
                        next_state = s.raw_value.strip(' "\'')
                        continue  # Skip state assignment from payload!
                    else:
                        payload_stmts.append(s)
                        continue

                # Check for conditional state mutation: if cond (set state=A) else (set state=B)
                if isinstance(s, IfNode):
                    cond_state = self._extract_conditional_state_updates(s, state_var)
                    if cond_state:
                        cond_transitions.extend(cond_state)
                        continue  # Skip conditional state setter
                    else:
                        payload_stmts.append(s)
                        continue

                payload_stmts.append(s)

            blocks[state_val] = CFFBlockInfo(
                state_key=state_val,
                label_name=lbl_name,
                statements=payload_stmts,
                raw_statements=section_stmts,
                next_state=next_state,
                conditional_transitions=cond_transitions,
                is_terminal=is_terminal,
                jumps_to_dispatcher=jumps_to_dispatcher
            )

        return blocks

    def _extract_conditional_state_updates(
        self,
        node: IfNode,
        state_var: str
    ) -> Optional[List[Tuple[str, str]]]:
        """Extracts conditional state mutations like: if %x%==1 (set state=2) else (set state=3)."""
        transitions: List[Tuple[str, str]] = []

        then_val = self._extract_state_assignment_val(node.then_block, state_var)
        else_val = self._extract_state_assignment_val(node.else_block, state_var) if node.else_block else None

        if then_val:
            transitions.append((node.condition, then_val))
            if else_val:
                transitions.append((f"NOT ({node.condition})", else_val))
            return transitions

        return None

    def _extract_state_assignment_val(self, node: Optional[ASTNode], state_var: str) -> Optional[str]:
        if not node:
            return None
        if isinstance(node, AssignmentNode):
            if node.var_name.lower() == state_var.lower():
                return node.raw_value.strip(' "\'')
        if isinstance(node, BlockNode):
            for child in node.statements:
                v = self._extract_state_assignment_val(child, state_var)
                if v:
                    return v
        return None
