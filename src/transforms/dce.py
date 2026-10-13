"""
Dead Code Elimination (DCE) and Unreferenced SET Pruning Optimization Pass.
Identifies unused variable definitions, eliminates overwritten dead stores,
prunes unreachable statements following unconditional control transfers,
and collapses redundant blocks.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import re

from ..ast_nodes import (
    ASTVisitor, ASTNode, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode,
    CommentNode, IfNode, ForNode, ParamExpandNode, LabelNode, GotoNode,
    CallNode, ExitNode
)
from .base import TransformPass


# Standard Windows system and dynamic environment variables that should
# typically be preserved unless explicitly marked for pruning.
DEFAULT_PRESERVE_VARS: Set[str] = {
    'comspec', 'path', 'pathext', 'systemroot', 'windir', 'temp', 'tmp',
    'errorlevel', 'cd', 'date', 'time', 'random', 'cmdcmdline',
    'cmdextversion', 'prompt', 'username', 'userprofile', 'allusersprofile',
    'programdata', 'programfiles', 'os', 'computername', 'appdata',
    'localappdata', 'homedrive', 'homepath', 'systemdrive'
}


@dataclass
class DCEMetrics:
    """Summary metrics of dead code and dead store pruning operations."""
    pruned_assignments: int = 0
    pruned_overwrites: int = 0
    pruned_unreachable: int = 0
    pruned_empty_blocks: int = 0
    pruned_variable_names: List[str] = field(default_factory=list)
    iterations: int = 0

    @property
    def total_pruned(self) -> int:
        return (
            self.pruned_assignments +
            self.pruned_overwrites +
            self.pruned_unreachable +
            self.pruned_empty_blocks
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_pruned': self.total_pruned,
            'pruned_assignments': self.pruned_assignments,
            'pruned_overwrites': self.pruned_overwrites,
            'pruned_unreachable': self.pruned_unreachable,
            'pruned_empty_blocks': self.pruned_empty_blocks,
            'pruned_variable_names': sorted(list(set(self.pruned_variable_names))),
            'iterations': self.iterations,
        }

    def summary(self) -> str:
        parts = [
            f"Total pruned items: {self.total_pruned}",
            f"Unreferenced SET statements: {self.pruned_assignments}",
            f"Overwritten dead stores: {self.pruned_overwrites}",
            f"Unreachable branch statements: {self.pruned_unreachable}",
            f"Empty blocks collapsed: {self.pruned_empty_blocks}",
            f"Iterations: {self.iterations}",
        ]
        if self.pruned_variable_names:
            unique_vars = sorted(list(set(self.pruned_variable_names)))
            parts.append(f"Pruned variables: {', '.join(unique_vars)}")
        return "\n".join(parts)


class VariableLivenessAnalyzer(ASTVisitor):
    """
    Collects all variable references (reads / uses) across an AST hierarchy.
    Inspects variable expansion nodes, dynamic commands, conditional tests,
    parameter modifier path specifications, and literal expressions.
    """
    def __init__(self):
        self.uses: Set[str] = set()

    def analyze(self, root: ASTNode) -> Set[str]:
        """Scans the AST and returns a set of lowercased referenced variable names."""
        self.uses = set()
        if root is not None:
            self.visit(root)
        return set(self.uses)

    def _extract_embedded_vars(self, text: Optional[str]) -> None:
        if not text:
            return
        # Match %VAR% and !VAR! with optional slicing/substitution
        for m in re.finditer(r'[%!]([a-zA-Z0-9_#$@.-]+)(?::[^%!]+)?[%!]', text):
            self.uses.add(m.group(1).lower())
        # Match "defined VAR" or "not defined VAR" in IF statements
        for m in re.finditer(r'(?i)\bdefined\s+([a-zA-Z0-9_#$@.-]+)', text):
            self.uses.add(m.group(1).lower())
        # Check errorlevel reference
        if re.search(r'(?i)\berrorlevel\b', text):
            self.uses.add('errorlevel')

    def visit_VarExpandNode(self, node: VarExpandNode) -> None:
        self.uses.add(node.name.lower())
        if '%' in node.name or '!' in node.name:
            self._extract_embedded_vars(node.name)
        if node.slice_start_expr:
            self._extract_embedded_vars(node.slice_start_expr)
        if node.slice_len_expr:
            self._extract_embedded_vars(node.slice_len_expr)
        if node.sub_search:
            self._extract_embedded_vars(node.sub_search)
        if node.sub_replace:
            self._extract_embedded_vars(node.sub_replace)

    def visit_LiteralNode(self, node: LiteralNode) -> None:
        self._extract_embedded_vars(node.value)

    def visit_CommandNode(self, node: CommandNode) -> None:
        self._extract_embedded_vars(node.target)
        if node.target_nodes:
            for t in node.target_nodes:
                self.visit(t)
        for arg in node.arguments:
            self.visit(arg)

    def visit_AssignmentNode(self, node: AssignmentNode) -> None:
        # The RHS of an assignment uses variables
        if node.value_nodes:
            for v in node.value_nodes:
                self.visit(v)
        else:
            self._extract_embedded_vars(node.raw_value)
        # Arithmetic expressions (set /a x=y+1) can reference variables without percent delimiters
        if node.is_arithmetic and node.raw_value:
            for word in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', node.raw_value):
                # Exclude purely numeric hex (0x...) or decimal
                if not re.match(r'^(0x[0-9a-fA-F]+|\d+)$', word):
                    self.uses.add(word.lower())

    def visit_IfNode(self, node: IfNode) -> None:
        self._extract_embedded_vars(node.condition)
        if node.then_block:
            self.visit(node.then_block)
        if node.else_block:
            self.visit(node.else_block)

    def visit_ForNode(self, node: ForNode) -> None:
        self._extract_embedded_vars(node.in_clause)
        self._extract_embedded_vars(node.options)
        if node.body:
            self.visit(node.body)

    def visit_ParamExpandNode(self, node: ParamExpandNode) -> None:
        if node.modifiers and '$' in node.modifiers:
            # e.g. ~$PATH:1 -> uses PATH variable
            m = re.search(r'\$([a-zA-Z0-9_]+):', node.modifiers)
            if m:
                self.uses.add(m.group(1).lower())

    def visit_GotoNode(self, node: GotoNode) -> None:
        if node.is_dynamic:
            self._extract_embedded_vars(node.target)
        if node.target_nodes:
            for t in node.target_nodes:
                self.visit(t)

    def visit_CallNode(self, node: CallNode) -> None:
        if node.is_dynamic:
            self._extract_embedded_vars(node.target)
        if node.target_nodes:
            for t in node.target_nodes:
                self.visit(t)
        for arg in node.arguments:
            self.visit(arg)

    def visit_RedirectNode(self, node: RedirectNode) -> None:
        self._extract_embedded_vars(node.destination)
        if node.command:
            self.visit(node.command)

    def visit_ChainNode(self, node: ChainNode) -> None:
        if node.left:
            self.visit(node.left)
        if node.right:
            self.visit(node.right)

    def visit_PipeNode(self, node: PipeNode) -> None:
        if node.left:
            self.visit(node.left)
        if node.right:
            self.visit(node.right)

    def visit_BlockNode(self, node: BlockNode) -> None:
        for stmt in node.statements:
            if stmt:
                self.visit(stmt)

    def visit_ScriptNode(self, node: ScriptNode) -> None:
        for stmt in node.statements:
            if stmt:
                self.visit(stmt)

    def visit_LabelNode(self, node: LabelNode) -> None:
        pass

    def visit_ExitNode(self, node: ExitNode) -> None:
        if node.exit_code:
            self._extract_embedded_vars(str(node.exit_code))

    def visit_CommentNode(self, node: CommentNode) -> None:
        pass

    def generic_visit(self, node: ASTNode) -> None:
        pass



class DeadCodeEliminationPass(TransformPass):
    """
    Compiler optimization pass implementing Dead Code Elimination (DCE).
    Prunes:
      1. Unreferenced variable assignments (set VAR=VAL when VAR is never used).
      2. Overwritten dead stores (set VAR=1 followed by set VAR=2 with no reads in between).
      3. Unreachable statements following unconditional control flow transfers.
      4. Redundant empty blocks.
    """
    def __init__(
        self,
        name: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        preserve_vars: Optional[Set[str]] = None,
        prune_unreferenced: bool = True,
        prune_overwrites: bool = True,
        prune_unreachable: bool = True,
        prune_empty_blocks: bool = True,
        max_iterations: int = 10
    ):
        super().__init__(name=name, env=env)
        self.preserve_vars: Set[str] = set(DEFAULT_PRESERVE_VARS)
        if preserve_vars:
            for v in preserve_vars:
                self.preserve_vars.add(v.lower())
        self.prune_unreferenced = prune_unreferenced
        self.prune_overwrites = prune_overwrites
        self.prune_unreachable = prune_unreachable
        self.prune_empty_blocks = prune_empty_blocks
        self.max_iterations = max_iterations
        self.metrics = DCEMetrics()
        self.analyzer = VariableLivenessAnalyzer()
        self.current_uses: Set[str] = set()

    def transform(self, root: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        """Runs iterative fixed-point dead code elimination on the root AST."""
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v

        current_ast = root
        for _ in range(self.max_iterations):
            self.modified = False
            # Recompute global liveness for the current AST state
            self.current_uses = self.analyzer.analyze(current_ast)
            new_ast = self.visit(current_ast)
            if self.modified:
                self.metrics.iterations += 1
                current_ast = new_ast
            else:
                break
        return current_ast

    def _is_unconditional_terminator(self, node: ASTNode) -> bool:
        if isinstance(node, ExitNode):
            return True
        if isinstance(node, GotoNode) and not node.is_dynamic:
            return True
        if isinstance(node, CommandNode) and node.target.strip().lower() == 'exit':
            return True
        return False

    def _clean_statement_list(self, statements: List[ASTNode]) -> List[ASTNode]:
        if not statements:
            return []

        # -------------------------------------------------------------
        # Phase 1: Unreachable statement pruning
        # -------------------------------------------------------------
        phase1_stmts: List[ASTNode] = []
        is_unreachable = False

        for stmt in statements:
            if stmt is None:
                continue

            if self.prune_unreachable and is_unreachable:
                # Labels are reachable jump targets from elsewhere
                if isinstance(stmt, LabelNode):
                    is_unreachable = False
                    phase1_stmts.append(stmt)
                else:
                    self.metrics.pruned_unreachable += 1
                    self.modified = True
                    continue
            else:
                phase1_stmts.append(stmt)
                if self.prune_unreachable and self._is_unconditional_terminator(stmt):
                    is_unreachable = True

        # -------------------------------------------------------------
        # Phase 2: Overwritten dead store pruning
        # -------------------------------------------------------------
        phase2_stmts: List[ASTNode] = []
        dead_indices: Set[int] = set()

        if self.prune_overwrites:
            n = len(phase1_stmts)
            for i in range(n):
                stmt_i = phase1_stmts[i]
                if not isinstance(stmt_i, AssignmentNode):
                    continue

                vname = stmt_i.var_name.lower()
                # Check if there is a later assignment to the exact same variable
                for j in range(i + 1, n):
                    stmt_j = phase1_stmts[j]

                    # Branching / control flow barriers stop safe linear dead store analysis
                    if isinstance(stmt_j, (LabelNode, GotoNode, CallNode, IfNode, ForNode, ExitNode)):
                        break

                    # Check if intermediate statement reads vname
                    intermediate_uses = self.analyzer.analyze(stmt_j)
                    if vname in intermediate_uses:
                        break

                    # If stmt_j reassigns vname without any intermediate read, stmt_i was dead!
                    if isinstance(stmt_j, AssignmentNode) and stmt_j.var_name.lower() == vname:
                        dead_indices.add(i)
                        self.metrics.pruned_overwrites += 1
                        self.modified = True
                        break

        for idx, stmt in enumerate(phase1_stmts):
            if idx not in dead_indices:
                phase2_stmts.append(stmt)

        # -------------------------------------------------------------
        # Phase 3: Recursive statement transformation & filtering
        # -------------------------------------------------------------
        phase3_stmts: List[ASTNode] = []

        for stmt in phase2_stmts:
            visited = self.visit(stmt)
            if visited is not None:
                phase3_stmts.append(visited)

        return phase3_stmts

    def visit_AssignmentNode(self, node: AssignmentNode) -> Optional[ASTNode]:
        if self.prune_unreferenced:
            vkey = node.var_name.lower()
            if vkey not in self.current_uses and vkey not in self.preserve_vars:
                self.metrics.pruned_assignments += 1
                self.metrics.pruned_variable_names.append(node.var_name)
                self.modified = True
                return None
        return node


    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        cleaned = self._clean_statement_list(node.statements)
        if cleaned != node.statements:
            self.modified = True
            return ScriptNode(statements=cleaned, span=node.span)
        return node

    def visit_BlockNode(self, node: BlockNode) -> Optional[ASTNode]:
        cleaned = self._clean_statement_list(node.statements)
        if self.prune_empty_blocks and not cleaned:
            self.metrics.pruned_empty_blocks += 1
            self.modified = True
            return None
        if cleaned != node.statements:
            self.modified = True
            return BlockNode(statements=cleaned, span=node.span)
        return node

    def visit_ChainNode(self, node: ChainNode) -> Optional[ASTNode]:
        left = self.visit(node.left)
        right = self.visit(node.right)

        if left is None and right is None:
            self.metrics.pruned_empty_blocks += 1
            self.modified = True
            return None
        if left is None:
            self.modified = True
            return right
        if right is None:
            self.modified = True
            return left

        # If left is an unconditional terminator in & or && chains, right is unreachable
        if self.prune_unreachable and node.operator in ('&', '&&') and self._is_unconditional_terminator(left):
            self.metrics.pruned_unreachable += 1
            self.modified = True
            return left

        if left is not node.left or right is not node.right:
            self.modified = True
            return ChainNode(left=left, operator=node.operator, right=right, span=node.span)
        return node

    def visit_PipeNode(self, node: PipeNode) -> Optional[ASTNode]:
        left = self.visit(node.left)
        right = self.visit(node.right)

        if left is None:
            self.modified = True
            return right
        if right is None:
            self.modified = True
            return left

        if left is not node.left or right is not node.right:
            self.modified = True
            return PipeNode(left=left, right=right, span=node.span)
        return node

    def visit_IfNode(self, node: IfNode) -> IfNode:
        then_b = self.visit(node.then_block)
        else_b = self.visit(node.else_block) if node.else_block else None
        if then_b is not node.then_block or else_b is not node.else_block:
            self.modified = True
            return IfNode(condition=node.condition, then_block=then_b, else_block=else_b, span=node.span)
        return node

    def visit_ForNode(self, node: ForNode) -> ForNode:
        body_node = self.visit(node.body) if node.body else None
        if body_node is not node.body:
            self.modified = True
            return ForNode(
                iterator=node.iterator,
                flags=node.flags,
                options=node.options,
                in_clause=node.in_clause,
                body=body_node,
                span=node.span
            )
        return node


def eliminate_dead_code(
    ast: ASTNode,
    preserve_vars: Optional[Set[str]] = None,
    env: Optional[Dict[str, str]] = None,
    **kwargs
) -> ASTNode:
    """Convenience helper function to run dead code elimination on an AST."""
    pass_instance = DeadCodeEliminationPass(
        preserve_vars=preserve_vars,
        env=env,
        **kwargs
    )
    return pass_instance.transform(ast)
