"""
Control Flow De-flattening & Packer Extraction AST Transform Pass.
Integrates PackerSignatureDetector, PackerUnpacker, CFFAnalyzer, and CFFLinearizer
into the unified TransformPass and PassManager optimization pipeline.
"""

from typing import List, Dict, Optional, Set
from .base import TransformPass
from ..ast_nodes import (
    ASTNode, ScriptNode, BlockNode, LabelNode, AssignmentNode,
    CommandNode, IfNode, GotoNode, ExitNode
)
from ..packers import (
    PackerSignatureDetector,
    PackerUnpacker,
    PackerDetectionResult,
    PackerType,
    MultiStagePackerEngine,
    LayeredUnpackResult,
)
from ..cff import (
    CFFAnalyzer, CFFLinearizer, CFFStateMachine, DeflatResult,
    DeflatMetrics, CFFUnrollConfig
)


class DeflatPass(TransformPass):
    """
    AST Optimization pass that identifies 0xidiz3r / batch packer wrappers,
    extracts packed payloads, and linearizes Control Flow Flattening (CFF) state machines.
    """

    def __init__(
        self,
        env: Optional[Dict[str, str]] = None,
        config: Optional[CFFUnrollConfig] = None
    ):
        super().__init__(name="DeflatPass", env=env)
        self.config = config or CFFUnrollConfig()
        self.detector = PackerSignatureDetector()
        self.packer_engine = MultiStagePackerEngine(detector=self.detector)
        self.unpacker = PackerUnpacker(detector=self.detector, engine=self.packer_engine)
        self.cff_analyzer = CFFAnalyzer()
        self.linearizer = CFFLinearizer(config=self.config)
        self.deflat_metrics = DeflatMetrics()
        self.packer_detection: Optional[PackerDetectionResult] = None
        self.layered_unpack_result: Optional[LayeredUnpackResult] = None

    def transform(self, root: ASTNode, env: Optional[Dict[str, str]] = None) -> ASTNode:
        """Runs packer inspection, multi-stage unpacking, and CFF de-flattening."""
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v
        self.modified = False

        # Phase 1: Multi-stage recursive unpacking (CertUtil base64/hex, PowerShell, droppers, 0xidiz3r)
        source = self.to_source(root)
        self.layered_unpack_result = self.packer_engine.unpack(source)
        self.packer_detection = self.unpacker.unpack(source)

        if self.layered_unpack_result and self.layered_unpack_result.layers_unpacked > 0:
            from ..parser import CmdASTParser
            try:
                new_ast = CmdASTParser.from_source(self.layered_unpack_result.final_source).parse()
                root = new_ast
                self.modified = True
            except Exception:
                pass  # Fall back to original AST if re-parse encounters non-standard syntax

        # Phase 2: CFF State Machine Detection and Linearization
        return self.visit(root)

    def visit_ScriptNode(self, node: ScriptNode) -> ScriptNode:
        """Detects and linearizes CFF state machines within script statements."""
        state_machine = self.cff_analyzer.analyze(node)
        if not state_machine:
            return node

        deflat_res = self.linearizer.linearize(state_machine, config=self.config)
        if not deflat_res.success or not deflat_res.linearized_nodes:
            return node

        self.deflat_metrics = deflat_res.metrics
        self.modified = True

        # Reconstruct script: keep external preamble and postamble, replace CFF labels
        new_stmts = self._splice_linearized_statements(node.statements, state_machine, deflat_res.linearized_nodes)
        return ScriptNode(statements=new_stmts, span=node.span)

    def visit_BlockNode(self, node: BlockNode) -> BlockNode:
        """Detects and linearizes CFF inside parenthesized blocks."""
        state_machine = self.cff_analyzer.analyze(node)
        if not state_machine:
            return node

        deflat_res = self.linearizer.linearize(state_machine, config=self.config)
        if not deflat_res.success or not deflat_res.linearized_nodes:
            return node

        self.deflat_metrics = deflat_res.metrics
        self.modified = True

        new_stmts = self._splice_linearized_statements(node.statements, state_machine, deflat_res.linearized_nodes)
        return BlockNode(statements=new_stmts, span=node.span)

    def _splice_linearized_statements(
        self,
        original_stmts: List[ASTNode],
        state_machine: CFFStateMachine,
        linearized_nodes: List[ASTNode]
    ) -> List[ASTNode]:
        """
        Replaces CFF dispatcher and state handler statements with linearized payload nodes,
        preserving any statements or subroutines that are independent of the CFF state machine.
        """
        result: List[ASTNode] = []
        cff_labels_lower = {lbl.lower() for lbl in state_machine.all_cff_labels}
        cff_inserted = False
        in_cff_section = False

        for stmt in original_stmts:
            if isinstance(stmt, LabelNode):
                clean_lbl = stmt.name.lstrip(':').lower()
                if clean_lbl in cff_labels_lower:
                    in_cff_section = True
                    if not cff_inserted:
                        # Insert the fully linearized de-flattened logic here
                        result.extend(linearized_nodes)
                        cff_inserted = True
                    continue
                else:
                    # Encountered non-CFF label (e.g. independent subroutine)
                    in_cff_section = False
                    result.append(stmt)
                    continue

            if in_cff_section:
                # Statements inside CFF labels are discarded in favor of linearized_nodes
                continue

            # Check if this statement is the initial state variable assignment (e.g. set state=1)
            if isinstance(stmt, AssignmentNode):
                if stmt.var_name.lower() == state_machine.state_var.lower():
                    # Dead initial state assignment discarded
                    continue

            # Check if this statement is a goto to the dispatcher before the CFF block
            if isinstance(stmt, GotoNode):
                tgt = stmt.target.lstrip(':').lower()
                if tgt == state_machine.dispatcher_label.lower():
                    # Dead entry jump discarded
                    continue

            result.append(stmt)

        if not cff_inserted:
            # Fallback in case dispatcher wasn't a standard label
            result.extend(linearized_nodes)

        return result
