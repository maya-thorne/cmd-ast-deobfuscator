"""
Obfuscation Primitive Detector for AST-based & Lexical Command Obfuscation Analysis.
"""

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.ast_nodes import (
    ASTNode,
    AssignmentNode,
    BlockNode,
    CallNode,
    ChainNode,
    CommandNode,
    ForNode,
    GotoNode,
    IfNode,
    LabelNode,
    LiteralNode,
    ParamExpandNode,
    PipeNode,
    RedirectNode,
    ScriptNode,
    VarExpandNode,
)
from src.ioc.models import MitreAttackMapping, MitreTactic
from src.sigma.models import (
    ObfuscationPrimitive,
    ObfuscationPrimitiveType,
    ObfuscationScore,
    PrimitiveSeverity,
    SigmaAnalysisResult,
)


class ObfuscationPrimitiveDetector:
    """Detects and categorizes obfuscation primitives from batch scripts and AST nodes."""

    def __init__(self, min_confidence: float = 0.5):
        self.min_confidence = min_confidence
        self._primitives: List[ObfuscationPrimitive] = []
        self._mitre_cache: Dict[str, MitreAttackMapping] = {
            "T1027": MitreAttackMapping("T1027", "Obfuscated Files or Information", MitreTactic.DEFENSE_EVASION),
            "T1027.010": MitreAttackMapping("T1027.010", "Command Obfuscation", MitreTactic.DEFENSE_EVASION),
            "T1059.003": MitreAttackMapping("T1059.003", "Windows Command Shell", MitreTactic.EXECUTION),
            "T1140": MitreAttackMapping("T1140", "Deobfuscate/Decode Files or Information", MitreTactic.DEFENSE_EVASION),
            "T1564": MitreAttackMapping("T1564", "Hide Artifacts", MitreTactic.DEFENSE_EVASION),
            "T1105": MitreAttackMapping("T1105", "Ingress Tool Transfer", MitreTactic.COMMAND_AND_CONTROL),
        }

    def detect(
        self,
        ast_root: Optional[ASTNode] = None,
        source_text: str = "",
        source_file: Optional[str] = None,
    ) -> SigmaAnalysisResult:
        """Executes full detection across both AST structure and raw text source."""
        self._primitives.clear()

        # If source_text is provided and ast_root is None, auto-parse AST
        if ast_root is None and source_text:
            try:
                from src.parser import CmdASTParser
                ast_root = CmdASTParser.from_source(source_text).parse()
            except Exception:
                pass

        # 1. Structural AST analysis
        if ast_root:
            self._traverse_node(ast_root, line_num=1)

        # 2. Raw source text pattern analysis (for caret insertions, delimiters & encodings)
        if source_text:
            self._scan_raw_source(source_text)

        # 3. Deduplicate primitives by (type, line_number, matched_token)
        deduped = self._deduplicate_primitives(self._primitives)

        # Filter by confidence threshold
        final_primitives = [p for p in deduped if p.confidence >= self.min_confidence]

        # Calculate entropy
        entropy = self._compute_entropy(source_text) if source_text else 0.0

        # Calculate score
        score = ObfuscationScore.calculate(final_primitives, entropy=entropy)

        return SigmaAnalysisResult(
            primitives=final_primitives,
            score=score,
            rules=[],
            source_file=source_file,
            metadata={
                "entropy": entropy,
                "total_scanned_primitives": len(self._primitives),
            },
        )

    def _traverse_node(self, node: ASTNode, line_num: int = 1) -> None:
        """Recursively inspects AST nodes for syntactic obfuscation patterns."""
        if not node:
            return

        # 1. CommandNode: Check command target, argument fragments & concatenation
        if isinstance(node, CommandNode):
            self._inspect_command_node(node, line_num)

        # 2. VarExpandNode: Check variable slicing & delayed expansion
        elif isinstance(node, VarExpandNode):
            self._inspect_var_expand(node, line_num)

        # 3. ForNode: Check for string reversal loops
        elif isinstance(node, ForNode):
            self._inspect_for_node(node, line_num)

        # 4. AssignmentNode: Check arithmetic encoding & dead store bloat
        elif isinstance(node, AssignmentNode):
            self._inspect_assignment_node(node, line_num)

        # 5. CallNode: Check dynamic call trampolines
        elif isinstance(node, CallNode):
            self._inspect_call_node(node, line_num)

        # 6. RedirectNode: Check I/O stealth null devices
        elif isinstance(node, RedirectNode):
            self._inspect_redirect_node(node, line_num)

        # 7. LiteralNode: Check caret escaping and quote toggling in literals
        elif isinstance(node, LiteralNode):
            self._inspect_literal_node(node, line_num)

        # Recurse children
        for child in self._get_node_children(node):
            self._traverse_node(child, line_num)

    def _inspect_command_node(self, node: CommandNode, line_num: int) -> None:
        """Inspects CommandNode for target obfuscation and multi-part variable assembly."""
        # Check target for quote interleaving: "c"m"d"
        if node.target and '"' in node.target:
            if re.search(r'"[A-Za-z0-9]+"[A-Za-z0-9]+', node.target) or re.search(r'[A-Za-z0-9]+"[A-Za-z0-9]+"', node.target) or re.search(r'"[A-Za-z0-9]"', node.target):
                self._add_primitive(
                    ObfuscationPrimitiveType.QUOTE_INTERLEAVING,
                    PrimitiveSeverity.HIGH,
                    confidence=0.94,
                    description=f"Quote interleaving fragmentation inside command target: {node.target}",
                    line_number=line_num,
                    matched_token=node.target,
                    ast_node_type="CommandNode",
                    mitre=self._mitre_cache["T1027.010"],
                    weight=3.0,
                )

        all_parts = list(node.target_nodes) + list(node.arguments)
        var_count = sum(1 for p in all_parts if isinstance(p, VarExpandNode))
        if var_count >= 3:
            self._add_primitive(
                ObfuscationPrimitiveType.ENV_CONCATENATION,
                PrimitiveSeverity.HIGH,
                confidence=0.90,
                description=f"Command assembled from {var_count} concatenated environment variables",
                line_number=line_num,
                matched_token=f"{var_count} variable parts",
                ast_node_type="CommandNode",
                mitre=self._mitre_cache["T1027.010"],
                weight=3.5,
            )

        # Check arguments for dropper stubs (e.g. powershell -enc, certutil -decode)
        arg_text = " ".join(
            p.value if isinstance(p, LiteralNode) else (p.target if isinstance(p, CommandNode) else "")
            for p in node.arguments
        )
        if re.search(r"-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}", arg_text, re.IGNORECASE):
            self._add_primitive(
                ObfuscationPrimitiveType.SCRIPT_STUB_DROPPING,
                PrimitiveSeverity.CRITICAL,
                confidence=0.98,
                description="PowerShell encoded command execution stub detected",
                line_number=line_num,
                matched_token=arg_text[:40],
                ast_node_type="CommandNode",
                mitre=self._mitre_cache["T1059.003"],
                weight=5.0,
            )
        elif re.search(r"certutil.*-(?:decode|decodehex)", arg_text, re.IGNORECASE):
            self._add_primitive(
                ObfuscationPrimitiveType.SCRIPT_STUB_DROPPING,
                PrimitiveSeverity.CRITICAL,
                confidence=0.98,
                description="CertUtil payload decoder stub detected",
                line_number=line_num,
                matched_token=arg_text[:40],
                ast_node_type="CommandNode",
                mitre=self._mitre_cache["T1140"],
                weight=5.0,
            )

    def _inspect_var_expand(self, node: VarExpandNode, line_num: int) -> None:
        """Inspects VarExpandNode for substring slicing and character carving."""
        if node.slice_start is not None or node.slice_len is not None:
            start = node.slice_start
            length = node.slice_len
            var_name = node.name or "VAR"
            # Check for reverse / negative slicing: start < 0 or length < 0
            if (start is not None and start < 0) or (length is not None and length < 0):
                self._add_primitive(
                    ObfuscationPrimitiveType.REVERSE_SLICING,
                    PrimitiveSeverity.MEDIUM,
                    confidence=0.88,
                    description=f"Negative index substring slicing: %{var_name}:~{start},{length}%",
                    line_number=line_num,
                    matched_token=f"%{var_name}:~{start},{length}%",
                    ast_node_type="VarExpandNode",
                    mitre=self._mitre_cache["T1027"],
                    weight=2.0,
                )
            # Check for single-character extraction: length == 1
            elif length == 1:
                self._add_primitive(
                    ObfuscationPrimitiveType.SUBSTRING_SLICING,
                    PrimitiveSeverity.HIGH,
                    confidence=0.95,
                    description=f"Single-character substring carving: %{var_name}:~{start},{length}%",
                    line_number=line_num,
                    matched_token=f"%{var_name}:~{start},{length}%",
                    ast_node_type="VarExpandNode",
                    mitre=self._mitre_cache["T1027"],
                    weight=3.0,
                )
            else:
                self._add_primitive(
                    ObfuscationPrimitiveType.SUBSTRING_SLICING,
                    PrimitiveSeverity.MEDIUM,
                    confidence=0.80,
                    description=f"Variable substring slice extraction: %{var_name}:~{start},{length}%",
                    line_number=line_num,
                    matched_token=f"%{var_name}:~{start},{length}%",
                    ast_node_type="VarExpandNode",
                    mitre=self._mitre_cache["T1027"],
                    weight=2.0,
                )

    def _inspect_for_node(self, node: ForNode, line_num: int) -> None:
        """Inspects ForNode for string reversal and transposition loops."""
        is_loop_l = "/l" in (node.flags or "").lower()
        if is_loop_l and node.in_clause:
            clause = node.in_clause.strip()
            parts = [p.strip() for p in re.split(r"[, ]+", clause.strip("()")) if p.strip()]
            if len(parts) >= 2:
                try:
                    step = int(parts[1])
                    if step < 0:
                        self._add_primitive(
                            ObfuscationPrimitiveType.STRING_REVERSAL,
                            PrimitiveSeverity.HIGH,
                            confidence=0.95,
                            description=f"FOR /L reverse stepping loop detected: in ({clause})",
                            line_number=line_num,
                            matched_token=f"for /l in ({clause})",
                            ast_node_type="ForNode",
                            mitre=self._mitre_cache["T1140"],
                            weight=4.0,
                        )
                except ValueError:
                    pass

    def _inspect_assignment_node(self, node: AssignmentNode, line_num: int) -> None:
        """Inspects AssignmentNode for arithmetic encoding or dead store bloat."""
        if node.is_arithmetic:
            expr = node.raw_value or ""
            # Bitwise ops indicate arithmetic obfuscation
            if any(op in expr for op in ("^", "<<", ">>", "|", "&", "~")):
                self._add_primitive(
                    ObfuscationPrimitiveType.ARITHMETIC_ENCODING,
                    PrimitiveSeverity.MEDIUM,
                    confidence=0.88,
                    description=f"Bitwise arithmetic expression encoding: set /a {expr}",
                    line_number=line_num,
                    matched_token=f"set /a {expr[:30]}",
                    ast_node_type="AssignmentNode",
                    mitre=self._mitre_cache["T1027"],
                    weight=2.5,
                )
            elif "," in expr:
                self._add_primitive(
                    ObfuscationPrimitiveType.ARITHMETIC_ENCODING,
                    PrimitiveSeverity.LOW,
                    confidence=0.75,
                    description=f"Compound comma-separated arithmetic sequence: set /a {expr}",
                    line_number=line_num,
                    matched_token=f"set /a {expr[:30]}",
                    ast_node_type="AssignmentNode",
                    mitre=self._mitre_cache["T1027"],
                    weight=1.5,
                )

    def _inspect_call_node(self, node: CallNode, line_num: int) -> None:
        """Inspects CallNode for dynamic trampolines."""
        target_name = node.target or ""
        if target_name.startswith("%") or target_name.startswith("!") or node.is_dynamic:
            self._add_primitive(
                ObfuscationPrimitiveType.DYNAMIC_CALL_TRAMPOLINE,
                PrimitiveSeverity.HIGH,
                confidence=0.92,
                description=f"Dynamic CALL execution trampoline: call {target_name}",
                line_number=line_num,
                matched_token=f"call {target_name}",
                ast_node_type="CallNode",
                mitre=self._mitre_cache["T1059.003"],
                weight=3.5,
            )

    def _inspect_redirect_node(self, node: RedirectNode, line_num: int) -> None:
        """Inspects RedirectNode for I/O stealth suppression."""
        dest = (node.destination or "").strip().lower()
        if "nul" in dest:
            self._add_primitive(
                ObfuscationPrimitiveType.IO_STEALTH_REDIRECTION,
                PrimitiveSeverity.LOW,
                confidence=0.80,
                description="I/O stealth suppression redirecting stream to NUL device",
                line_number=line_num,
                matched_token=f"{node.stream} {node.destination}",
                ast_node_type="RedirectNode",
                mitre=self._mitre_cache["T1564"],
                weight=1.0,
            )

    def _inspect_literal_node(self, node: LiteralNode, line_num: int) -> None:
        """Inspects LiteralNode for caret masking and quote interleaving."""
        val = node.value or ""
        # Quote interleaving within a word: "c"m"d"
        if re.search(r'[A-Za-z0-9]"[A-Za-z0-9]', val) or re.search(r'""[A-Za-z0-9]', val):
            self._add_primitive(
                ObfuscationPrimitiveType.QUOTE_INTERLEAVING,
                PrimitiveSeverity.HIGH,
                confidence=0.92,
                description=f"Quote interleaving fragmentation inside token: {val}",
                line_number=line_num,
                matched_token=val[:30],
                ast_node_type="LiteralNode",
                mitre=self._mitre_cache["T1027.010"],
                weight=3.0,
            )

    def _scan_raw_source(self, text: str) -> None:
        """Performs lexical pattern scanning across raw source lines."""
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            sline = line.strip()
            if not sline or sline.startswith("::") or sline.lower().startswith("rem "):
                continue

            # 1. Caret insertion pattern: c^m^d or nested carets ^^^
            if "^^^" in sline or re.search(r"[A-Za-z0-9]\^[A-Za-z0-9]", sline):
                carets = re.findall(r"(?:[A-Za-z0-9]\^)+[A-Za-z0-9]", sline)
                matched = carets[0] if carets else "^^^"
                self._add_primitive(
                    ObfuscationPrimitiveType.CARET_INSERTION,
                    PrimitiveSeverity.HIGH,
                    confidence=0.94,
                    description=f"Character-level caret insertion obfuscation: {matched}",
                    line_number=idx,
                    matched_token=matched[:30],
                    ast_node_type="RawSource",
                    mitre=self._mitre_cache["T1027.010"],
                    weight=3.0,
                )

            # 1b. Quote interleaving pattern in raw source: "c"m"d" or ""w""h""
            if re.search(r'"[A-Za-z0-9]+"[A-Za-z0-9]+', sline) or re.search(r'[A-Za-z0-9]+"[A-Za-z0-9]+"', sline):
                quote_matches = re.findall(r'(?:[A-Za-z0-9]*"[A-Za-z0-9]+"[A-Za-z0-9]*)+', sline)
                matched = quote_matches[0] if quote_matches else '""'
                self._add_primitive(
                    ObfuscationPrimitiveType.QUOTE_INTERLEAVING,
                    PrimitiveSeverity.HIGH,
                    confidence=0.92,
                    description=f"Quote interleaving fragmentation inside token: {matched}",
                    line_number=idx,
                    matched_token=matched[:30],
                    ast_node_type="RawSource",
                    mitre=self._mitre_cache["T1027.010"],
                    weight=3.0,
                )

            # 2. Delimiter scrambling: cmd,/,c,whoami or cmd;/,c;
            if re.search(r"cmd(?:\.exe)?(?:[,;=]+[/\w]+)+", sline, re.IGNORECASE) or re.search(r"^[a-zA-Z0-9_\.]+(?:[,;=]\s*)+", sline):
                if any(delim in sline for delim in (",", ";", "=")) and ("cmd" in sline.lower() or "/" in sline):
                    self._add_primitive(
                        ObfuscationPrimitiveType.DELIMITER_SCRAMBLING,
                        PrimitiveSeverity.MEDIUM,
                        confidence=0.88,
                        description="Scrambled delimiter separation (, ; =) in command line",
                        line_number=idx,
                        matched_token=sline[:35],
                        ast_node_type="RawSource",
                        mitre=self._mitre_cache["T1027.010"],
                        weight=2.5,
                    )

            # 3. Environment variable concatenation: %a%%b%%c%%d%
            concat_match = re.search(r"(?:%[a-zA-Z0-9_#@]+%){3,}", sline)
            if concat_match:
                self._add_primitive(
                    ObfuscationPrimitiveType.ENV_CONCATENATION,
                    PrimitiveSeverity.HIGH,
                    confidence=0.92,
                    description="Environment variable fragment concatenation chain",
                    line_number=idx,
                    matched_token=concat_match.group(0)[:35],
                    ast_node_type="RawSource",
                    mitre=self._mitre_cache["T1027.010"],
                    weight=3.5,
                )

            # 4. Multi-stealth redirection: >nul 2>&1
            if ">nul" in sline.lower() and ("2>&1" in sline or "2>nul" in sline.lower()):
                self._add_primitive(
                    ObfuscationPrimitiveType.IO_STEALTH_REDIRECTION,
                    PrimitiveSeverity.MEDIUM,
                    confidence=0.85,
                    description="Dual stdout/stderr output suppression to NUL device",
                    line_number=idx,
                    matched_token=">nul 2>&1",
                    ast_node_type="RawSource",
                    mitre=self._mitre_cache["T1564"],
                    weight=1.5,
                )

    def _add_primitive(
        self,
        p_type: ObfuscationPrimitiveType,
        severity: PrimitiveSeverity,
        confidence: float,
        description: str,
        line_number: int,
        matched_token: str,
        ast_node_type: str = "",
        mitre: Optional[MitreAttackMapping] = None,
        weight: float = 1.0,
    ) -> None:
        """Appends a newly detected primitive to internal collector."""
        p = ObfuscationPrimitive(
            primitive_type=p_type,
            severity=severity,
            confidence=confidence,
            description=description,
            line_number=line_number,
            matched_token=matched_token,
            ast_node_type=ast_node_type,
            mitre_attack=mitre,
            weight=weight,
        )
        self._primitives.append(p)

    def _get_node_children(self, node: ASTNode) -> List[ASTNode]:
        """Collects immediate child nodes for recursive descent."""
        children: List[ASTNode] = []
        if isinstance(node, ScriptNode):
            children.extend(node.statements)
        elif isinstance(node, BlockNode):
            children.extend(node.statements)
        elif isinstance(node, ChainNode):
            if node.left:
                children.append(node.left)
            if node.right:
                children.append(node.right)
        elif isinstance(node, PipeNode):
            if node.left:
                children.append(node.left)
            if node.right:
                children.append(node.right)
        elif isinstance(node, IfNode):
            if node.then_block:
                children.append(node.then_block)
            if node.else_block:
                children.append(node.else_block)
        elif isinstance(node, ForNode):
            if node.body:
                children.append(node.body)
        elif isinstance(node, CommandNode):
            children.extend(node.target_nodes)
            children.extend(node.arguments)
        elif isinstance(node, AssignmentNode):
            children.extend(node.value_nodes)
        elif isinstance(node, CallNode):
            children.extend(node.target_nodes)
            children.extend(node.arguments)
        elif isinstance(node, GotoNode):
            children.extend(node.target_nodes)
        elif isinstance(node, RedirectNode):
            if node.command:
                children.append(node.command)
        return children

    @staticmethod
    def _deduplicate_primitives(primitives: List[ObfuscationPrimitive]) -> List[ObfuscationPrimitive]:
        """Eliminates redundant duplicates sharing type, line, and token."""
        seen: Set[Tuple[str, int, str]] = set()
        deduped: List[ObfuscationPrimitive] = []
        for p in primitives:
            p_type = p.primitive_type.value if isinstance(p.primitive_type, ObfuscationPrimitiveType) else str(p.primitive_type)
            key = (p_type, p.line_number, p.matched_token.strip())
            if key not in seen:
                seen.add(key)
                deduped.append(p)
        return deduped

    @staticmethod
    def _compute_entropy(text: str) -> float:
        """Computes Shannon entropy across characters."""
        if not text:
            return 0.0
        frequencies: Dict[str, int] = {}
        for c in text:
            frequencies[c] = frequencies.get(c, 0) + 1
        total = len(text)
        entropy = 0.0
        for count in frequencies.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy
