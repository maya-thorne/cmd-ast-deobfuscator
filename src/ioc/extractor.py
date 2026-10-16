"""
AST-based Malware Indicator of Compromise (IOC) Extractor for cmd.exe scripts.
Performs syntax tree traversal, parameter analysis, LOLBin identification,
file drop heuristics, and MITRE ATT&CK behavior mapping.
"""

import bisect
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..ast_nodes import (
    ASTNode,
    ASTVisitor,
    AssignmentNode,
    BlockNode,
    CallNode,
    ChainNode,
    CommandNode,
    ForNode,
    GotoNode,
    IfNode,
    LiteralNode,
    ParamExpandNode,
    PipeNode,
    RedirectNode,
    ScriptNode,
    VarExpandNode,
)
from ..parser import CmdASTParser
from .models import (
    IOCExtractionResult,
    IOCItem,
    IOCMetrics,
    IOCSeverity,
    IOCType,
    MitreAttackMapping,
    MitreTactic,
)
from .patterns import (
    CMD_ARG_TOKEN_REGEX,
    DOMAIN_REGEX,
    EMAIL_REGEX,
    EXECUTABLE_EXTENSIONS,
    FILE_DROP_REGEX,
    IPV4_REGEX,
    IPV6_REGEX,
    KNOWN_SYSTEM_DLLS,
    KNOWN_WINDOWS_COM_FILES,
    LOLBIN_REGISTRY,
    MD5_REGEX,
    MITRE_CATALOG,
    POWERSHELL_DOWNLOADFILE_REGEX,
    POWERSHELL_OUTFILE_REGEX,
    REGISTRY_KEY_REGEX,
    RUNNER_BINS,
    SHA1_REGEX,
    SHA256_REGEX,
    SUSPICIOUS_CMD_PATTERNS,
    URL_REGEX,
    get_mitre_mapping,
)



class IOCExtractor(ASTVisitor):
    """
    Extracts malware IOCs and MITRE ATT&CK tactics from cmd.exe AST trees.
    Combines AST structural node inspection with regex heuristics.
    """

    def __init__(self, min_confidence: float = 0.0):
        self.min_confidence = min_confidence
        self.iocs: List[IOCItem] = []
        self.current_line: Optional[int] = None
        self.source_file: Optional[str] = None
        self._line_offsets: List[int] = []

    def extract_from_ast(self, root: ASTNode, source_file: Optional[str] = None, source_text: Optional[str] = None) -> IOCExtractionResult:
        """Traverses the given AST root and collects all malware indicators."""
        self.iocs.clear()
        self.source_file = source_file
        if source_text:
            self._line_offsets = [0] + [m.end() for m in re.finditer(r"\n", source_text)]
        self.visit(root)
        return self._build_result()

    def extract_from_source(self, source: str, source_file: Optional[str] = None) -> IOCExtractionResult:
        """Parses batch source code to AST and performs comprehensive IOC extraction."""
        parser = CmdASTParser.from_source(source)
        ast = parser.parse()
        self.extract_from_ast(ast, source_file=source_file, source_text=source)
        self._scan_raw_source_fallback(source)
        return self._build_result()

    def _build_result(self) -> IOCExtractionResult:
        """Consolidates deduplicated IOCs and computes telemetry metrics."""
        filtered = [i for i in self.iocs if i.confidence >= self.min_confidence]
        metrics = IOCMetrics.from_iocs(filtered)
        return IOCExtractionResult(iocs=filtered, metrics=metrics, source_file=self.source_file)

    def _add_ioc(self, item: IOCItem) -> None:
        """Deduplicates and registers an extracted indicator."""
        if not item.line_number and self.current_line:
            item.line_number = self.current_line
        tid = item.mitre_attack.technique_id if item.mitre_attack else ""
        item_val = item.value.lower().strip()
        for ex in self.iocs:
            if (ex.ioc_type, ex.value.lower().strip()) == (item.ioc_type, item_val):
                ex_tid = ex.mitre_attack.technique_id if ex.mitre_attack else ""
                if ex_tid == tid or (not ex_tid and tid):
                    if not ex_tid and tid:
                        ex.mitre_attack = item.mitre_attack
                    ex.confidence = max(ex.confidence, item.confidence)
                    return
        self.iocs.append(item)

    # =========================================================================
    # AST Visitor Node Handlers
    # =========================================================================

    def visit(self, node: ASTNode) -> Any:
        if hasattr(node, "span") and node.span and node.span != (0, 0) and self._line_offsets:
            self.current_line = bisect.bisect_right(self._line_offsets, node.span[0])
        return super().visit(node)

    def generic_visit(self, node: ASTNode) -> None:
        for attr, value in node.__dict__.items():
            if isinstance(value, ASTNode):
                self.visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ASTNode):
                        self.visit(item)

    def visit_ScriptNode(self, node: ScriptNode) -> None:
        for stmt in node.statements:
            self.visit(stmt)

    visit_BlockNode = visit_ScriptNode

    def visit_ChainNode(self, node: ChainNode) -> None:
        self.visit(node.left)
        self.visit(node.right)

    visit_PipeNode = visit_ChainNode

    def visit_IfNode(self, node: IfNode) -> None:
        if node.condition:
            self._scan_text_for_iocs(node.condition, context="IF condition")
        if node.then_block:
            self.visit(node.then_block)
        if node.else_block:
            self.visit(node.else_block)

    def visit_ForNode(self, node: ForNode) -> None:
        if node.in_clause:
            self._scan_text_for_iocs(node.in_clause, context="FOR in-clause")
        if node.body:
            self.visit(node.body)

    def visit_AssignmentNode(self, node: AssignmentNode) -> None:
        full_text = f"{node.var_name}={node.raw_value}"
        self._scan_text_for_iocs(node.raw_value, context=f"SET {full_text}")
        for v in node.value_nodes:
            self.visit(v)

    def visit_RedirectNode(self, node: RedirectNode) -> None:
        dest = node.destination.strip(' "\'')
        dest_lower = dest.lower()
        is_exec = any(dest_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS)
        is_temp = any(t in dest_lower for t in ("%temp%", "%tmp%", "%appdata%", "users\\public", "windows\\temp"))

        if is_exec or (is_temp and "." in dest):
            mitre = get_mitre_mapping("T1059.003")
            self._add_ioc(IOCItem(
                ioc_type=IOCType.FILE_DROP,
                value=dest,
                context=f"Redirection ({node.stream} {dest})",
                confidence=0.95 if is_exec else 0.80,
                severity=IOCSeverity.HIGH if is_exec else IOCSeverity.MEDIUM,
                mitre_attack=mitre,
                tags=["file_drop", "stream_redirect"],
            ))
        if node.command:
            self.visit(node.command)

    def _visit_cmd(self, target: str, args: List[ASTNode], prefix: str = "") -> None:
        clean_t = target.strip()
        arg_str = self._reconstruct_arguments(args)
        cmd_line = f"{prefix}{clean_t} {arg_str}".strip()
        self._analyze_command_target_and_args(clean_t, arg_str, cmd_line)
        for arg in args:
            self.visit(arg)

    def visit_CallNode(self, node: CallNode) -> None:
        self._visit_cmd(node.target, node.arguments, prefix="call ")

    def visit_CommandNode(self, node: CommandNode) -> None:
        self._visit_cmd(node.target, node.arguments)


    def visit_LiteralNode(self, node: LiteralNode) -> None:
        if node.value:
            self._scan_text_for_iocs(node.value, context="Literal")

    def visit_VarExpandNode(self, node: VarExpandNode) -> None:
        if node.sub_replace:
            self._scan_text_for_iocs(node.sub_replace, context=f"Variable replacement %{node.name}%")

    # =========================================================================
    # Semantic & Pattern Extraction Helpers
    # =========================================================================

    def _reconstruct_arguments(self, args: List[ASTNode]) -> str:
        if not args:
            return ""
        tokens: List[str] = []
        curr_tok = ""
        for i, arg in enumerate(args):
            if hasattr(arg, "value"):
                val = arg.value
            elif isinstance(arg, VarExpandNode):
                delim = "!" if arg.is_delayed else "%"
                val = f"{delim}{arg.name}{delim}"
            elif isinstance(arg, ParamExpandNode):
                prefix = "%%" if arg.is_for_var else "%"
                val = f"{prefix}{arg.modifiers}{arg.name}"
            elif hasattr(arg, "name"):
                val = f"%{arg.name}%"
            else:
                val = str(arg)

            is_adjacent = False
            if i > 0:
                prev = args[i - 1]
                if prev.span and arg.span and prev.span != (0, 0) and arg.span != (0, 0):
                    is_adjacent = (prev.span[1] == arg.span[0])
                elif curr_tok.endswith(("%", "!")) and val.startswith(("\\", "/")):
                    is_adjacent = True
            if is_adjacent:
                curr_tok += val
            else:
                if curr_tok:
                    tokens.append(curr_tok)
                curr_tok = val
        if curr_tok:
            tokens.append(curr_tok)
        return " ".join(tokens)

    def _analyze_command_target_and_args(self, target: str, args: str, cmd_line: str) -> None:
        raw_target = target.strip(' "\'')
        clean_target = raw_target.lower()
        base_name = os.path.basename(clean_target)

        # 1. Identify LOLBins
        if base_name in LOLBIN_REGISTRY or clean_target in LOLBIN_REGISTRY:
            tid = LOLBIN_REGISTRY.get(base_name) or LOLBIN_REGISTRY.get(clean_target)
            mitre = get_mitre_mapping(tid) if tid else None
            for pat, override_tid in SUSPICIOUS_CMD_PATTERNS:
                if pat.search(cmd_line):
                    mitre = get_mitre_mapping(override_tid)
                    break
            self._add_ioc(IOCItem(
                ioc_type=IOCType.LOLBIN,
                value=base_name,
                context=cmd_line,
                confidence=0.90,
                severity=IOCSeverity.MEDIUM,
                mitre_attack=mitre,
                tags=["lolbin", base_name],
            ))

        # 2. Check for File Drops & Registry Keys
        self._detect_command_file_drops(raw_target, args, cmd_line)
        self._detect_registry_keys(cmd_line)
        self._scan_text_for_iocs(cmd_line, context=cmd_line)

    def _detect_command_file_drops(self, target: str, args: str, cmd_line: str) -> None:
        target_clean = target.strip(' "\'')
        base = os.path.basename(target_clean)
        base_lower = base.lower()
        has_path = ("\\" in target_clean or "/" in target_clean or target_clean.startswith("."))

        if (not target_clean.startswith(":") and
            (has_path or target_clean.lower().endswith((".bat", ".cmd"))) and
            any(base_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS) and
            base_lower not in LOLBIN_REGISTRY):
            self._add_ioc(IOCItem(
                ioc_type=IOCType.FILE_DROP,
                value=target_clean,
                context=cmd_line,
                confidence=0.90,
                severity=IOCSeverity.HIGH,
                mitre_attack=get_mitre_mapping("T1059.003"),
                tags=["executed_file_drop", base_lower],
            ))

        ingress_bins = ("certutil", "certutil.exe", "curl", "curl.exe", "wget", "wget.exe", "bitsadmin", "bitsadmin.exe")
        copy_bins = ("copy", "xcopy", "robocopy", "move", "ren", "rename")
        tokens = [m.strip(' "\'') for m in CMD_ARG_TOKEN_REGEX.findall(args) if m.strip(' "\'')]

        if base_lower in ingress_bins:
            for tok in tokens:
                if "://" in tok or tok.startswith(("-", "/")):
                    continue
                if any(tok.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
                    self._add_ioc(IOCItem(
                        ioc_type=IOCType.FILE_DROP,
                        value=tok,
                        context=cmd_line,
                        confidence=0.95,
                        severity=IOCSeverity.HIGH,
                        mitre_attack=get_mitre_mapping("T1105"),
                        tags=["ingress_drop", base_lower],
                    ))
        elif base_lower in copy_bins and tokens:
            non_switches = [t for t in tokens if not t.startswith(("-", "/"))]
            if non_switches:
                dest = non_switches[-1]
                if any(dest.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
                    self._add_ioc(IOCItem(
                        ioc_type=IOCType.FILE_DROP,
                        value=dest,
                        context=cmd_line,
                        confidence=0.85,
                        severity=IOCSeverity.MEDIUM,
                        mitre_attack=get_mitre_mapping("T1059.003"),
                        tags=["file_copy_drop"],
                    ))
        elif base_lower in RUNNER_BINS:
            for tok in tokens:
                if "://" in tok or tok.startswith(("-", "/")):
                    continue
                cand = tok.split(",")[0].strip(' "\'')
                cand_lower = cand.lower()
                cand_base = os.path.basename(cand_lower)
                if any(cand_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS) and cand_base not in KNOWN_SYSTEM_DLLS:
                    self._add_ioc(IOCItem(
                        ioc_type=IOCType.FILE_DROP,
                        value=cand,
                        context=cmd_line,
                        confidence=0.90,
                        severity=IOCSeverity.HIGH,
                        mitre_attack=get_mitre_mapping("T1059.003"),
                        tags=["runner_payload_drop", base_lower],
                    ))
        elif base_lower in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
            for rx, tag in ((POWERSHELL_OUTFILE_REGEX, "outfile"), (POWERSHELL_DOWNLOADFILE_REGEX, "downloadfile")):
                m = rx.search(args)
                if m:
                    p = (m.group(1) or (m.group(2) if len(m.groups()) > 1 else None) or "").strip(' "\'')
                    if any(p.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
                        self._add_ioc(IOCItem(
                            ioc_type=IOCType.FILE_DROP,
                            value=p,
                            context=cmd_line,
                            confidence=0.95,
                            severity=IOCSeverity.HIGH,
                            mitre_attack=get_mitre_mapping("T1105"),
                            tags=["powershell_drop", tag],
                        ))

    def _detect_registry_keys(self, cmd_line: str) -> None:
        for m in REGISTRY_KEY_REGEX.finditer(cmd_line):
            key_val = (m.group(1) or m.group(2)).strip(' "\'')
            key_lower = key_val.lower()
            is_run = "currentversion\\run" in key_lower
            is_defense = any(d in key_lower for d in ("policies", "windows defender", "firewallpolicy"))
            tid = "T1547.001" if is_run else ("T1562.001" if is_defense else "T1112")
            self._add_ioc(IOCItem(
                ioc_type=IOCType.REGISTRY_KEY,
                value=key_val,
                context=cmd_line,
                confidence=0.90,
                severity=IOCSeverity.HIGH if (is_run or is_defense) else IOCSeverity.MEDIUM,
                mitre_attack=get_mitre_mapping(tid),
                tags=["registry", "run_key" if is_run else ("impair_defense" if is_defense else "modify_reg")],
            ))


    def _scan_text_for_iocs(self, text: str, context: str) -> None:
        if not text:
            return

        # URLs
        for url_match in URL_REGEX.finditer(text):
            url = url_match.group(1).rstrip(",;)\"'^")
            self._add_ioc(IOCItem(
                ioc_type=IOCType.URL,
                value=url,
                context=context,
                confidence=0.95,
                severity=IOCSeverity.HIGH,
                mitre_attack=get_mitre_mapping("T1105"),
                tags=["network", "url"],
            ))

        # IPv4
        for ip_match in IPV4_REGEX.finditer(text):
            ip, port = ip_match.group(1), ip_match.group(2)
            octets = ip.split(".")
            if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                is_loopback = ip.startswith("127.") or ip == "0.0.0.0"
                val = f"{ip}:{port}" if (port and 0 <= int(port) <= 65535) else ip
                self._add_ioc(IOCItem(
                    ioc_type=IOCType.IPV4,
                    value=val,
                    context=context,
                    confidence=0.50 if is_loopback else 0.90,
                    severity=IOCSeverity.LOW if is_loopback else IOCSeverity.HIGH,
                    mitre_attack=get_mitre_mapping("T1105"),
                    tags=["network", "ipv4"],
                ))

        # IPv6
        for ip6_match in IPV6_REGEX.finditer(text):
            ip6 = ip6_match.group(1)
            if ip6 == "::" or not any(c in "0123456789abcdefABCDEF" for c in ip6):
                continue
            if "::" in ip6 or ip6.count(":") >= 2:
                self._add_ioc(IOCItem(
                    ioc_type=IOCType.IPV6,
                    value=ip6,
                    context=context,
                    confidence=0.85,
                    severity=IOCSeverity.HIGH,
                    mitre_attack=get_mitre_mapping("T1105"),
                    tags=["network", "ipv6"],
                ))

        # Domains
        for dom_match in DOMAIN_REGEX.finditer(text):
            dom = dom_match.group(1).rstrip(",;)\"'^")
            dom_lower = dom.lower()
            if not any(dom_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS) and dom_lower not in KNOWN_WINDOWS_COM_FILES:
                self._add_ioc(IOCItem(
                    ioc_type=IOCType.DOMAIN,
                    value=dom,
                    context=context,
                    confidence=0.80,
                    severity=IOCSeverity.MEDIUM,
                    mitre_attack=get_mitre_mapping("T1105"),
                    tags=["network", "domain"],
                ))

        # Emails
        for em_match in EMAIL_REGEX.finditer(text):
            self._add_ioc(IOCItem(
                ioc_type=IOCType.EMAIL,
                value=em_match.group(0),
                context=context,
                confidence=0.80,
                severity=IOCSeverity.LOW,
                tags=["email"],
            ))

        # Hashes (SHA256, SHA1, MD5)
        for rx, h_type, tag, conf, prior_types in (
            (SHA256_REGEX, IOCType.HASH_SHA256, "sha256", 0.90, ()),
            (SHA1_REGEX, IOCType.HASH_SHA1, "sha1", 0.85, (IOCType.HASH_SHA256,)),
            (MD5_REGEX, IOCType.HASH_MD5, "md5", 0.80, (IOCType.HASH_SHA256, IOCType.HASH_SHA1)),
        ):
            for h_match in rx.finditer(text):
                h_val = h_match.group(1).lower()
                if not h_val.isdigit() and not any(h_val in ex.value.lower() for ex in self.iocs if ex.ioc_type in prior_types):
                    self._add_ioc(IOCItem(
                        ioc_type=h_type,
                        value=h_val,
                        context=context,
                        confidence=conf,
                        severity=IOCSeverity.MEDIUM,
                        tags=["hash", tag],
                    ))

    def _scan_raw_source_fallback(self, source: str) -> None:
        """Inspects raw script lines to identify IOCs in comments or atypical structures."""
        for line_idx, line in enumerate(source.splitlines(), 1):
            line_str = line.strip()
            if line_str.startswith("::"):
                content = line_str.lstrip(":").strip()
            elif re.match(r"(?i)^rem(?:[\s./\\;,=]|$)", line_str):
                content = re.sub(r"(?i)^rem[\s./\\;,=]*", "", line_str).strip()
            else:
                continue
            self.current_line = line_idx
            if content:
                self._scan_text_for_iocs(content, context=f"Comment: {line_str}")

