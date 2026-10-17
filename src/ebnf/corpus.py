"""
cmd-ast-deobfuscator: Canonical Test Corpus for EBNF Conformance and Coverage.
Contains standard, edge-case, and obfuscated cmd.exe scripts designed to exercise
and formally validate all syntactic, lexical, expansion, and control-flow rules.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class CorpusSample:
    """Individual canonical test corpus sample."""
    id: str
    name: str
    category: str
    code: str
    targeted_rules: List[str]
    expected_status: str = "PASS"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "code": self.code,
            "targeted_rules": list(self.targeted_rules),
            "expected_status": self.expected_status,
            "description": self.description,
        }


CANONICAL_CORPUS: List[CorpusSample] = [
    CorpusSample(
        id="CORPUS-001",
        name="Atomic Command Invocation",
        category="commands",
        code="echo hello world\n",
        targeted_rules=["Script", "Line", "Command", "CommandTarget", "Argument", "LiteralText", "Atom"],
        description="Single atomic command execution with arguments and unquoted literals.",
    ),
    CorpusSample(
        id="CORPUS-002",
        name="Sequential Command Chain",
        category="statements",
        code="dir /b & echo done\n",
        targeted_rules=["Script", "Line", "Statement", "ChainOperator", "SeqOp", "Command", "Argument"],
        description="Unconditional sequential execution chaining two atomic commands with '&'.",
    ),
    CorpusSample(
        id="CORPUS-003",
        name="Conditional On-Success Chain",
        category="statements",
        code="mkdir build && copy file.txt build\\\n",
        targeted_rules=["Script", "Line", "Statement", "ChainOperator", "AndOp", "Command"],
        description="Conditional on-success execution chaining two commands with '&&'.",
    ),
    CorpusSample(
        id="CORPUS-004",
        name="Conditional On-Failure Chain",
        category="statements",
        code="ping 127.0.0.1 || echo unreachable\n",
        targeted_rules=["Script", "Line", "Statement", "ChainOperator", "OrOp", "Command"],
        description="Conditional on-failure execution chaining with '||'.",
    ),
    CorpusSample(
        id="CORPUS-005",
        name="Inter-Process Pipeline",
        category="statements",
        code="type test.log | findstr /i error\n",
        targeted_rules=["Script", "Line", "Pipeline", "PipeOp", "Command"],
        description="Standard pipe operator streaming stdout of left command into stdin of right command.",
    ),
    CorpusSample(
        id="CORPUS-006",
        name="Compound Block Expression",
        category="statements",
        code="(\n  echo Starting\n  echo In Progress\n)\n",
        targeted_rules=["Script", "Block", "CommandOrBlock", "Command", "Line"],
        description="Parenthesized grouped block expression executing multiple inner statements.",
    ),
    CorpusSample(
        id="CORPUS-007",
        name="Standard Variable Assignment",
        category="statements",
        code="set APP_NAME=cmd_deobfuscator\n",
        targeted_rules=["Script", "Assignment", "VarName", "AssignOp", "CommandOrBlock"],
        description="Environment variable assignment without arithmetic flags.",
    ),
    CorpusSample(
        id="CORPUS-008",
        name="Arithmetic Expression Assignment",
        category="statements",
        code="set /a TOTAL=10 + 20 * 2\n",
        targeted_rules=["Script", "Assignment", "VarName", "AssignOp"],
        description="SET /A arithmetic expression assignment with operator evaluation.",
    ),
    CorpusSample(
        id="CORPUS-009",
        name="Percent Environment Variable Expansion",
        category="expansion",
        code="echo %PATH%\n",
        targeted_rules=["Script", "Command", "PercentVar", "VarName", "Atom"],
        description="Standard immediate percent-expansion syntax for environment variables.",
    ),
    CorpusSample(
        id="CORPUS-010",
        name="Delayed Environment Variable Expansion",
        category="expansion",
        code="echo !LOCAL_FLAG!\n",
        targeted_rules=["Script", "Command", "DelayedVar", "VarName", "Atom"],
        description="Exclamation-delimited delayed environment variable expansion.",
    ),
    CorpusSample(
        id="CORPUS-011",
        name="Substring Slicing Expansion",
        category="expansion",
        code="echo %PATH:~0,5% & echo !NAME:~-3!\n",
        targeted_rules=["PercentSlice", "DelayedSlice", "SliceStart", "SliceLen", "Statement"],
        description="Positive and negative offset substring slicing on percent and delayed variables.",
    ),
    CorpusSample(
        id="CORPUS-012",
        name="Variable Pattern Substitution",
        category="expansion",
        code="echo %VAR:foo=bar%\n",
        targeted_rules=["PercentSubst", "VarName", "Command", "Atom"],
        description="Search-and-replace string substitution syntax on variable expansion.",
    ),
    CorpusSample(
        id="CORPUS-013",
        name="Script Parameters and Path Modifiers",
        category="expansion",
        code="echo %0 %~dp0 %*\n",
        targeted_rules=["ParamExpand", "Command", "Argument", "Atom"],
        description="Positional arguments and cmd.exe parameter modifier attributes.",
    ),
    CorpusSample(
        id="CORPUS-014",
        name="FOR Loop Parameter Modifiers",
        category="expansion",
        code="for %%i in (*.bat) do echo %%~fi\n",
        targeted_rules=["ForLoop", "ParamExpand", "Command", "Atom"],
        description="Loop variable attribute modifier syntax resolving full file path.",
    ),
    CorpusSample(
        id="CORPUS-015",
        name="Caret Escape Obfuscation",
        category="atoms",
        code="c^m^d.e^x^e /c e^c^h^o h^e^l^l^o\n",
        targeted_rules=["CaretEscape", "Command", "CommandTarget", "Argument", "Atom"],
        description="Self-stripping caret escape sequences obfuscating command and argument tokens.",
    ),
    CorpusSample(
        id="CORPUS-016",
        name="Quoted String and Empty Quote Pairs",
        category="atoms",
        code="echo \"hello & world\" \"\"\n",
        targeted_rules=["QuotedString", "EmptyQuotePair", "DoubleQuote", "Command", "Atom"],
        description="Quoted string containing meta-characters and collapsed empty quote pairs.",
    ),
    CorpusSample(
        id="CORPUS-017",
        name="Output and Append Redirections",
        category="redirection",
        code="dir > output.txt & type log.txt >> all.log\n",
        targeted_rules=["Redirection", "RedirOut", "RedirAppend", "Statement", "Command"],
        description="Standard output truncation and append stream redirection.",
    ),
    CorpusSample(
        id="CORPUS-018",
        name="Input Redirection and Stream Duplication",
        category="redirection",
        code="sort < input.txt & cmd.exe 2>&1\n",
        targeted_rules=["Redirection", "RedirIn", "RedirDup", "Statement", "Command"],
        description="Standard input routing and stderr-to-stdout descriptor duplication (2>&1).",
    ),
    CorpusSample(
        id="CORPUS-019",
        name="Conditional IF-ELSE Branching",
        category="control_flow",
        code="if exist build.bat ( echo exists ) else ( echo missing )\n",
        targeted_rules=["IfStatement", "Block", "CommandOrBlock", "Command"],
        description="Standard conditional IF statement with parenthesized THEN and ELSE branches.",
    ),
    CorpusSample(
        id="CORPUS-020",
        name="FOR Iteration Loops",
        category="control_flow",
        code="for /l %%x in (1,1,5) do echo %%x\n",
        targeted_rules=["ForLoop", "ParamExpand", "CommandOrBlock", "Command"],
        description="Numeric sequence FOR /L loop iterating from start to end with step.",
    ),
    CorpusSample(
        id="CORPUS-021",
        name="Labels and GOTO Jumps",
        category="control_flow",
        code=":MAIN_LOOP\necho looping\ngoto :MAIN_LOOP\ngoto :EOF\n",
        targeted_rules=["LabelDef", "GotoStatement", "Command", "Script"],
        description="Label definition, cyclical jump, and special :EOF return target.",
    ),
    CorpusSample(
        id="CORPUS-022",
        name="Subroutine and External CALL",
        category="control_flow",
        code="call :my_subroutine arg1 & call helper.bat\n",
        targeted_rules=["CallStatement", "Statement", "Command"],
        description="Internal labeled subroutine call and external batch script execution.",
    ),
    CorpusSample(
        id="CORPUS-023",
        name="Script Termination and Return",
        category="control_flow",
        code="exit /b 0 & exit 1\n",
        targeted_rules=["ExitStatement", "Statement"],
        description="Batch return with status code and global process termination.",
    ),
    CorpusSample(
        id="CORPUS-024",
        name="Comment Lines (REM and ::)",
        category="control_flow",
        code="rem Standard documentation comment\n:: Pseudo-label comment annotation\n",
        targeted_rules=["Comment", "Script", "Line"],
        description="Both standard REM statements and colon-colon comment annotations.",
    ),
    CorpusSample(
        id="CORPUS-025",
        name="Complex Composite Obfuscated Batch Script",
        category="complex",
        code="(\n  set /a N=1\n  if not \"%N%\"==\"\" (\n    c^m^d.e^x^e /c echo !VAR:~0,3! > out.txt 2>&1\n  )\n)\n",
        targeted_rules=[
            "Script", "Block", "Assignment", "IfStatement", "CaretEscape",
            "DelayedSlice", "Redirection", "RedirOut", "RedirDup", "PercentVar",
            "QuotedString", "DoubleQuote", "Command",
        ],
        description="Multi-line realistic obfuscated script combining blocks, IFs, carets, slices, and redirections.",
    ),
]


def get_canonical_corpus() -> List[CorpusSample]:
    """Returns the full list of canonical test corpus samples."""
    return list(CANONICAL_CORPUS)


def get_corpus_by_category(category: Optional[str]) -> List[CorpusSample]:
    """Filters corpus samples by category."""
    if not category:
        return []
    cat_lower = category.strip().lower()
    return [s for s in CANONICAL_CORPUS if s.category.lower() == cat_lower]


def get_corpus_by_rule(rule_name: Optional[str]) -> List[CorpusSample]:
    """Finds all corpus samples that target a specific grammar rule."""
    if not rule_name:
        return []
    return [s for s in CANONICAL_CORPUS if rule_name in s.targeted_rules]
