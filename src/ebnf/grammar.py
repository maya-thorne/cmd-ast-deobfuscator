"""
cmd-ast-deobfuscator: Formal cmd.exe EBNF Grammar Specification and Rule Registry.
Encodes the lexical, expansion, syntactic, and control-flow production rules
of the Windows Command Processor (cmd.exe) based on formal language theory.
"""

from typing import Dict, List, Optional
from .models import GrammarRule, GrammarRuleType, GrammarSpecification


def _r(
    name: str,
    rtype: GrammarRuleType,
    ebnf: str,
    desc: str,
    cat: str,
    ast: Optional[List[str]] = None,
    term: bool = False,
    ex: Optional[List[str]] = None,
) -> GrammarRule:
    """Helper to concisely define a grammar rule."""
    return GrammarRule(
        name=name,
        rule_type=rtype,
        ebnf_expression=ebnf,
        description=desc,
        category=cat,
        ast_node_types=ast or [],
        is_terminal=term,
        examples=ex or [],
    )


def build_cmd_ebnf_rules() -> Dict[str, GrammarRule]:
    """Builds and returns the comprehensive dictionary of formal cmd.exe EBNF rules."""
    L = GrammarRuleType.LEXICAL
    A = GrammarRuleType.ATOM
    R = GrammarRuleType.REDIRECTION
    E = GrammarRuleType.EXPANSION
    S = GrammarRuleType.SYNTACTIC
    C = GrammarRuleType.CONTROL_FLOW

    rules = [
        # --- 1. Lexical Terminals & Characters ---
        _r("Character", L, "Character = ? Any Unicode or ASCII character ? ;", "Universal character terminal.", "lexical", term=True, ex=["a", "Z", "$"]),
        _r("Newline", L, 'Newline = "\\n" | "\\r\\n" ;', "Line delimiter terminating batch statements.", "lexical", term=True, ex=["\n", "\r\n"]),
        _r("Whitespace", L, 'Whitespace = " " | "\\t" ;', "Token separator whitespace characters.", "lexical", term=True, ex=[" ", "\t"]),
        _r("Digit", L, 'Digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" ;', "Decimal digit terminal.", "lexical", term=True, ex=["0", "9"]),
        _r("Letter", L, 'Letter = "a" ... "z" | "A" ... "Z" ;', "Alphabetical letter terminal.", "lexical", term=True, ex=["a", "Z"]),
        _r("SpecialChar", L, 'SpecialChar = "^" | \'"\' | "%" | "!" | "&" | "|" | "<" | ">" | "(" | ")" | "=" ;', "Reserved shell meta-characters.", "lexical", term=True, ex=["^", "&", "|"]),
        _r("CaretEscape", A, 'CaretEscape = "^" , Character ;', "Escape sequence neutralizing meta-characters.", "atoms", ["LiteralNode"], ex=["^c", "^^"]),
        _r("EmptyQuotePair", A, 'EmptyQuotePair = \'""\' ;', "Collapsed empty double-quote pair.", "atoms", ["LiteralNode"], term=True, ex=['""']),
        _r("DoubleQuote", L, 'DoubleQuote = \'"\' ;', "Double quotation mark toggling shell literal escape state.", "lexical", term=True, ex=['"']),
        _r("QuotedString", A, 'QuotedString = DoubleQuote , { Character - DoubleQuote } , DoubleQuote ;', "Enclosed literal string literal.", "atoms", ["LiteralNode"], ex=['"test"']),
        _r("LiteralText", A, 'LiteralText = { Character - ( Whitespace | SpecialChar | Newline ) }+ ;', "Unquoted atomic text token.", "atoms", ["LiteralNode"], ex=["echo", "target.exe"]),
        _r("SeqOp", L, 'SeqOp = "&" ;', "Sequential command chaining operator.", "lexical", ["ChainNode"], term=True, ex=["&"]),
        _r("AndOp", L, 'AndOp = "&&" ;', "Conditional on-success chaining operator.", "lexical", ["ChainNode"], term=True, ex=["&&"]),
        _r("OrOp", L, 'OrOp = "||" ;', "Conditional on-failure chaining operator.", "lexical", ["ChainNode"], term=True, ex=["||"]),
        _r("PipeOp", L, 'PipeOp = "|" ;', "Inter-process pipeline operator.", "lexical", ["PipeNode"], term=True, ex=["|"]),
        _r("AssignOp", L, 'AssignOp = "=" ;', "Variable assignment operator for SET.", "lexical", ["AssignmentNode"], term=True, ex=["="]),
        _r("RedirOut", R, 'RedirOut = ">" ;', "Standard output truncation redirection.", "redirection", ["RedirectNode"], term=True, ex=[">"]),
        _r("RedirAppend", R, 'RedirAppend = ">>" ;', "Standard output appending redirection.", "redirection", ["RedirectNode"], term=True, ex=[">>"]),
        _r("RedirIn", R, 'RedirIn = "<" ;', "Standard input redirection operator.", "redirection", ["RedirectNode"], term=True, ex=["<"]),
        _r("RedirDup", R, 'RedirDup = [ Digit ] , ( ">&" | "<&" ) , Digit ;', "Descriptor duplication redirection (e.g. 2>&1, <&0).", "redirection", ["RedirectNode"], term=True, ex=["2>&1", "<&0"]),

        # --- 2. Variable and Parameter Expansions ---
        _r("VarName", E, 'VarName = ( Letter | Digit | "_" )+ ;', "Environment variable identifier.", "expansion", ex=["PATH", "TEMP"]),
        _r("SliceStart", E, 'SliceStart = [ "-" ] , Digit+ ;', "Substring slicing start offset.", "expansion", ex=["0", "-3"]),
        _r("SliceLen", E, 'SliceLen = [ "-" ] , Digit+ ;', "Substring slicing length offset.", "expansion", ex=["5", "-1"]),
        _r("PercentVar", E, 'PercentVar = "%" , VarName , "%" ;', "Immediate percent variable expansion.", "expansion", ["VarExpandNode"], ex=["%PATH%"]),
        _r("PercentSlice", E, 'PercentSlice = "%" , VarName , ":~" , SliceStart , [ "," , SliceLen ] , "%" ;', "Percent variable substring slicing.", "expansion", ["VarExpandNode"], ex=["%VAR:~0,5%"]),
        _r("PercentSubst", E, 'PercentSubst = "%" , VarName , ":" , { Character - "=" } , "=" , { Character - "%" } , "%" ;', "Variable substitution syntax.", "expansion", ["VarExpandNode"], ex=["%VAR:old=new%"]),
        _r("DelayedVar", E, 'DelayedVar = "!" , VarName , "!" ;', "Delayed variable expansion.", "expansion", ["VarExpandNode"], ex=["!FLAG!"]),
        _r("DelayedSlice", E, 'DelayedSlice = "!" , VarName , ":~" , SliceStart , [ "," , SliceLen ] , "!" ;', "Delayed expansion substring slicing.", "expansion", ["VarExpandNode"], ex=["!VAR:~0,3!"]),
        _r("ParamExpand", E, 'ParamExpand = "%" , [ "~" , [ Modifiers ] ] , ( Digit | "*" | Letter ) ;', "Script parameter (%0..%9, %*) or loop var.", "expansion", ["ParamExpandNode"], ex=["%0", "%~dp0", "%%i"]),

        # --- 3. Syntactic Productions ---
        _r("Script", S, "Script = { Line } , [ EOF ] ;", "Root batch script AST node.", "script", ["ScriptNode"], ex=["echo hello\n"]),
        _r("Line", S, "Line = [ Statement ] , Newline ;", "Single physical script line.", "script", ex=["dir\n"]),
        _r("Statement", S, "Statement = Pipeline , { ChainOperator , Pipeline } ;", "Chained composite statement.", "statements", ["ChainNode"], ex=["echo a & echo b"]),
        _r("ChainOperator", S, "ChainOperator = SeqOp | AndOp | OrOp ;", "Command chaining operator.", "statements", ["ChainNode"], ex=["&", "&&", "||"]),
        _r("Pipeline", S, "Pipeline = CommandOrBlock , { PipeOp , CommandOrBlock } ;", "Execution pipeline.", "statements", ["PipeNode"], ex=["type f.txt | find error"]),
        _r("CommandOrBlock", S, "CommandOrBlock = Block | Command | Assignment | ControlFlow | Comment ;", "Executable production unit.", "statements", ex=["echo hi", "( echo a )"]),
        _r("Block", S, 'Block = "(" , { Line | Statement } , ")" ;', "Grouped compound block.", "statements", ["BlockNode"], ex=["( echo 1 & echo 2 )"]),
        _r("Assignment", S, 'Assignment = [ "set" | "SET" ] , Whitespace , [ "/a" | "/A" ] , Whitespace , VarName , AssignOp , [ Expression ] ;', "Variable assignment.", "statements", ["AssignmentNode"], ex=["set X=1"]),
        _r("Command", S, "Command = CommandTarget , { Argument } , { Redirection } ;", "Executable command invocation.", "commands", ["CommandNode"], ex=["dir /b /s"]),
        _r("CommandTarget", S, "CommandTarget = Atom+ ;", "Command executable target.", "commands", ex=["echo", "cmd.exe"]),
        _r("Argument", S, "Argument = Atom+ ;", "Command argument parameter.", "commands", ex=["/c", "hello"]),
        _r("Redirection", R, "Redirection = ( RedirOut | RedirAppend | RedirIn | RedirDup ) , [ Whitespace ] , Atom+ ;", "Stream routing directive.", "redirection", ["RedirectNode"], ex=["> out.txt", "2>&1"]),
        _r("Atom", A, "Atom = CaretEscape | EmptyQuotePair | QuotedString | PercentVar | PercentSlice | PercentSubst | DelayedVar | DelayedSlice | ParamExpand | LiteralText ;", "Fundamental atomic token.", "atoms", ex=["hello", "%VAR%"]),

        # --- 4. Control Flow Productions ---
        _r("IfStatement", C, 'IfStatement = [ "if" | "IF" ] , [ "not" | "NOT" ] , Condition , CommandOrBlock , [ "else" | "ELSE" , CommandOrBlock ] ;', "Conditional branching.", "control_flow", ["IfNode"], ex=['if exist a.txt ( echo ok )']),
        _r("ForLoop", C, 'ForLoop = [ "for" | "FOR" ] , [ Flags ] , Iterator , "in" , "(" , Set , ")" , "do" , CommandOrBlock ;', "Iterative loop.", "control_flow", ["ForNode"], ex=['for %%i in (*.txt) do echo %%i']),
        _r("LabelDef", C, 'LabelDef = ":" , LabelName ;', "Label definition.", "control_flow", ["LabelNode"], ex=[":START", ":EOF"]),
        _r("GotoStatement", C, 'GotoStatement = [ "goto" | "GOTO" ] , Target ;', "Unconditional jump.", "control_flow", ["GotoNode"], ex=["goto :START"]),
        _r("CallStatement", C, 'CallStatement = [ "call" | "CALL" ] , Target , { Argument } ;', "Subroutine or script call.", "control_flow", ["CallNode"], ex=["call :subroutine"]),
        _r("ExitStatement", C, 'ExitStatement = [ "exit" | "EXIT" ] , [ "/b" | "/B" ] , [ ExitCode ] ;', "Termination or return.", "control_flow", ["ExitNode"], ex=["exit /b 0"]),
        _r("Comment", C, 'Comment = ( "rem" | "REM" | "::" ) , { Character } ;', "Comment annotation.", "control_flow", ["CommentNode"], ex=["rem note", ":: label note"]),
    ]

    return {r.name: r for r in rules}


def get_default_grammar() -> GrammarSpecification:
    """Instantiates and returns the default cmd.exe formal EBNF grammar specification."""
    return GrammarSpecification(
        title="Formal cmd.exe EBNF Grammar Specification",
        version="0.20.0",
        rules=build_cmd_ebnf_rules(),
    )


CMD_EBNF_SPEC: GrammarSpecification = get_default_grammar()


def export_ebnf_specification() -> str:
    """Exports the complete formal EBNF specification as a formatted string."""
    return CMD_EBNF_SPEC.to_ebnf_text()
