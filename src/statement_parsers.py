"""
Statement Parsers Submodule for cmd-ast-deobfuscator.
Decomposes specialized control flow and assignment statements:
- FOR loops (flags, options, in-clause, body)
- IF conditionals (parenthesized blocks, single command, else branches)
- SET assignments (quotes, equals delimiters, slices)
- GOTO jumps (static, dynamic, EOF)
- CALL invocations (subroutine labels vs external scripts)
- EXIT statements (batch return vs process exit)
"""

import re
from typing import List, Optional, Callable, Any, Type
from .lexer import CmdToken, CmdTokenType
from .ast_nodes import (
    ASTNode, ForNode, IfNode, AssignmentNode, GotoNode,
    CallNode, ExitNode, CommandNode, BlockNode, LiteralNode
)


def parse_for_statement(tokens: List[CmdToken], parser_cls: Type[Any]) -> Optional[ForNode]:
    """Parses 'FOR [/F | /R | /D | /L] %%i IN (...) DO (...)' statements."""
    in_idx = -1
    do_idx = -1

    for i, t in enumerate(tokens):
        if not t.in_quote and t.type == CmdTokenType.LITERAL:
            val_lower = t.value.strip().lower()
            if val_lower == 'in' and in_idx == -1 and i > 0:
                in_idx = i
            elif val_lower == 'do' and in_idx != -1 and do_idx == -1:
                do_idx = i

    if in_idx == -1 or do_idx == -1 or in_idx >= do_idx:
        return None

    between_for_in = tokens[1:in_idx]
    iterator = ""
    flags_parts = []
    options_parts = []

    i = 0
    while i < len(between_for_in):
        tok = between_for_in[i]
        if tok.type == CmdTokenType.WHITESPACE:
            i += 1
            continue
        if tok.type in (CmdTokenType.FOR_VAR, CmdTokenType.PARAM_VAR) or tok.value.startswith('%'):
            iterator = tok.value
            i += 1
            continue
        if tok.type == CmdTokenType.QUOTE or tok.value.startswith('"'):
            opt_chars = [tok.value]
            if tok.value != '""' and not (tok.value.startswith('"') and tok.value.endswith('"') and len(tok.value) > 1):
                i += 1
                while i < len(between_for_in):
                    sub_t = between_for_in[i]
                    opt_chars.append(sub_t.value)
                    i += 1
                    if sub_t.type == CmdTokenType.QUOTE or sub_t.value == '"':
                        break
                options_parts.append("".join(opt_chars))
                continue
            else:
                options_parts.append(tok.value)
                i += 1
                continue
        if tok.value.startswith('/'):
            flags_parts.append(tok.value)
            i += 1
            continue
        flags_parts.append(tok.value)
        i += 1

    in_tokens = tokens[in_idx + 1:do_idx]
    while in_tokens and in_tokens[0].type == CmdTokenType.WHITESPACE:
        in_tokens.pop(0)
    while in_tokens and in_tokens[-1].type == CmdTokenType.WHITESPACE:
        in_tokens.pop()
    in_clause = "".join(t.value for t in in_tokens).strip()

    body_tokens = tokens[do_idx + 1:]
    while body_tokens and body_tokens[0].type == CmdTokenType.WHITESPACE:
        body_tokens.pop(0)
    while body_tokens and body_tokens[-1].type == CmdTokenType.WHITESPACE:
        body_tokens.pop()

    if not body_tokens:
        body: ASTNode = CommandNode(target="")
    elif body_tokens[0].type == CmdTokenType.LPAREN and body_tokens[-1].type == CmdTokenType.RPAREN:
        inner = body_tokens[1:-1]
        sub_parser = parser_cls(inner)
        sub_script = sub_parser.parse()
        body = BlockNode(statements=sub_script.statements)
    else:
        sub_parser = parser_cls(body_tokens)
        body = sub_parser.parse_statement() or CommandNode(target="".join(t.value for t in body_tokens).strip())

    return ForNode(
        iterator=iterator,
        flags=" ".join(flags_parts),
        options=" ".join(options_parts),
        in_clause=in_clause,
        body=body
    )


def parse_if_statement(tokens: List[CmdToken], parser_cls: Type[Any]) -> Optional[IfNode]:
    """Parses 'IF [NOT] condition ( then ) ELSE ( else )' or single-command IF."""
    lparen_idx = -1
    for i, t in enumerate(tokens):
        if not t.in_quote and t.type == CmdTokenType.LPAREN:
            lparen_idx = i
            break

    if lparen_idx != -1:
        cond_tokens = tokens[1:lparen_idx]
        condition = "".join(t.value for t in cond_tokens).strip()

        rparen_idx = -1
        depth = 0
        for i in range(lparen_idx, len(tokens)):
            t = tokens[i]
            if not t.in_quote:
                if t.type == CmdTokenType.LPAREN:
                    depth += 1
                elif t.type == CmdTokenType.RPAREN:
                    depth -= 1
                    if depth == 0:
                        rparen_idx = i
                        break

        if rparen_idx == -1:
            return None

        then_inner_tokens = tokens[lparen_idx + 1:rparen_idx]
        then_parser = parser_cls(then_inner_tokens)
        then_script = then_parser.parse()
        then_block = BlockNode(statements=then_script.statements)

        else_block = None
        after_then = tokens[rparen_idx + 1:]
        else_idx = -1
        for j, t in enumerate(after_then):
            if not t.in_quote and t.type == CmdTokenType.LITERAL and t.value.strip().lower() == 'else':
                else_idx = j
                break

        if else_idx != -1:
            after_else = after_then[else_idx + 1:]
            else_lparen = -1
            for k, t in enumerate(after_else):
                if not t.in_quote and t.type == CmdTokenType.LPAREN:
                    else_lparen = k
                    break

            if else_lparen != -1:
                else_rparen = -1
                edepth = 0
                for k in range(else_lparen, len(after_else)):
                    t = after_else[k]
                    if not t.in_quote:
                        if t.type == CmdTokenType.LPAREN:
                            edepth += 1
                        elif t.type == CmdTokenType.RPAREN:
                            edepth -= 1
                            if edepth == 0:
                                else_rparen = k
                                break
                if else_rparen != -1:
                    else_inner = after_else[else_lparen + 1:else_rparen]
                    else_parser = parser_cls(else_inner)
                    else_script = else_parser.parse()
                    else_block = BlockNode(statements=else_script.statements)
            else:
                else_parser = parser_cls(after_else)
                else_script = else_parser.parse()
                else_block = else_script.statements[0] if len(else_script.statements) == 1 else BlockNode(statements=else_script.statements)

        return IfNode(condition=condition, then_block=then_block, else_block=else_block)

    # Single-command IF without parentheses: find then-command keyword
    cmd_keywords = {'goto', 'set', 'call', 'echo', 'exit', 'del', 'copy', 'move', 'start'}
    then_start_idx = -1
    for i in range(1, len(tokens)):
        t = tokens[i]
        if not t.in_quote and t.type == CmdTokenType.LITERAL:
            val_lower = t.value.strip().lower()
            if val_lower in cmd_keywords and i > 1:
                then_start_idx = i
                break

    if then_start_idx != -1:
        cond_tokens = tokens[1:then_start_idx]
        condition = "".join(t.value for t in cond_tokens).strip()
        then_tokens = tokens[then_start_idx:]
        then_parser = parser_cls(then_tokens)
        then_script = then_parser.parse()
        then_stmt = then_script.statements[0] if len(then_script.statements) == 1 else BlockNode(statements=then_script.statements)
        return IfNode(condition=condition, then_block=then_stmt, else_block=None)

    return None


def parse_set_assignment(
    tokens: List[CmdToken],
    token_to_node_fn: Callable[[CmdToken], ASTNode]
) -> AssignmentNode:
    """Parses 'set VAR=VAL' statements with slicing/quote resolution and /a /p flags."""
    raw_tail = "".join(t.value for t in tokens[1:]).strip()

    is_arithmetic = False
    is_prompt = False

    # Check for /A (arithmetic) or /P (prompt) flags
    flag_match = re.match(r'^\s*/([apAP])\b\s*(.*)', raw_tail, re.IGNORECASE)
    if flag_match:
        flag = flag_match.group(1).lower()
        if flag == 'a':
            is_arithmetic = True
        elif flag == 'p':
            is_prompt = True
        raw_tail = flag_match.group(2).strip()

    is_enclosed_quotes = False
    if raw_tail.startswith('"') and raw_tail.endswith('"'):
        raw_tail = raw_tail[1:-1]
        is_enclosed_quotes = True

    if is_arithmetic:
        if '=' in raw_tail and ',' not in raw_tail:
            var_name, var_val = raw_tail.split('=', 1)
        else:
            var_name, var_val = "", raw_tail
    elif '=' in raw_tail:
        var_name, var_val = raw_tail.split('=', 1)
    else:
        var_name, var_val = raw_tail, ""

    val_tokens: List[CmdToken] = []
    if is_arithmetic and not var_name:
        for t in tokens[1:]:
            val_str = t.value.strip().lower()
            if val_str in ('/a', '/p'):
                continue
            if val_str.startswith('/a') or val_str.startswith('/p'):
                trimmed = t.value.strip()[2:].strip()
                if trimmed:
                    val_tokens.append(CmdToken(t.type, trimmed, t.span, t.in_quote))
                continue
            val_tokens.append(t)
    else:
        found_eq = False
        for t in tokens[1:]:
            if found_eq:
                val_tokens.append(t)
            elif t.type == CmdTokenType.EQUALS:
                found_eq = True
            elif '=' in t.value:
                found_eq = True
                _, after_eq = t.value.split('=', 1)
                if after_eq:
                    val_tokens.append(CmdToken(CmdTokenType.LITERAL, after_eq, t.span, t.in_quote))

    if is_enclosed_quotes:
        while val_tokens and (val_tokens[-1].type == CmdTokenType.QUOTE or val_tokens[-1].value == '"'):
            val_tokens.pop()

    while val_tokens and val_tokens[-1].type == CmdTokenType.WHITESPACE:
        val_tokens.pop()

    value_nodes: List[ASTNode] = []
    for t in val_tokens:
        if t.type == CmdTokenType.EOF:
            continue
        value_nodes.append(token_to_node_fn(t))

    if not value_nodes and var_val:
        value_nodes = [LiteralNode(value=var_val)]

    return AssignmentNode(
        var_name=var_name.strip(),
        raw_value=var_val,
        value_nodes=value_nodes,
        is_arithmetic=is_arithmetic
    )



def parse_goto_statement(
    tokens: List[CmdToken],
    token_to_node_fn: Callable[[CmdToken], ASTNode]
) -> Optional[GotoNode]:
    """Parses 'goto :label' or dynamic 'goto %VAR%' statement."""
    after_goto = [t for t in tokens[1:] if t.type != CmdTokenType.WHITESPACE or t.in_quote]
    if not after_goto:
        return GotoNode(target="")

    target_nodes = [token_to_node_fn(t) for t in after_goto]
    raw_target = "".join(t.value for t in after_goto).strip()
    clean_target = raw_target.lstrip(':')
    is_dynamic = any(
        t.type in (CmdTokenType.PERCENT_VAR, CmdTokenType.EXCLAM_VAR, CmdTokenType.PARAM_VAR, CmdTokenType.FOR_VAR)
        for t in after_goto
    )
    is_eof = (clean_target.lower() == 'eof')
    return GotoNode(
        target=clean_target,
        target_nodes=target_nodes,
        is_eof=is_eof,
        is_dynamic=is_dynamic
    )


def parse_call_statement(
    tokens: List[CmdToken],
    token_to_node_fn: Callable[[CmdToken], ASTNode]
) -> Optional[CallNode]:
    """Parses 'call :label [args...]' or 'call script.bat [args...]'."""
    target_tokens: List[CmdToken] = []
    arg_tokens: List[CmdToken] = []
    state = 0

    for t in tokens[1:]:
        if state == 0:
            if t.type == CmdTokenType.WHITESPACE and not t.in_quote:
                continue
            state = 1
            target_tokens.append(t)
        elif state == 1:
            if t.type == CmdTokenType.WHITESPACE and not t.in_quote:
                state = 2
            else:
                target_tokens.append(t)
        else:
            arg_tokens.append(t)

    if not target_tokens:
        return None

    raw_target = "".join(t.value for t in target_tokens).strip()
    is_subroutine = raw_target.startswith(':')
    clean_target = raw_target.lstrip(':') if is_subroutine else raw_target

    target_nodes = [token_to_node_fn(t) for t in target_tokens]
    arg_nodes = [token_to_node_fn(t) for t in arg_tokens if t.type != CmdTokenType.WHITESPACE or t.in_quote]

    is_dynamic = any(
        t.type in (CmdTokenType.PERCENT_VAR, CmdTokenType.EXCLAM_VAR, CmdTokenType.PARAM_VAR, CmdTokenType.FOR_VAR)
        for t in target_tokens
    )

    return CallNode(
        target=clean_target,
        target_nodes=target_nodes,
        arguments=arg_nodes,
        is_subroutine=is_subroutine,
        is_dynamic=is_dynamic
    )


def parse_exit_statement(tokens: List[CmdToken]) -> ExitNode:
    """Parses 'exit [/b] [code]' statement."""
    is_batch_return = False
    exit_code: Optional[str] = None

    for t in tokens[1:]:
        if t.type == CmdTokenType.WHITESPACE:
            continue
        val_lower = t.value.strip().lower()
        if val_lower == '/b':
            is_batch_return = True
        elif exit_code is None:
            exit_code = t.value.strip()

    return ExitNode(
        is_batch_return=is_batch_return,
        exit_code=exit_code
    )
