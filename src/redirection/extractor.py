"""
I/O Redirection Token Extractor and AST Builder.
Extracts leading, embedded, and trailing stream redirections from token streams.
"""

from typing import List, Tuple, Optional, Set
from ..lexer import CmdToken, CmdTokenType
from ..ast_nodes import ASTNode, RedirectNode
from .models import (
    RedirectEntry, DestinationType
)

MAX_REDIRECTS_PER_COMMAND: int = 64

# Standard DOS/Windows reserved device names
RESERVED_DEVICES: Set[str] = {
    'nul', 'con', 'prn', 'aux', 'clock$', 'conin$', 'conout$', 'conerr$',
    'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
    'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'
}


def is_device_destination(target: str) -> bool:
    """Checks whether a target string refers to a Windows system device."""
    if not target:
        return False
    clean = target.strip().strip('"').strip("'").lower()
    # Strip Win32 device namespace / DOS device path prefixes
    for prefix in ('\\\\.\\', '\\\\?\\', '//./', '//?/', '\\device\\', '/device/'):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
            break
    if clean.endswith(':'):
        clean = clean[:-1]
    # Check base device name or base before extension (e.g. nul.txt, null)
    base = clean.split('.')[0] if '.' in clean else clean
    return base in RESERVED_DEVICES or base == 'null'


def classify_destination(target: str) -> Tuple[DestinationType, bool]:
    """Determines the destination type and whether the stream is silenced/suppressed."""
    if not target:
        return DestinationType.FILE, False

    t_clean = target.strip()
    if t_clean.startswith('&'):
        if t_clean == '&-':
            return DestinationType.CLOSED, False
        return DestinationType.HANDLE, False

    if is_device_destination(t_clean):
        base = t_clean.strip().strip('"').strip("'").lower()
        for prefix in ('\\\\.\\', '\\\\?\\', '//./', '//?/', '\\device\\', '/device/'):
            if base.startswith(prefix):
                base = base[len(prefix):]
                break
        if base.endswith(':'):
            base = base[:-1]
        base_name = base.split('.')[0] if '.' in base else base
        is_suppressed = (base_name in ('nul', 'null'))
        return DestinationType.DEVICE, is_suppressed

    return DestinationType.FILE, False


def extract_redirections(tokens: List[CmdToken]) -> Tuple[List[CmdToken], List[RedirectEntry]]:
    """
    Extracts all redirection directives from a token sequence.
    Returns (cleaned_tokens, list_of_redirect_entries).
    """
    if not tokens:
        return [], []

    remaining: List[CmdToken] = []
    entries: List[RedirectEntry] = []
    idx = 0
    n = len(tokens)

    redirect_types = {
        CmdTokenType.REDIRECT_OUT,
        CmdTokenType.REDIRECT_APPEND,
        CmdTokenType.REDIRECT_IN,
        CmdTokenType.REDIRECT_DUP
    }

    while idx < n:
        tok = tokens[idx]

        if tok.type in redirect_types and not tok.in_quote:
            if len(entries) >= MAX_REDIRECTS_PER_COMMAND:
                # Security limit reached, stop extracting further redirects
                remaining.append(tok)
                idx += 1
                continue

            # Determine source file descriptor
            source_fd: int = 1
            if tok.type == CmdTokenType.REDIRECT_IN:
                source_fd = 0

            # Check if previous token was an attached single-digit descriptor
            prev_token_consumed = False
            if remaining and remaining[-1].type == CmdTokenType.LITERAL:
                prev_tok = remaining[-1]
                if (
                    len(prev_tok.value) == 1
                    and prev_tok.value.isdigit()
                    and prev_tok.span[1] == tok.span[0]
                ):
                    source_fd = int(prev_tok.value)
                    remaining.pop()
                    prev_token_consumed = True

            # Determine operator characteristics
            is_append = (tok.type == CmdTokenType.REDIRECT_APPEND or tok.value == '>>')
            is_input = (tok.type == CmdTokenType.REDIRECT_IN or tok.value in ('<', '<<'))
            is_dup = (tok.type == CmdTokenType.REDIRECT_DUP or tok.value in ('>&', '<&'))
            operator_str = tok.value

            # Extract destination token(s)
            dest_parts: List[str] = []
            next_idx = idx + 1

            # Skip immediate whitespace between operator and destination
            while next_idx < n and tokens[next_idx].type == CmdTokenType.WHITESPACE:
                next_idx += 1

            target_fd: Optional[int] = None
            span_start = tok.span[0]
            span_end = tok.span[1]

            if next_idx < n:
                dest_tok = tokens[next_idx]
                span_end = dest_tok.span[1]

                if is_dup:
                    # Duplication target: &1, 1, 2, or &-
                    raw_dest = dest_tok.value.strip()
                    if raw_dest.startswith('&'):
                        if raw_dest == '&-':
                            target_fd = None
                            dest_parts.append('&-')
                        else:
                            digits = raw_dest[1:]
                            if digits.isdigit():
                                target_fd = int(digits)
                            dest_parts.append(raw_dest)
                    elif raw_dest == '-':
                        dest_parts.append('&-')
                    elif raw_dest.isdigit():
                        target_fd = int(raw_dest)
                        dest_parts.append(f"&{raw_dest}")
                    else:
                        dest_parts.append(raw_dest)
                    next_idx += 1
                elif dest_tok.type == CmdTokenType.QUOTE or dest_tok.value.startswith('"'):
                    # Quoted destination: collect quoted span
                    dest_parts.append(dest_tok.value)
                    next_idx += 1
                    if not (dest_tok.value.endswith('"') and len(dest_tok.value) > 1):
                        while next_idx < n:
                            sub_tok = tokens[next_idx]
                            dest_parts.append(sub_tok.value)
                            span_end = sub_tok.span[1]
                            next_idx += 1
                            if sub_tok.type == CmdTokenType.QUOTE or sub_tok.value.endswith('"'):
                                break
                else:
                    # Collect contiguous tokens forming destination path/variable
                    while next_idx < n:
                        sub_tok = tokens[next_idx]
                        if sub_tok.type in (
                            CmdTokenType.WHITESPACE, CmdTokenType.NEWLINE, CmdTokenType.EOF,
                            CmdTokenType.AMP, CmdTokenType.DOUBLE_AMP, CmdTokenType.DOUBLE_PIPE,
                            CmdTokenType.PIPE, CmdTokenType.REDIRECT_OUT, CmdTokenType.REDIRECT_APPEND,
                            CmdTokenType.REDIRECT_IN, CmdTokenType.REDIRECT_DUP
                        ):
                            break
                        dest_parts.append(sub_tok.value)
                        span_end = sub_tok.span[1]
                        next_idx += 1

            destination_str = "".join(dest_parts).strip()
            dest_type, is_suppressed = classify_destination(destination_str)

            # Build raw representation (e.g., '2>&1', '> out.txt', '2>nul')
            prefix_fd = str(source_fd) if (
                (source_fd != 1 and not is_input) or (source_fd != 0 and is_input) or prev_token_consumed
            ) else ""
            if is_dup and operator_str.endswith('&') and destination_str.startswith('&'):
                raw_repr = f"{prefix_fd}{operator_str}{destination_str[1:]}".strip()
            else:
                raw_repr = f"{prefix_fd}{operator_str}{destination_str}".strip()

            entry = RedirectEntry(
                source_fd=source_fd,
                operator=operator_str,
                destination=destination_str,
                target_fd=target_fd,
                dest_type=dest_type,
                is_append=is_append,
                is_input=is_input,
                is_dup=is_dup,
                is_suppressed=is_suppressed,
                raw=raw_repr,
                span=(span_start, span_end)
            )
            entries.append(entry)
            idx = next_idx
            continue

        remaining.append(tok)
        idx += 1

    return remaining, entries


def build_redirect_tree(command: ASTNode, entries: List[RedirectEntry]) -> ASTNode:
    """Wraps an AST node with RedirectNode instances matching extraction order."""
    if not entries:
        return command

    current = command
    for entry in entries:
        current = RedirectNode(
            command=current,
            stream=entry.operator,
            destination=entry.destination,
            source_fd=entry.source_fd,
            target_fd=entry.target_fd,
            is_append=entry.is_append,
            is_input=entry.is_input,
            is_dup=entry.is_dup,
            span=entry.span
        )

    return current
