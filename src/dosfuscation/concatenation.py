#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Invoke-DOSfuscation Concatenation Heuristic Decoder
Implements state-machine and heuristic pattern transformers to unmask:
1. Environment variable fragment chaining (%a%%b%%c%, !a!!b!!c!)
2. Interleaved junk/empty variable insertion (%_dummy%c%_dummy%m%_dummy%d)
3. Delimiter scrambling (commas, semicolons, equals signs as whitespace)
4. FOR token accumulation loops (for %x in (c a l c) do set out=!out!%x)
5. CALL execution trampolines (call %cmd% -> direct execution)
6. Array-indexed variable assembly (%arr[0]%%arr[1]%)
"""

import re
from typing import Dict, List, Optional, Tuple, Set, Any
from .models import (
    ConcatenationType,
    ConcatenationPattern,
    DosfuscationMetrics,
    DosfuscationResult,
)


class DosfuscationConcatenationDecoder:
    """
    Advanced heuristic deobfuscator specifically tuned for Invoke-DOSfuscation
    concatenation algorithms and real-world batch fragment assemblers.
    """

    # Characters that cmd.exe treats as parameter/command delimiters outside quotes
    DELIMITER_CHARS = {',', ';', '='}

    def __init__(self, env: Optional[Dict[str, str]] = None):
        self.env: Dict[str, str] = {
            "comspec": r"C:\Windows\system32\cmd.exe",
            "systemroot": r"C:\Windows",
            "windir": r"C:\Windows",
            "programdata": r"C:\ProgramData",
            "public": r"C:\Users\Public",
            "allusersprofile": r"C:\ProgramData",
            "commonprogramfiles": r"C:\Program Files\Common Files",
            "path": r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem",
            "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
            "os": "Windows_NT",
        }
        if env:
            for k, v in env.items():
                self.env[k.lower()] = v
        self.metrics = DosfuscationMetrics()

    def strip_junk_variables(self, text: str, local_env: Optional[Dict[str, str]] = None) -> Tuple[str, int]:
        """
        Strips empty or dummy junk variables inserted between characters.
        Examples:
          - %PUBLIC:~0,0%c%PUBLIC:~0,0%m%PUBLIC:~0,0%d -> cmd
          - set "junk=" & %junk%p%junk%o%junk%w -> pow
        """
        env_ref = local_env if local_env is not None else self.env
        stripped_count = 0

        # Pass 1: Empty slice expressions like %VAR:~x,0% or %VAR:~,0%
        def empty_slice_repl(match: re.Match) -> str:
            nonlocal stripped_count
            stripped_count += 1
            return ""

        empty_slice_pat = re.compile(
            r'[%!][a-zA-Z0-9_\-\.\$]+:~(?:-?\d*)?,0[%!]',
            re.IGNORECASE
        )
        text = empty_slice_pat.sub(empty_slice_repl, text)

        # Pass 2: Variables explicitly set to empty in the environment
        empty_vars = {k for k, v in env_ref.items() if v == ""}
        if empty_vars:
            for evar in empty_vars:
                var_pat = re.compile(r'[%!]' + re.escape(evar) + r'[%!]', re.IGNORECASE)
                matches = list(var_pat.finditer(text))
                if matches:
                    stripped_count += len(matches)
                    text = var_pat.sub("", text)

        return text, stripped_count

    def normalize_delimiters(self, text: str) -> Tuple[str, int]:
        """
        Normalizes scrambled cmd.exe delimiters (commas, semicolons)
        outside double quotes, variable expansions, and loop parentheses
        into canonical single spaces or strips them when leading/trailing.
        Example:
          'cmd,;,/c,;,whoami' -> 'cmd /c whoami'
          ',;cmd.exe,; /c,;' -> 'cmd.exe /c'
        """
        normalized_count = 0
        lines = text.splitlines(keepends=True)
        new_lines: List[str] = []

        for line in lines:
            line_str = line
            trimmed = line_str.lstrip()
            if trimmed.lower().startswith(("rem ", "rem\t", "::")):
                new_lines.append(line_str)
                continue

            parts: List[str] = []
            in_quote = False
            in_percent = False
            in_exclam = False
            paren_depth = 0
            i = 0
            n = len(line_str)

            while i < n:
                ch = line_str[i]
                if ch == '"':
                    in_quote = not in_quote
                    parts.append(ch)
                    i += 1
                elif in_quote:
                    parts.append(ch)
                    i += 1
                elif ch == '%':
                    # Only toggle if not an escaped percent %%
                    if i + 1 < n and line_str[i + 1] == '%':
                        parts.append('%%')
                        i += 2
                    else:
                        in_percent = not in_percent
                        parts.append(ch)
                        i += 1
                elif ch == '!':
                    in_exclam = not in_exclam
                    parts.append(ch)
                    i += 1
                elif in_percent or in_exclam:
                    parts.append(ch)
                    i += 1
                elif ch == '(':
                    paren_depth += 1
                    parts.append(ch)
                    i += 1
                elif ch == ')':
                    if paren_depth > 0:
                        paren_depth -= 1
                    parts.append(ch)
                    i += 1
                elif paren_depth > 0:
                    parts.append(ch)
                    i += 1
                else:
                    # Outside quotes, vars, and parens: check for scrambled delimiters
                    if ch in (',', ';'):
                        start_idx = i
                        while i < n and line_str[i] in (',', ';', ' ', '\t'):
                            i += 1
                        delim_run = line_str[start_idx:i]
                        if any(c in (',', ';') for c in delim_run):
                            normalized_count += 1
                            # If at the beginning of the line/command
                            if not parts or parts[-1].endswith(('\n', '\r')):
                                pass
                            elif i >= n or line_str[i] in ('\r', '\n', '&', '|'):
                                pass
                            else:
                                if parts and not parts[-1].endswith((' ', '\t', '&', '|', '(')):
                                    parts.append(' ')
                        else:
                            parts.append(delim_run)
                    else:
                        parts.append(ch)
                        i += 1

            new_lines.append("".join(parts))

        return "".join(new_lines), normalized_count

    def resolve_token_accumulation_loops(self, text: str, local_env: Optional[Dict[str, str]] = None) -> Tuple[str, int]:
        """
        Detects and resolves FOR loops that accumulate tokens or characters into a variable.
        Example:
          for %x in (p o w e r s h e l l) do set out=!out!%x
          -> set "out=powershell"
          for %i in (c,a,l,c) do set res=%res%%i
          -> set "res=calc"
        """
        env_ref = local_env if local_env is not None else self.env
        accum_count = 0

        # Match FOR %var IN (items) DO SET target=!target!%var or %target%%var
        loop_pattern = re.compile(
            r'(?i)for\s+(?:/f\s+[^)]+\s+)?(?:%|%%)([a-zA-Z0-9_])\s+in\s*\(([^)]+)\)\s+do\s+'
            r'(?:\()?set\s+(?:")?([a-zA-Z0-9_\-\.\$]+)\s*=\s*([^"\r\n\)]+)(?:")?(?:\))?',
            re.IGNORECASE
        )

        def loop_repl(match: re.Match) -> str:
            nonlocal accum_count
            iterator = match.group(1)
            in_clause = match.group(2).strip()
            target_var = match.group(3)
            body_expr = match.group(4).strip()

            # Split in_clause by whitespace, comma, or semicolon
            raw_tokens = [tok.strip(' ",\t;') for tok in re.split(r'[,;\s]+', in_clause) if tok.strip(' ",\t;')]
            if not raw_tokens:
                return match.group(0)

            # Check if body_expr accumulates target_var and iterator
            # Patterns: !target!%iterator, %target%%iterator, %iterator%!target! (prepend)
            iter_ref = re.escape(iterator)
            targ_ref = re.escape(target_var)

            append_pat = re.compile(
                r'^(?:[%!]' + targ_ref + r'[%!])\s*(?:(?:%|%%)' + iter_ref + r')$',
                re.IGNORECASE
            )
            prepend_pat = re.compile(
                r'^(?:(?:%|%%)' + iter_ref + r')\s*(?:[%!]' + targ_ref + r'[%!])$',
                re.IGNORECASE
            )
            direct_pat = re.compile(
                r'^(?:%|%%)' + iter_ref + r'$',
                re.IGNORECASE
            )

            # Resolve initial value from environment if present
            current_val = env_ref.get(target_var.lower(), "")

            if append_pat.match(body_expr):
                for tok in raw_tokens:
                    current_val += tok
                accum_count += 1
                env_ref[target_var.lower()] = current_val
                return f'set "{target_var}={current_val}"'
            elif prepend_pat.match(body_expr):
                for tok in raw_tokens:
                    current_val = tok + current_val
                accum_count += 1
                env_ref[target_var.lower()] = current_val
                return f'set "{target_var}={current_val}"'
            elif direct_pat.match(body_expr) and len(raw_tokens) == 1:
                # Single item assignment loop
                current_val = raw_tokens[0]
                accum_count += 1
                env_ref[target_var.lower()] = current_val
                return f'set "{target_var}={current_val}"'

            return match.group(0)

        result = loop_pattern.sub(loop_repl, text)
        return result, accum_count

    def fuse_variable_chains(self, text: str, local_env: Optional[Dict[str, str]] = None) -> Tuple[str, int]:
        """
        Fuses chains of concatenated variables (%a%%b%%c%, !a!!b!!c!)
        resolving multi-pass references in virtual symbol table.
        """
        env_ref = local_env if local_env is not None else self.env
        fused_count = 0

        # Pattern matching single variable expansion %VAR% or !VAR!
        var_pat = re.compile(r'([%!])([a-zA-Z0-9_\-\.\$\[\]\:\~,]+)\1')

        # Run up to 10 convergence iterations for nested/chained variables
        prev = None
        iters = 0
        while prev != text and iters < 10:
            prev = text
            iters += 1

            def repl(m: re.Match) -> str:
                nonlocal fused_count
                vname = m.group(2).lower()
                # Check direct match
                if vname in env_ref:
                    fused_count += 1
                    return env_ref[vname]
                return m.group(0)

            text = var_pat.sub(repl, text)

        return text, fused_count

    def extract_symbol_definitions(self, line: str, local_env: Optional[Dict[str, str]] = None) -> None:
        """
        Parses assignments like 'set VAR=VAL', 'set "VAR=VAL"', 'set/a VAR=1+2'
        handling compound chains delimited by '&' or '&&'.
        """
        env_ref = local_env if local_env is not None else self.env

        # Split line by & or && outside double quotes
        sub_commands = self._split_by_operators(line)
        for cmd in sub_commands:
            cleaned = cmd.strip()
            if cleaned.lower().startswith("@"):
                cleaned = cleaned[1:].strip()

            # Strip enclosing parentheses if present e.g. (set foo=bar)
            if cleaned.startswith("(") and cleaned.endswith(")"):
                cleaned = cleaned[1:-1].strip()

            m = re.match(
                r'^set(?:\s+|,\s*|;\s*)(?:/a\s+|/p\s+)?(?:")?([a-zA-Z0-9_\-\.\:\$\[\]]+)=([^"\r\n]*)(?:")?$',
                cleaned,
                re.IGNORECASE,
            )
            if m:
                var_name = m.group(1).lower().strip()
                raw_val = m.group(2)
                # Expand any already known variables in the value
                resolved_val, _ = self.fuse_variable_chains(raw_val, env_ref)
                env_ref[var_name] = resolved_val

    def _split_by_operators(self, line: str) -> List[str]:
        """Splits command line by & and && operators outside double quotes."""
        parts: List[str] = []
        cur = []
        in_quote = False
        i = 0
        n = len(line)

        while i < n:
            ch = line[i]
            if ch == '"':
                in_quote = not in_quote
                cur.append(ch)
                i += 1
            elif not in_quote and ch == '&':
                # Check for & or &&
                if i + 1 < n and line[i + 1] == '&':
                    i += 2
                else:
                    i += 1
                if cur:
                    parts.append("".join(cur))
                    cur = []
            else:
                cur.append(ch)
                i += 1

        if cur:
            parts.append("".join(cur))
        return parts

    def unroll_call_trampolines(self, text: str, local_env: Optional[Dict[str, str]] = None) -> Tuple[str, int]:
        """
        Unrolls 'call %var% ...' or 'call %a%%b% ...' dynamic trampolines
        into direct command invocations when the variable resolves to a known target.
        Preserves genuine batch subroutine calls (call :label).
        """
        env_ref = local_env if local_env is not None else self.env
        unrolled_count = 0
        lines = text.splitlines(keepends=True)
        new_lines: List[str] = []

        call_pat = re.compile(
            r'^(?P<indent>\s*)(?:@)?call\s+(?P<target>[^:\s][^\s]*)(?P<rest>.*)$',
            re.IGNORECASE
        )

        for line in lines:
            m = call_pat.match(line)
            if m:
                target = m.group("target")
                rest = m.group("rest")
                indent = m.group("indent")

                # If target contains variable expansions, resolve them
                resolved_target, _ = self.fuse_variable_chains(target, env_ref)
                # If target resolved to a typical binary/command (e.g. powershell, cmd, calc)
                # unwrap the CALL trampoline
                if resolved_target != target or resolved_target.lower() in {
                    "cmd", "powershell", "powershell.exe", "cmd.exe", "whoami",
                    "calc", "calc.exe", "certutil", "certutil.exe", "bitsadmin"
                }:
                    unrolled_count += 1
                    new_lines.append(f"{indent}{resolved_target}{rest}")
                    continue

            new_lines.append(line)

        return "".join(new_lines), unrolled_count

    def decode(self, script_content: str) -> DosfuscationResult:
        """
        Executes a complete multi-phase Invoke-DOSfuscation concatenation decoding run
        until convergence is reached.
        """
        original = script_content
        current = script_content
        patterns: List[ConcatenationPattern] = []
        local_env = dict(self.env)

        metrics = DosfuscationMetrics(bytes_before=len(original.encode('utf-8')))

        for pass_num in range(1, 15):
            prev = current

            # Step 1: Strip junk and empty interleaved variables
            current, stripped_junk = self.strip_junk_variables(current, local_env)
            metrics.junk_vars_stripped += stripped_junk
            if stripped_junk > 0 and pass_num == 1:
                patterns.append(ConcatenationPattern(
                    pattern_type=ConcatenationType.JUNK_VAR_INTERLEAVE,
                    confidence=0.95,
                    raw_snippet="interleaved empty variables",
                    normalized_snippet="stripped junk variables",
                    details={"count": stripped_junk}
                ))

            # Step 2: Normalize scrambled delimiters (, ; =) outside quotes
            current, norm_delims = self.normalize_delimiters(current)
            metrics.delimiters_normalized += norm_delims
            if norm_delims > 0 and pass_num == 1:
                patterns.append(ConcatenationPattern(
                    pattern_type=ConcatenationType.DELIMITER_SCRAMBLE,
                    confidence=0.90,
                    raw_snippet="scrambled commas/semicolons/equals",
                    normalized_snippet="normalized spaces",
                    details={"count": norm_delims}
                ))

            # Step 3: Resolve FOR token accumulation loops
            current, loop_accum = self.resolve_token_accumulation_loops(current, local_env)
            metrics.loops_accumulated += loop_accum
            if loop_accum > 0:
                patterns.append(ConcatenationPattern(
                    pattern_type=ConcatenationType.FOR_TOKEN_ACCUMULATOR,
                    confidence=0.98,
                    raw_snippet="for token accumulator loop",
                    normalized_snippet="folded assignment",
                    details={"count": loop_accum}
                ))

            # Step 4: Extract and register environment variables line-by-line
            lines = current.splitlines()
            for line in lines:
                self.extract_symbol_definitions(line, local_env)

            # Step 5: Fuse variable chains across the text
            current, var_fused = self.fuse_variable_chains(current, local_env)
            metrics.var_chains_fused += var_fused
            if var_fused > 0 and pass_num == 1:
                patterns.append(ConcatenationPattern(
                    pattern_type=ConcatenationType.VAR_FRAGMENT_CHAIN,
                    confidence=0.92,
                    raw_snippet="chained %var% tokens",
                    normalized_snippet="fused command tokens",
                    details={"count": var_fused}
                ))

            # Step 6: Unroll CALL execution trampolines
            current, trampolines = self.unroll_call_trampolines(current, local_env)
            metrics.trampolines_unrolled += trampolines
            if trampolines > 0:
                patterns.append(ConcatenationPattern(
                    pattern_type=ConcatenationType.CALL_TRAMPOLINE,
                    confidence=0.88,
                    raw_snippet="call dynamic trampoline",
                    normalized_snippet="direct command invocation",
                    details={"count": trampolines}
                ))

            if current == prev:
                break

        metrics.bytes_after = len(current.encode('utf-8'))
        metrics.total_patterns_detected = len(patterns)

        # Calculate concatenation score
        score = min(1.0, (metrics.var_chains_fused * 0.1) +
                         (metrics.junk_vars_stripped * 0.15) +
                         (metrics.delimiters_normalized * 0.05) +
                         (metrics.loops_accumulated * 0.3) +
                         (metrics.trampolines_unrolled * 0.1))

        return DosfuscationResult(
            original_text=original,
            decoded_text=current,
            patterns=patterns,
            metrics=metrics,
            concatenation_score=score
        )
