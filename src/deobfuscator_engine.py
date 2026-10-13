#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Multi-Pass Pushdown Automaton & Substring Slicing Deobfuscator Engine
Synthesizes state-machine techniques from DissectMalware (CCCS), Invoke-DOSfuscation, 0xidiz3r, and SomalifuscatorV2.
"""

import re
import sys
import os
from typing import Optional

try:
    from .reversal.automaton import StringReversalAutomaton
except (ImportError, ValueError):
    try:
        from reversal.automaton import StringReversalAutomaton
    except ImportError:
        StringReversalAutomaton = None

try:
    from .quotes import collapse_empty_quotes
except (ImportError, ValueError):
    try:
        from quotes import collapse_empty_quotes
    except ImportError:
        collapse_empty_quotes = None


class BatchDeobfuscator:
    def __init__(self, max_passes: int = 15):
        self.max_passes = max_passes
        self.env_vars = {}
        self.env_vars.update({
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
        })

    def strip_bom_and_empty_quotes(self, text: str) -> str:
        """Remove UTF-16/UTF-8 BOM headers and obfuscated empty quote pairs (e.g. w""h""o -> who)."""
        text = text.lstrip("\ufeff\ufffe")
        if collapse_empty_quotes:
            return collapse_empty_quotes(text)
        return re.sub(r'([a-zA-Z0-9_/\-\.])""(?=[a-zA-Z0-9_/\-\.])', r"\1", text)

    def strip_carets(self, text: str) -> str:
        """Strip carets outside double quotes while preserving quoted strings."""
        result = []
        in_quotes = False
        i = 0
        n = len(text)
        while i < n:
            char = text[i]
            if char == '"':
                in_quotes = not in_quotes
                result.append(char)
                i += 1
            elif char == "^":
                if in_quotes:
                    result.append(char)
                    i += 1
                else:
                    if i + 1 < n:
                        result.append(text[i + 1])
                        i += 2
                    else:
                        i += 1
            else:
                result.append(char)
                i += 1
        return "".join(result)

    def extract_and_set_vars(self, line: str) -> None:
        """Identify 'set VAR=VAL' or 'set \"VAR=VAL\"' and record in virtual symbol table."""
        cleaned = line.strip()
        if cleaned.lower().startswith("@"):
            cleaned = cleaned[1:].strip()

        m = re.match(
            r'^set\s+(?:/a\s+|/p\s+)?(?:")?([a-zA-Z0-9_\-\.\:\$]+)=([^"\r\n]*)(?:")?',
            cleaned,
            re.IGNORECASE,
        )
        if m:
            var_name = m.group(1).lower()
            var_val = self.resolve_variables(m.group(2))
            self.env_vars[var_name] = var_val

    @staticmethod
    def calculate_slice(val: str, start: int, length: Optional[int]) -> str:
        """Computes cmd.exe substring slicing with positive and negative indices."""
        n = len(val)
        if start < 0:
            offset = max(0, n + start)
        else:
            offset = start

        if offset >= n:
            return ""

        if length is None:
            return val[offset:]

        if length < 0:
            end_offset = n + length
        else:
            end_offset = offset + length

        if end_offset <= offset:
            return ""

        return val[offset:end_offset]

    def resolve_slicing(self, text: str) -> str:
        """Resolve %VAR:~start,length% and !VAR:~start,length! substring operations."""
        def slice_repl(match):
            var_name = match.group(2).lower()
            start_str = match.group(3)
            start = int(start_str) if start_str else 0
            has_comma = match.group(4) is not None
            len_str = match.group(5)

            if var_name in self.env_vars:
                val = self.env_vars[var_name]
                length = (int(len_str) if len_str else 0) if has_comma else None
                return self.calculate_slice(val, start, length)
            return match.group(0)

        pattern = r'([%!])([a-zA-Z0-9_\-\.\$]+):~(-?\d*)(?:(,)(-?\d*))?\1'
        return re.sub(pattern, slice_repl, text)

    def resolve_substitution(self, text: str) -> str:
        """Resolve %VAR:old=new% string replacement syntax."""
        def sub_repl(match):
            var_name = match.group(2).lower()
            old_str = match.group(3)
            new_str = match.group(4)
            if var_name in self.env_vars:
                val = self.env_vars[var_name]
                if not old_str or old_str == '*':
                    return match.group(0)
                if old_str.startswith('*'):
                    target_str = old_str[1:]
                    if not target_str:
                        return match.group(0)
                    idx = val.lower().find(target_str.lower())
                    if idx != -1:
                        return new_str + val[idx + len(target_str):]
                    return val
                pattern = re.compile(re.escape(old_str), re.IGNORECASE)
                return pattern.sub(lambda _: new_str, val)
            return match.group(0)

        pattern = r'([%!])([a-zA-Z0-9_\-\.\$]+):([^%=!\r\n]+)=([^%=!\r\n]*)\1'
        return re.sub(pattern, sub_repl, text)

    def resolve_variables(self, text: str) -> str:
        """Resolve slicing, substitution, and direct %VAR% / !VAR! expansions."""
        prev = None
        iters = 0
        while prev != text and iters < 10:
            prev = text
            iters += 1
            text = self.resolve_slicing(text)
            text = self.resolve_substitution(text)

            def var_repl(match):
                vname = match.group(2).lower()
                if vname in self.env_vars:
                    return self.env_vars[vname]
                return match.group(0)

            pattern = r'([%!])([a-zA-Z0-9_\-\.\$]+)\1'
            text = re.sub(pattern, var_repl, text)

        return text

    def resolve_reversal_loops(self, text: str) -> str:
        """Resolve Somalifuscator FOR /L reverse string loops e.g. for /l %i in (len,-1,0) do set out=!out!!s:~%i,1!."""
        if not StringReversalAutomaton:
            return text

        def loop_repl(m):
            iterator = m.group(1).lstrip('%')
            in_clause = m.group(2).strip()
            in_clause = self.resolve_variables(in_clause)
            parts = [p.strip() for p in re.split(r'[, \t]+', in_clause) if p.strip()]
            if len(parts) != 3:
                return m.group(0)
            try:
                start, step, stop = int(parts[0]), int(parts[1]), int(parts[2])
            except ValueError:
                return m.group(0)

            dest_var = m.group(3)
            body_expr = m.group(4)

            pat_app = re.compile(
                r'[%!]' + re.escape(dest_var) + r'[%!]\s*[%!]([a-zA-Z0-9_\-\.\$]+):~%*' +
                re.escape(iterator) + r'(?:,(\d+))?[%!]',
                re.IGNORECASE
            )
            pat_prep = re.compile(
                r'[%!]([a-zA-Z0-9_\-\.\$]+):~%*' + re.escape(iterator) +
                r'(?:,(\d+))?[%!]\s*[%!]' + re.escape(dest_var) + r'[%!]',
                re.IGNORECASE
            )

            m_app = pat_app.search(body_expr)
            m_prep = pat_prep.search(body_expr)
            if not m_app and not m_prep:
                return m.group(0)

            source_var = (m_app or m_prep).group(1)
            slice_len = int((m_app or m_prep).group(2)) if (m_app or m_prep).group(2) else 1
            is_prepend = bool(m_prep)

            source_key = source_var.lower()
            if source_key not in self.env_vars:
                return m.group(0)

            source_val = self.env_vars[source_key]
            sim_res = StringReversalAutomaton.simulate_slice_loop(
                source_text=source_val,
                start=start,
                step=step,
                stop=stop,
                slice_len=slice_len,
                is_prepend=is_prepend
            )
            decoded = sim_res.decoded_text
            self.env_vars[dest_var.lower()] = decoded
            return f'set "{dest_var}={decoded}"'

        pattern = r'(?i)for\s+/l\s+(%[a-zA-Z0-9_]+)\s+in\s*\(([^)]+)\)\s+do\s+(?:\()?set\s+(?:/a\s+|/p\s+)?(?:")?([a-zA-Z0-9_\-\.\$]+)=([^"\r\n\)]+)(?:")?(?:\))?'
        return re.sub(pattern, loop_repl, text)

    def deobfuscate(self, script_content: str) -> str:
        """Execute multi-pass deobfuscation until fixed-point convergence."""
        current = self.strip_bom_and_empty_quotes(script_content)

        for _ in range(1, self.max_passes + 1):
            prev = current
            current = self.strip_carets(current)
            current = self.strip_bom_and_empty_quotes(current)
            current = self.resolve_reversal_loops(current)

            lines = current.splitlines()
            processed_lines = []
            for line in lines:
                self.extract_and_set_vars(line)
                resolved_line = self.resolve_variables(line)
                processed_lines.append(resolved_line)

            current = "\n".join(processed_lines)
            if current == prev:
                break

        return current


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python deobfuscator_engine.py <input.bat> [output.bat]")
        sys.exit(1)

    in_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else in_file + ".deobf.bat"

    with open(in_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    engine = BatchDeobfuscator()
    clean = engine.deobfuscate(content)

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(clean)

    print(f"[+] Deobfuscation complete. Result saved to: {out_file}")
