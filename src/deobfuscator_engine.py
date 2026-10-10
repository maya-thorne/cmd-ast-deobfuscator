#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmd-ast-deobfuscator: Multi-Pass Pushdown Automaton & Substring Slicing Deobfuscator Engine
Synthesizes state-machine techniques from DissectMalware (CCCS), Invoke-DOSfuscation, 0xidiz3r, and SomalifuscatorV2.
"""

import re
import sys
import os


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

    def resolve_slicing(self, text: str) -> str:
        """Resolve %VAR:~start,length% and !VAR:~start,length! substring operations."""
        def slice_repl(match):
            var_name = match.group(2).lower()
            start = int(match.group(3))
            length = match.group(4)

            if var_name in self.env_vars:
                val = self.env_vars[var_name]
                if length is not None:
                    length = int(length)
                    if length < 0:
                        return val[start:length]
                    if start < 0:
                        end_idx = len(val) + start + length
                        return val[start : end_idx if end_idx <= len(val) else None]
                    return val[start : start + length]
                return val[start:]
            return match.group(0)

        pattern = r'([%!])([a-zA-Z0-9_\-\.\:\$]+):~(-?\d+)(?:,(-?\d+))?\1'
        return re.sub(pattern, slice_repl, text)

    def resolve_substitution(self, text: str) -> str:
        """Resolve %VAR:old=new% string replacement syntax."""
        def sub_repl(match):
            var_name = match.group(2).lower()
            old_str = match.group(3)
            new_str = match.group(4)
            if var_name in self.env_vars:
                val = self.env_vars[var_name]
                return re.sub(re.escape(old_str), new_str, val, flags=re.IGNORECASE)
            return match.group(0)

        pattern = r'([%!])([a-zA-Z0-9_\-\.\:\$]+):([^%=!\r\n]+)=([^%=!\r\n]*)\1'
        return re.sub(pattern, sub_repl, text)

    def resolve_variables(self, text: str) -> str:
        """Resolve slicing, substitution, and direct %VAR% / !VAR! expansions."""
        text = self.resolve_slicing(text)
        text = self.resolve_substitution(text)

        def var_repl(match):
            vname = match.group(2).lower()
            if vname in self.env_vars:
                return self.env_vars[vname]
            return match.group(0)

        pattern = r'([%!])([a-zA-Z0-9_\-\.\:\$]+)\1'
        return re.sub(pattern, var_repl, text)

    def deobfuscate(self, script_content: str) -> str:
        """Execute multi-pass deobfuscation until fixed-point convergence."""
        current = self.strip_bom_and_empty_quotes(script_content)

        for _ in range(1, self.max_passes + 1):
            prev = current
            current = self.strip_carets(current)
            current = self.strip_bom_and_empty_quotes(current)

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
