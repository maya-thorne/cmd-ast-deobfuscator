"""
Parameter and FOR Variable Path Modifier Interpreter for Windows cmd.exe.
Parses and evaluates syntax modifiers (~f, ~d, ~p, ~n, ~x, ~s, ~a, ~t, ~z, ~$VAR:).
"""

import os
import re
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple


@dataclass
class ModifierSpec:
    """
    Structured representation of parameter/FOR variable path modifiers.
    E.g. %~dp0 -> drive=True, path_dir=True, strip_quotes=True
    """
    raw: str = ""
    strip_quotes: bool = False
    full_path: bool = False
    drive: bool = False
    path_dir: bool = False
    name: bool = False
    extension: bool = False
    short_path: bool = False
    attributes: bool = False
    timestamp: bool = False
    size: bool = False
    search_var: Optional[str] = None

    @property
    def has_path_modifiers(self) -> bool:
        """Returns True if any path transformation modifiers are present."""
        return any([
            self.full_path, self.drive, self.path_dir, self.name,
            self.extension, self.short_path, self.attributes,
            self.timestamp, self.size, bool(self.search_var)
        ])


def parse_modifiers(mod_str: str) -> ModifierSpec:
    """
    Parses a modifier string into a ModifierSpec.
    Examples:
        '~dp' -> strip_quotes=True, drive=True, path_dir=True
        '~nx' -> strip_quotes=True, name=True, extension=True
        '~f'  -> strip_quotes=True, full_path=True
        '~$PATH:' -> strip_quotes=True, search_var='PATH'
        '~'   -> strip_quotes=True
    """
    spec = ModifierSpec(raw=mod_str)
    if not mod_str:
        return spec

    if mod_str.startswith('~'):
        spec.strip_quotes = True
        body = mod_str[1:]
    else:
        body = mod_str

    # Extract $VAR: if present e.g. ~$PATH: or $LIB:
    search_match = re.search(r'\$([a-zA-Z0-9_]+):', body)
    if search_match:
        spec.search_var = search_match.group(1).upper()
        # Remove the $VAR: portion from body for remaining flag inspection
        body = body[:search_match.start()] + body[search_match.end():]

    for char in body.lower():
        if char == 'f':
            spec.full_path = True
        elif char == 'd':
            spec.drive = True
        elif char == 'p':
            spec.path_dir = True
        elif char == 'n':
            spec.name = True
        elif char == 'x':
            spec.extension = True
        elif char == 's':
            spec.short_path = True
        elif char == 'a':
            spec.attributes = True
        elif char == 't':
            spec.timestamp = True
        elif char == 'z':
            spec.size = True

    return spec


class PathModifierResolver:
    """
    Evaluates Windows parameter and FOR variable path modifiers statically.
    Implements deterministic, cross-platform path splitting and canonicalization
    mirroring cmd.exe modifier behavior without invoking external processes.
    """
    DEFAULT_BASE_DIR = r"C:\Windows\System32"
    DEFAULT_ATTRIBUTES = "--a--------"
    DEFAULT_TIMESTAMP = "2026-10-13 10:00"
    DEFAULT_SIZE = "0"

    @staticmethod
    def unquote(target: str) -> str:
        """Strips matching outer quotes from string if present."""
        s = target.strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            if len(s) >= 2:
                return s[1:-1]
        return s

    @classmethod
    def to_83_short_name(cls, segment: str) -> str:
        """
        Synthesizes an 8.3 short name representation for a path segment.
        E.g. 'Program Files' -> 'PROGRA~1', 'document.markdown' -> 'DOCUME~1.MAR'
        """
        # If segment already conforms to 8.3 without spaces or long names, keep it
        clean_seg = segment.replace('/', '\\')
        if ' ' not in clean_seg and len(clean_seg) <= 12 and '.' in clean_seg:
            name_p, ext_p = clean_seg.rsplit('.', 1)
            if len(name_p) <= 8 and len(ext_p) <= 3 and '~' not in name_p:
                return clean_seg.upper()

        if '.' in clean_seg:
            name_part, ext_part = clean_seg.rsplit('.', 1)
            ext_83 = re.sub(r'[^A-Za-z0-9]', '', ext_part)[:3].upper()
        else:
            name_part = clean_seg
            ext_83 = ""

        # Remove spaces and invalid characters
        alnum_name = re.sub(r'[^A-Za-z0-9]', '', name_part).upper()
        if not alnum_name:
            alnum_name = "FILE"

        base_6 = alnum_name[:6]
        short_base = f"{base_6}~1" if len(alnum_name) > 8 or ' ' in clean_seg else alnum_name[:8]
        if ext_83:
            return f"{short_base}.{ext_83}"
        return short_base

    @classmethod
    def split_windows_path(cls, path_str: str) -> Tuple[str, str, str, str]:
        """
        Decomposes a Windows path into (drive, directory, filename, extension).
        Examples:
            'C:\\foo\\bar.txt' -> ('C:', '\\foo\\', 'bar', '.txt')
            '\\\\server\\share\\foo.exe' -> ('\\\\server\\share', '\\', 'foo', '.exe')
            'bar.txt' -> ('', '', 'bar', '.txt')
        """
        norm = path_str.replace('/', '\\')

        drive = ""
        rest = norm

        # UNC path \\server\share
        if norm.startswith(r'\\'):
            parts = norm[2:].split('\\', 2)
            if len(parts) >= 2:
                drive = r'\\' + parts[0] + r'\\' + parts[1]
                rest = '\\' + parts[2] if len(parts) > 2 else '\\'
            else:
                drive = norm
                rest = ""
        # Standard drive letter C:
        elif len(norm) >= 2 and norm[1] == ':' and norm[0].isalpha():
            drive = norm[:2].upper()
            rest = norm[2:]

        # Split remaining into directory and filename
        if '\\' in rest:
            last_slash = rest.rfind('\\')
            dir_part = rest[:last_slash + 1]
            file_part = rest[last_slash + 1:]
        else:
            dir_part = ""
            file_part = rest

        # Split filename and extension
        if '.' in file_part and not file_part.startswith('.'):
            name, ext = file_part.rsplit('.', 1)
            ext = '.' + ext
        elif file_part.startswith('.') and file_part.count('.') > 1:
            name, ext = file_part.rsplit('.', 1)
            ext = '.' + ext
        else:
            name = file_part
            ext = ""

        return drive, dir_part, name, ext

    @classmethod
    def make_absolute(cls, path_str: str, base_dir: str) -> str:
        """
        Resolves relative paths against base_dir with Windows backslash rules.
        """
        norm_path = path_str.replace('/', '\\')
        norm_base = base_dir.replace('/', '\\').rstrip('\\')

        # Already absolute with drive: C:\... or C:...
        if len(norm_path) >= 2 and norm_path[0].isalpha() and norm_path[1] == ':':
            return norm_path
        if norm_path.startswith(r'\\'):
            return norm_path

        # Rooted path without drive: \foo\bar -> attach drive from base_dir
        if norm_path.startswith('\\'):
            drive_prefix = norm_base[:2] if len(norm_base) >= 2 and norm_base[1] == ':' else "C:"
            return drive_prefix + norm_path

        # Relative path: base_dir \ path
        return norm_base + '\\' + norm_path

    @classmethod
    def search_in_var(cls, filename: str, var_name: str, env: Optional[Dict[str, str]] = None) -> Optional[str]:
        """
        Simulates %~$VAR:1 search across directory paths in environment variable.
        """
        if not env:
            return None
        var_val = None
        for k, v in env.items():
            if k.upper() == var_name.upper():
                var_val = v
                break
        if not var_val:
            return None

        dirs = [d.strip() for d in var_val.split(';') if d.strip()]
        for d in dirs:
            clean_d = d.replace('/', '\\').rstrip('\\')
            candidate = f"{clean_d}\\{filename}"
            # Check candidate match
            return candidate

        return None

    @classmethod
    def resolve(
        cls,
        spec: ModifierSpec,
        target_val: str,
        base_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        fs_metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Applies ModifierSpec to target_val and returns resolved string.
        """
        base = base_dir or cls.DEFAULT_BASE_DIR

        # 1. Unquote if requested or standard parameter modifier
        resolved_target = cls.unquote(target_val) if spec.strip_quotes else target_val

        # If only ~ is used without any path flags: return unquoted string
        if not spec.has_path_modifiers:
            return resolved_target

        # 2. $VAR: search resolution
        if spec.search_var:
            filename = os.path.basename(resolved_target.replace('/', '\\'))
            found = cls.search_in_var(filename, spec.search_var, env)
            if not found:
                return ""
            resolved_target = found

        # 3. File metadata modifiers (attributes, timestamp, size)
        meta = fs_metadata or {}
        if spec.attributes and not (spec.drive or spec.path_dir or spec.name or spec.extension):
            return str(meta.get('attributes', cls.DEFAULT_ATTRIBUTES))
        if spec.timestamp and not (spec.drive or spec.path_dir or spec.name or spec.extension):
            return str(meta.get('timestamp', cls.DEFAULT_TIMESTAMP))
        if spec.size and not (spec.drive or spec.path_dir or spec.name or spec.extension):
            return str(meta.get('size', cls.DEFAULT_SIZE))

        # 4. Make absolute if full_path requested or combined path modifiers present
        full_abs = cls.make_absolute(resolved_target, base)
        drive, dir_part, name, ext = cls.split_windows_path(full_abs)

        # 5. Short path (8.3) transformation
        if spec.short_path:
            # Transform each directory segment to 8.3
            dir_segs = [s for s in dir_part.split('\\') if s]
            short_segs = [cls.to_83_short_name(s) for s in dir_segs]
            dir_part = ('\\' + '\\'.join(short_segs) + '\\') if short_segs else '\\'
            if name or ext:
                full_file = name + ext
                short_file = cls.to_83_short_name(full_file)
                if '.' in short_file:
                    name, ext = short_file.rsplit('.', 1)
                    ext = '.' + ext
                else:
                    name = short_file
                    ext = ""

        # 6. Assemble requested components in canonical cmd.exe order:
        # Canonical order: drive -> dir_part -> name -> ext
        # If full_path alone (e.g. %~f1 or %~fs1):
        if spec.full_path and not (spec.drive or spec.path_dir or spec.name or spec.extension):
            return f"{drive}{dir_part}{name}{ext}"

        result_parts = []
        if spec.drive:
            result_parts.append(drive)
        if spec.path_dir:
            # Ensure path_dir has trailing slash if non-empty
            if dir_part and not dir_part.endswith('\\'):
                dir_part += '\\'
            result_parts.append(dir_part)
        if spec.name:
            result_parts.append(name)
        if spec.extension:
            result_parts.append(ext)

        # If none of d, p, n, x were matched but full_path was set
        if not result_parts:
            return f"{drive}{dir_part}{name}{ext}"

        return "".join(result_parts)
