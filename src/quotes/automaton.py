"""
Quote toggle boundary pushdown automaton for Windows cmd.exe scripts.
Tracks quotation toggle transitions, escaped quotes, and performs deterministic
empty-quote collapse, target deobfuscation, and argument canonicalization.
"""

import re
from typing import List, Tuple, Optional
from .models import QuoteState, QuoteSegment, QuoteNormalizerMetrics


class QuoteToggleAutomaton:
    """
    Automaton tracking cmd.exe quotation boundary transitions.
    In cmd.exe:
      - Double quote (") toggles quote state on and off.
      - Caret escape (^") outside quotes emits a literal quote without toggling.
      - Caret (^) inside quotes is treated as a literal character.
      - Command target lookup strips all quotes from the executable name.
      - Command arguments with redundant or fragmented quotes can be canonicalized.
    """

    SAFE_ARG_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.\:\/\\~\$]+$')
    METADELIMS = set(' \t&|<>()^,;=')

    def __init__(self):
        self.metrics = QuoteNormalizerMetrics()

    def tokenize_segments(self, text: str) -> List[QuoteSegment]:
        """
        Tokenizes text into alternating quoted and unquoted segments based on cmd.exe toggle rules.
        """
        if not text:
            return []

        segments: List[QuoteSegment] = []
        n = len(text)
        i = 0
        in_quote = False
        current_chunk: List[str] = []
        chunk_start = 0

        while i < n:
            ch = text[i]

            # Escaped quote outside quotes: ^"
            if not in_quote and ch == '^' and i + 1 < n and text[i + 1] == '"':
                if current_chunk:
                    segments.append(QuoteSegment(
                        text="".join(current_chunk),
                        is_quoted=in_quote,
                        span=(chunk_start, i)
                    ))
                    current_chunk = []
                segments.append(QuoteSegment(
                    text='"',
                    is_quoted=False,
                    is_escaped=True,
                    span=(i, i + 2)
                ))
                i += 2
                chunk_start = i
                continue

            # Quote toggle: "
            if ch == '"':
                if current_chunk:
                    segments.append(QuoteSegment(
                        text="".join(current_chunk),
                        is_quoted=in_quote,
                        span=(chunk_start, i)
                    ))
                    current_chunk = []
                in_quote = not in_quote
                i += 1
                chunk_start = i
                continue

            current_chunk.append(ch)
            i += 1

        if current_chunk:
            segments.append(QuoteSegment(
                text="".join(current_chunk),
                is_quoted=in_quote,
                span=(chunk_start, n)
            ))

        return segments

    def collapse_empty_quotes(self, text: str) -> str:
        """
        Collapses redundant empty quote pairs and consecutive quote sequences.
        Examples:
          - c""m""d -> cmd
          - 4 consecutive quotes -> 2 quotes
          - "" -> "" (standalone empty string preserved)
        """
        if not text:
            return ""

        self.metrics.total_tokens_processed += 1

        # Standalone empty string argument: keep as ""
        if text == '""':
            return text

        # 1. Reduce sequences of 3 or more consecutive quotes
        def _reduce_consecutive_quotes(m: re.Match) -> str:
            count = len(m.group(0))
            self.metrics.consecutive_quotes_reduced += (count - 2)
            # An even number of quotes collapses to '' if embedded, or '""' if at least one pair is kept
            return '""'

        prev = None
        current = text
        while prev != current:
            prev = current
            current = re.sub(r'"{3,}', _reduce_consecutive_quotes, current)

        # 2. Collapse embedded empty quote pairs "" outside other quotes
        segments = self.tokenize_segments(current)
        if not segments:
            # All quotes toggled with no inner text (e.g. "" or """" or """""")
            self.metrics.empty_pairs_collapsed += 1
            return '""' if ('"' in text) else ''

        # Reconstruct string by filtering out empty segments resulting from ""
        res_parts: List[str] = []
        empty_pair_count = current.count('""')
        if empty_pair_count > 0:
            self.metrics.empty_pairs_collapsed += empty_pair_count

        # Embedded "" in words: who""ami -> whoami
        cleaned = current.replace('""', '')
        if not cleaned and current:
            return '""'
        return cleaned

    def normalize_target(self, target: str) -> str:
        """
        Normalizes a command target / executable name.
        cmd.exe strips all quotes when resolving command names.
        Examples:
          - '"c"m"d"' -> 'cmd'
          - 'c""m""d' -> 'cmd'
          - '""powershell""' -> 'powershell'
          - 'w^"h^"o^"a^"m^"i' -> 'whoami'
        """
        if not target:
            return ""

        self.metrics.total_tokens_processed += 1
        original = target

        # In cmd.exe command targets, double quotes are stripped entirely and carets unmasked
        res: List[str] = []
        i = 0
        n = len(target)

        while i < n:
            ch = target[i]
            if ch == '"':
                i += 1
                continue
            elif ch == '^':
                if i + 1 < n:
                    next_ch = target[i + 1]
                    if next_ch != '"':
                        res.append(next_ch)
                    i += 2
                    continue
                else:
                    i += 1
                    continue
            else:
                res.append(ch)
                i += 1

        cleaned = "".join(res)
        if cleaned != original:
            self.metrics.targets_normalized += 1

        return cleaned

    def normalize_argument(self, arg: str, preserve_delimiters: bool = True) -> str:
        """
        Normalizes a command argument token:
          - Standalone empty string '""' is preserved.
          - Purely alphanumeric / safe arguments without spaces or metacharacters
            have redundant quotes removed (e.g., '"calc.exe"' -> 'calc.exe').
          - Arguments containing spaces or metacharacters (&, |, <, >, ^) with
            fragmented quotes are canonicalized to a single outer quote pair
            (e.g., '"hello" "world"' -> '"hello world"').
          - Embedded empty quote pairs are collapsed (e.g., 'arg""val' -> 'argval').
        """
        if not arg:
            return ""

        self.metrics.total_tokens_processed += 1
        original = arg

        # Standalone empty string argument
        if arg.strip() == '""':
            return '""'

        # If argument has embedded empty quotes: collapse them
        if '""' in arg:
            arg = self.collapse_empty_quotes(arg)

        # Check if argument contains quotes
        if '"' not in arg:
            if arg != original:
                self.metrics.arguments_normalized += 1
            return arg

        # Check if argument is already cleanly quoted with exactly one pair (e.g., "dir")
        if arg.startswith('"') and arg.endswith('"') and arg.count('"') == 2:
            return arg

        # Tokenize segments to understand quote coverage
        segments = self.tokenize_segments(arg)
        inner_content = "".join(s.text for s in segments)

        # Check if inner content contains any whitespace or special delimiters
        has_metadelims = any(c in self.METADELIMS for c in inner_content)

        if not has_metadelims:
            # Safe token: unquote entirely
            self.metrics.arguments_normalized += 1
            return inner_content

        # Has spaces or metacharacters: needs surrounding quotes
        # Canonicalize to clean single enclosing pair: "inner_content"
        self.metrics.arguments_normalized += 1
        clean_inner = inner_content.replace('"', '')
        return f'"{clean_inner}"'

    def normalize_assignment_value(self, raw_value: str) -> Tuple[str, bool]:
        """
        Normalizes variable assignment value.
        Handles set "VAR=VAL", set ""VAR=VAL"", set VAR="VAL".
        Returns (normalized_value, is_enclosed_in_quotes).
        """
        if not raw_value:
            return "", False

        self.metrics.total_tokens_processed += 1

        # Check for outer enclosing quotes: "value"
        is_enclosed = False
        val = raw_value.strip()

        # Handle multiple redundant enclosing quotes: """val""" -> "val"
        while val.startswith('""') and val.endswith('""') and len(val) >= 4:
            self.metrics.consecutive_quotes_reduced += 1
            val = val[1:-1]

        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            is_enclosed = True
            inner = val[1:-1]
            # Strip embedded empty quotes
            cleaned_inner = self.collapse_empty_quotes(inner)
            self.metrics.assignments_normalized += 1
            return cleaned_inner, is_enclosed

        # Embedded empty quotes without outer enclosing quotes
        if '""' in val:
            val = self.collapse_empty_quotes(val)
            self.metrics.assignments_normalized += 1

        return val, is_enclosed

    def zeroize(self) -> None:
        """
        Wipes internal state and metrics for secure memory handling.
        """
        self.metrics = QuoteNormalizerMetrics()
