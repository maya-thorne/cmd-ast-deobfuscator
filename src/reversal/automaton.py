"""
Pushdown Automaton and State Machine Simulator for String Reversal and Transposition.
Simulates FOR /L reverse iterations, pushdown stack automata,
index transposition vectors, and rail fence transposition decoders with strict DoS guards.
"""

from typing import List, Optional, Dict, Any, Tuple
from .models import ReversalPatternType, TranspositionResult

MAX_SIMULATION_STEPS: int = 20000


class StringReversalAutomaton:
    """
    State machine engine capable of reconstructing obfuscated strings produced by
    Somalifuscator, Batch-Obfuscator, and Invoke-DOSfuscation transposition primitives.
    """

    @staticmethod
    def reverse(text: str) -> str:
        """Direct character reversal of a string."""
        return text[::-1]

    @staticmethod
    def zeroize(buffer: Any) -> None:
        """Best-effort in-memory zeroing of sensitive intermediate text buffers."""
        if isinstance(buffer, bytearray):
            for i in range(len(buffer)):
                buffer[i] = 0

    @staticmethod
    def get_slice(val: str, start: int, length: Optional[int] = 1) -> str:
        """
        Extracts a substring from val according to Windows cmd.exe semantics:
        Handles positive/negative start offsets and bounds clamping without exceptions.
        """
        n = len(val)
        if n == 0:
            return ""

        if start < 0:
            offset = 0 if -start >= n else max(0, n + start)
        else:
            offset = start

        if offset >= n or offset < 0:
            return ""

        if length is None:
            return val[offset:]
        if length == 0:
            return ""

        if length < 0:
            end_offset = n + length
        else:
            end_offset = offset + length

        if end_offset <= offset:
            return ""
        if end_offset > n:
            end_offset = n

        return val[offset:end_offset]

    @classmethod
    def simulate_slice_loop(
        cls,
        source_text: str,
        start: int,
        step: int,
        stop: int,
        slice_len: int = 1,
        is_prepend: bool = False,
        max_steps: int = MAX_SIMULATION_STEPS
    ) -> TranspositionResult:
        """
        Simulates execution of a FOR /L loop extracting slices from source_text:
        e.g., for /l %i in (start, step, stop) do set out=!out!!s:~%i,1!
        Guarded against infinite loops and DoS bounds.
        """
        if step == 0:
            return TranspositionResult(
                pattern_type=ReversalPatternType.FOR_L_REVERSAL,
                source_text=source_text,
                decoded_text="",
                source_var="",
                dest_var="",
                steps_simulated=0
            )

        accum: List[str] = []
        curr = start
        steps = 0

        # Determine loop continuation condition based on step sign
        def should_continue(c: int) -> bool:
            if step > 0:
                return c <= stop
            else:
                return c >= stop

        while should_continue(curr) and steps < max_steps:
            chunk = cls.get_slice(source_text, curr, slice_len)
            if is_prepend:
                accum.insert(0, chunk)
            else:
                accum.append(chunk)
            curr += step
            steps += 1

        decoded = "".join(accum)
        return TranspositionResult(
            pattern_type=ReversalPatternType.FOR_L_PREPEND if is_prepend else ReversalPatternType.FOR_L_REVERSAL,
            source_text=source_text,
            decoded_text=decoded,
            source_var="",
            dest_var="",
            steps_simulated=steps,
            metadata={"start": start, "step": step, "stop": stop, "slice_len": slice_len}
        )

    @classmethod
    def simulate_index_sequence(
        cls,
        source_text: str,
        indices: List[int],
        slice_len: int = 1,
        is_prepend: bool = False,
        max_steps: int = MAX_SIMULATION_STEPS
    ) -> TranspositionResult:
        """
        Simulates character transposition via an explicit sequence of index lookups:
        e.g., for %a in (22 7 14 0 12 8) do set out=!out!!dict:~%a,1!
        """
        accum: List[str] = []
        steps = 0

        for idx in indices:
            if steps >= max_steps:
                break
            chunk = cls.get_slice(source_text, idx, slice_len)
            if is_prepend:
                accum.insert(0, chunk)
            else:
                accum.append(chunk)
            steps += 1

        decoded = "".join(accum)
        return TranspositionResult(
            pattern_type=ReversalPatternType.FOR_IN_TRANSPOSITION,
            source_text=source_text,
            decoded_text=decoded,
            source_var="",
            dest_var="",
            steps_simulated=steps,
            metadata={"indices_count": len(indices), "slice_len": slice_len}
        )

    @classmethod
    def simulate_stack_reversal(
        cls,
        source_text: str,
        max_steps: int = MAX_SIMULATION_STEPS
    ) -> TranspositionResult:
        """
        Simulates a pushdown stack reversal automaton:
        e.g., :loop & set dst=%dst%%src:~-1% & set src=%src:~0,-1% & if defined src goto loop
        """
        stack = list(source_text)
        out: List[str] = []
        steps = 0

        while stack and steps < max_steps:
            out.append(stack.pop())
            steps += 1

        decoded = "".join(out)
        return TranspositionResult(
            pattern_type=ReversalPatternType.GOTO_STACK_REVERSAL,
            source_text=source_text,
            decoded_text=decoded,
            source_var="",
            dest_var="",
            steps_simulated=steps
        )

    @classmethod
    def apply_permutation(cls, source_text: str, permutation: List[int]) -> str:
        """Reorders characters according to a zero-based permutation index list."""
        n = len(source_text)
        result = []
        for idx in permutation:
            if 0 <= idx < n:
                result.append(source_text[idx])
        return "".join(result)

    @classmethod
    def decode_rail_fence(cls, ciphertext: str, rails: int) -> Optional[str]:
        """Decodes a rail-fence transposition cipher with the given number of rails."""
        if rails <= 1 or len(ciphertext) <= rails:
            return ciphertext

        n = len(ciphertext)
        # Determine fence rail pattern indices
        rail_pattern = []
        rail = 0
        direction = 1
        for _ in range(n):
            rail_pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        # Count chars in each rail
        counts = [rail_pattern.count(r) for r in range(rails)]
        rail_chars: List[List[str]] = []
        idx = 0
        for count in counts:
            rail_chars.append(list(ciphertext[idx:idx + count]))
            idx += count

        # Reconstruct decoded string
        decoded = []
        rail_ptrs = [0] * rails
        for r in rail_pattern:
            decoded.append(rail_chars[r][rail_ptrs[r]])
            rail_ptrs[r] += 1

        return "".join(decoded)
