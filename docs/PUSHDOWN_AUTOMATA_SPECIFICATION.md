# ⚙️ Pushdown Automaton (PDA) Specification for `cmd.exe`

This document defines the formal Pushdown Automaton modeling the parsing states of the Microsoft Windows Command Processor.

---

## 1. Formal Definition

The pushdown automaton is formally defined as a 7-tuple:

$$M = (Q, \Sigma, \Gamma, \delta, q_0, Z_0, F)$$

Where:
- **$Q$** (Finite set of states):
  - $q_0$: `START`
  - $q_1$: `IN_COMMAND`
  - $q_2$: `IN_ARGUMENTS`
  - $q_3$: `IN_SET_NAME`
  - $q_4$: `IN_SET_VALUE`
  - $q_5$: `IN_BLOCK`
  - $q_6$: `IN_PIPE`
  - $q_7$: `IN_REDIRECT`
  - $q_f$: `TERMINAL`
- **$\Sigma$** (Input alphabet): Lexical tokens emitted by `CmdLexer` (`LITERAL`, `CARET`, `QUOTE`, `PERCENT_VAR`, `PIPE`, `AMP`, `LPAREN`, `RPAREN`, `NEWLINE`, `EOF`).
- **$\Gamma$** (Stack alphabet): $\{\ '('\ ,\ Z_0 \}$ representing nested parenthesized compound block contexts.
- **$q_0$**: Initial state (`START`).
- **$Z_0$**: Bottom of stack marker.
- **$F$**: Set of accepting states $\{ q_f \}$.

---

## 2. State Transition Table

| Current State ($q$) | Input Symbol ($\sigma$) | Stack Top ($\gamma$) | Next State ($q'$) | Stack Operation | Semantic Action |
| :---: | :---: | :---: | :---: | :---: | :--- |
| `START` | `LITERAL ("set")` | Any | `IN_SET_NAME` | None | Begin variable assignment |
| `START` | `LITERAL (other)` | Any | `IN_COMMAND` | None | Set command executable target |
| `START` | `LPAREN ("(")` | $\gamma$ | `IN_BLOCK` | Push `(` | Open nested compound block |
| `IN_SET_NAME` | `EQUALS ("=")` | Any | `IN_SET_VALUE` | None | Transition to assigned expression |
| `IN_SET_VALUE` | `NEWLINE` / `AMP` | Any | `START` | None | Commit assignment to symbol table |
| `IN_COMMAND` | `LITERAL` / `ATOM` | Any | `IN_ARGUMENTS` | None | Append argument token |
| `IN_ARGUMENTS` | `PIPE ("|")` | Any | `IN_PIPE` | None | Construct PipeNode |
| `IN_ARGUMENTS` | `REDIRECT (">", ">>", "<")` | Any | `IN_REDIRECT` | None | Construct RedirectNode |
| `IN_ARGUMENTS` | `AMP ("&", "&&", "||")` | Any | `START` | None | Construct ChainNode |
| `IN_ARGUMENTS` | `RPAREN (")")` | `(` | `IN_COMMAND` | Pop `(` | Close compound block |
| `IN_BLOCK` | `RPAREN (")")` | `(` | `IN_COMMAND` | Pop `(` | Exit block frame |
| `Any` | `EOF` | $Z_0$ | `TERMINAL` | None | Accept parse tree |

---

## 3. Quoting and Escape Invariants

1. **Quote Context Invariance**: When a double quote is opened, state transitions on operators (`|`, `&`, `>`, `<`) are suppressed; the tokens are ingested as raw `LiteralNode` values.
2. **Stack Depth Invariance**: A script is syntactically valid with respect to compound blocks if and only if upon consuming `EOF`, the stack contains solely the bottom marker $Z_0$ (i.e., $\text{depth} = 0$).
