# 📐 Formal EBNF Grammar Specification for `cmd.exe`

This specification defines the formal Extended Backus-Naur Form (EBNF) grammar modeling the lexical and syntactic constructs of the Microsoft Windows Command Processor (`cmd.exe`).

---

## 1. Lexical Grammar (Tokens)

```ebnf
(* Character Sets *)
Character          = ? Any Unicode or ASCII character ? ;
Newline            = "\n" | "\r\n" ;
Whitespace         = " " | "\t" ;
Digit              = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" ;
Letter             = "a" ... "z" | "A" ... "Z" ;
SpecialChar        = "^" | '"' | "%" | "!" | "&" | "|" | "<" | ">" | "(" | ")" | "=" ;

(* Lexical Terminals *)
CaretEscape        = "^" , Character ;
EmptyQuotePair     = '""' ;
DoubleQuote        = '"' ;
PipeOp             = "|" ;
SeqOp              = "&" ;
AndOp              = "&&" ;
OrOp               = "||" ;
AssignOp           = "=" ;
RedirOut           = ">" ;
RedirAppend        = ">>" ;
RedirIn            = "<" ;

(* Environment Variable Tokens *)
VarName            = ( Letter | Digit | "_" )+ ;
SliceStart         = [ "-" ] , Digit+ ;
SliceLen           = [ "-" ] , Digit+ ;
PercentVar         = "%" , VarName , "%" ;
PercentSlice       = "%" , VarName , ":~" , SliceStart , [ "," , SliceLen ] , "%" ;
PercentSubst       = "%" , VarName , ":" , { Character - "=" } , "=" , { Character - "%" } , "%" ;
DelayedVar         = "!" , VarName , "!" ;
DelayedSlice       = "!" , VarName , ":~" , SliceStart , [ "," , SliceLen ] , "!" ;
```

---

## 2. Syntactic Grammar (Productions)

```ebnf
(* Script Level *)
Script             = { Line } , [ EOF ] ;
Line               = [ Statement ] , Newline ;

(* Statement Chaining *)
Statement          = Pipeline , { ChainOperator , Pipeline } ;
ChainOperator      = SeqOp | AndOp | OrOp ;

(* Pipelined Execution *)
Pipeline           = CommandOrBlock , { PipeOp , CommandOrBlock } ;

(* Compound Block vs Atomic Command *)
CommandOrBlock     = Block | Command | Assignment ;
Block              = "(" , { Line | Statement } , ")" ;

(* Variable Assignment *)
Assignment         = [ "set" | "SET" ] , Whitespace , [ "/a" | "/A" ] , Whitespace , 
                     VarName , AssignOp , [ Expression ] ;

(* Command Invocations *)
Command            = CommandTarget , { Argument } , { Redirection } ;
CommandTarget      = Atom+ ;
Argument           = Atom+ ;

(* Redirection Specifications *)
Redirection        = ( RedirOut | RedirAppend | RedirIn ) , Whitespace , Atom+ ;

(* Elementary Atoms *)
Atom               = CaretEscape
                   | EmptyQuotePair
                   | QuotedString
                   | PercentVar
                   | PercentSlice
                   | PercentSubst
                   | DelayedVar
                   | DelayedSlice
                   | LiteralText ;

QuotedString       = DoubleQuote , { Character - DoubleQuote } , DoubleQuote ;
LiteralText        = { Character - ( Whitespace | SpecialChar | Newline ) }+ ;
```

---

## 3. Discrepancy & Parser Quirks

1. **Quotation State Override**: Inside `QuotedString`, special operators (`&`, `|`, `<`, `>`, `^`) lose their delimiter semantics and are treated as literal text.
2. **Caret Neutralization**: A non-quoted caret (`^`) immediately followed by another character strips itself and emits the subsequent character literally into the argument token.
3. **Empty Double-Quote Collapse**: Consecutive double quotes outside existing quoted spans (`""`) are collapsed into empty strings without introducing token boundaries.

---

## 4. Conformance Validator & Canonical Test Corpus

The formal EBNF grammar is programmatically implemented and validated via `src/ebnf/`:
- **Models & Rule Registry (`src/ebnf/models.py`, `src/ebnf/grammar.py`)**: 49 formal production rules modeled via `GrammarRule` and registered within `GrammarSpecification`.
- **Conformance Validator (`src/ebnf/validator.py`)**: `EBNFConformanceValidator` verifies AST node structure and calculates rule coverage metrics (`ConformanceReport`).
- **Canonical Test Corpus (`src/ebnf/corpus.py`)**: 25 targeted test samples (`CANONICAL_CORPUS`) achieving 100.0% rule coverage and 100.0% grammar conformance.

---

## 5. CLI Operations

```bash
# Run the canonical EBNF test corpus audit suite
python -m src.cli --ebnf-audit-suite

# Validate arbitrary batch code against formal EBNF grammar
python -m src.cli -c "echo hello & dir /b" --ebnf-validate

# Generate detailed Markdown conformance report for a script
python -m src.cli -i sample.bat --ebnf-report --ebnf-md report.md
```
