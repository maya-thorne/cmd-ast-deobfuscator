"""
cmd-ast-deobfuscator: cmd.exe Formal EBNF Grammar Models, Validator, and Canonical Test Corpus.
"""

from .models import (
    GrammarRuleType,
    GrammarRule,
    GrammarSpecification,
    ValidationStatus,
    RuleValidationResult,
    SyntaxViolation,
    ConformanceReport,
)
from .grammar import (
    CMD_EBNF_SPEC,
    build_cmd_ebnf_rules,
    get_default_grammar,
    export_ebnf_specification,
)
from .corpus import (
    CorpusSample,
    CANONICAL_CORPUS,
    get_canonical_corpus,
    get_corpus_by_category,
    get_corpus_by_rule,
)
from .validator import (
    EBNFConformanceValidator,
    validate_source,
    audit_ebnf_suite,
    handle_ebnf_cli,
)

__all__ = [
    "GrammarRuleType",
    "GrammarRule",
    "GrammarSpecification",
    "ValidationStatus",
    "RuleValidationResult",
    "SyntaxViolation",
    "ConformanceReport",
    "CMD_EBNF_SPEC",
    "build_cmd_ebnf_rules",
    "get_default_grammar",
    "export_ebnf_specification",
    "CorpusSample",
    "CANONICAL_CORPUS",
    "get_canonical_corpus",
    "get_corpus_by_category",
    "get_corpus_by_rule",
    "EBNFConformanceValidator",
    "validate_source",
    "audit_ebnf_suite",
    "handle_ebnf_cli",
]
