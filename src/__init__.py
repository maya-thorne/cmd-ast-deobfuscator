"""
cmd-ast-deobfuscator: Compiler-Grade AST Parser & Pushdown Automaton Deobfuscation Engine for cmd.exe scripts.
"""

from .ast_nodes import (
    ASTNode, ASTVisitor, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode,
    CommentNode, ParamExpandNode, ForNode, IfNode, LabelNode, GotoNode,
    CallNode, ExitNode
)
from .lexer import CmdLexer, CmdToken, CmdTokenType
from .automaton import PushdownAutomaton, AutomatonState
from .parser import CmdASTParser
from .normalizer import ASTNormalizer
from .visualizer import ASTVisualizer
from .modifiers import ModifierSpec, parse_modifiers, PathModifierResolver
from .transforms import (
    TransformPass,
    PassManager,
    SlicingFolderPass,
    ConstantFolderPass,
    CaretNormalizerPass,
    ParamResolverPass,
    normalize_carets,
    run_transforms
)
from .benchmark import (
    BenchmarkRunner,
    BenchmarkSummary,
    BenchmarkSample,
    get_benchmark_corpus,
)
from .cfg import (
    ControlFlowGraph,
    CFGNode,
    CFGEdge,
    CFGEdgeType,
    CFGMetrics,
    CFGBuilder,
    JumpTableResolver,
    JumpTableResolutionResult,
    CFGVisualizer,
)

__all__ = [
    'ASTNode',
    'ASTVisitor',
    'ScriptNode',
    'CommandNode',
    'PipeNode',
    'ChainNode',
    'BlockNode',
    'AssignmentNode',
    'VarExpandNode',
    'LiteralNode',
    'RedirectNode',
    'CommentNode',
    'ParamExpandNode',
    'ForNode',
    'IfNode',
    'LabelNode',
    'GotoNode',
    'CallNode',
    'ExitNode',
    'CmdLexer',
    'CmdToken',
    'CmdTokenType',
    'PushdownAutomaton',
    'AutomatonState',
    'CmdASTParser',
    'ASTNormalizer',
    'ASTVisualizer',
    'ModifierSpec',
    'parse_modifiers',
    'PathModifierResolver',
    'TransformPass',
    'PassManager',
    'SlicingFolderPass',
    'ConstantFolderPass',
    'CaretNormalizerPass',
    'ParamResolverPass',
    'normalize_carets',
    'run_transforms',
    'BenchmarkRunner',
    'BenchmarkSummary',
    'BenchmarkSample',
    'get_benchmark_corpus',
    'ControlFlowGraph',
    'CFGNode',
    'CFGEdge',
    'CFGEdgeType',
    'CFGMetrics',
    'CFGBuilder',
    'JumpTableResolver',
    'JumpTableResolutionResult',
    'CFGVisualizer',
]

