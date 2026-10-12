"""
cmd-ast-deobfuscator: Compiler-Grade AST Parser & Pushdown Automaton Deobfuscation Engine for cmd.exe scripts.
"""

from .ast_nodes import (
    ASTNode, ASTVisitor, ScriptNode, CommandNode, PipeNode, ChainNode,
    BlockNode, AssignmentNode, VarExpandNode, LiteralNode, RedirectNode
)
from .lexer import CmdLexer, CmdToken, CmdTokenType
from .automaton import PushdownAutomaton, AutomatonState
from .parser import CmdASTParser
from .normalizer import ASTNormalizer
from .visualizer import ASTVisualizer
from .transforms import (
    TransformPass,
    PassManager,
    SlicingFolderPass,
    ConstantFolderPass,
    run_transforms
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
    'CmdLexer',
    'CmdToken',
    'CmdTokenType',
    'PushdownAutomaton',
    'AutomatonState',
    'CmdASTParser',
    'ASTNormalizer',
    'ASTVisualizer',
    'TransformPass',
    'PassManager',
    'SlicingFolderPass',
    'ConstantFolderPass',
    'run_transforms'
]
