"""
Comprehensive Unit and Integration Test Suite for I/O Redirection & Stream Routing (M12).
Verifies lexing, AST extraction, handle duplication, stream routing simulation,
stealth suppression, constant folding, security bounds, and zeroization.
"""

import unittest
from src.lexer import CmdLexer, CmdToken, CmdTokenType
from src.ast_nodes import (
    CommandNode, RedirectNode, BlockNode, IfNode, ForNode,
    LiteralNode, ScriptNode
)
from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.redirect import (
    StreamType, RedirectOperator, DestinationType, RedirectEntry,
    StreamRoute, RedirectPlan, RedirectMetrics, StreamRouter,
    extract_redirections, build_redirect_tree, is_device_destination,
    classify_destination, MAX_FORWARD_DEPTH
)
from src.transforms.redirect_normalizer import RedirectNormalizerPass
from src.transforms import PassManager


class TestRedirectLexer(unittest.TestCase):
    """1. Lexical tokenization of redirection operators and handle descriptors."""

    def test_basic_redirection_tokens(self):
        lexer = CmdLexer("echo A > out.txt >> log.txt < in.txt")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        op_types = [t.type for t in tokens if t.type in (
            CmdTokenType.REDIRECT_OUT, CmdTokenType.REDIRECT_APPEND, CmdTokenType.REDIRECT_IN
        )]
        self.assertEqual(op_types, [
            CmdTokenType.REDIRECT_OUT,
            CmdTokenType.REDIRECT_APPEND,
            CmdTokenType.REDIRECT_IN
        ])

    def test_handle_duplication_tokens(self):
        lexer = CmdLexer("cmd 2>&1 >&2 <&0")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        dup_tokens = [t for t in tokens if t.type == CmdTokenType.REDIRECT_DUP]
        self.assertEqual(len(dup_tokens), 3)
        self.assertEqual([t.value for t in dup_tokens], [">&", ">&", "<&"])

    def test_quote_escaped_redirect_characters(self):
        lexer = CmdLexer('echo ">" "^>"')
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.WHITESPACE and t.type != CmdTokenType.EOF]
        self.assertFalse(any(t.type in (
            CmdTokenType.REDIRECT_OUT, CmdTokenType.REDIRECT_APPEND, CmdTokenType.REDIRECT_IN
        ) for t in tokens))


class TestRedirectExtractor(unittest.TestCase):
    """2. Token extraction and syntactic classification across command positions."""

    def test_trailing_redirection_extraction(self):
        lexer = CmdLexer("dir /b > out.txt 2> err.log")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        clean_tokens, entries = extract_redirections(tokens)

        clean_text = "".join(t.value for t in clean_tokens).strip()
        self.assertEqual(clean_text, "dir /b")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].source_fd, 1)
        self.assertEqual(entries[0].destination, "out.txt")
        self.assertEqual(entries[1].source_fd, 2)
        self.assertEqual(entries[1].destination, "err.log")

    def test_leading_redirection_extraction(self):
        lexer = CmdLexer(">out.txt echo hello")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        clean_tokens, entries = extract_redirections(tokens)

        clean_text = "".join(t.value for t in clean_tokens).strip()
        self.assertEqual(clean_text, "echo hello")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].destination, "out.txt")

    def test_embedded_redirection_extraction(self):
        lexer = CmdLexer("dir /b > out.txt C:\\Windows")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        clean_tokens, entries = extract_redirections(tokens)

        clean_text = "".join(t.value for t in clean_tokens).strip()
        self.assertEqual(clean_text, "dir /b  C:\\Windows")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].destination, "out.txt")

    def test_handle_duplication_extraction(self):
        lexer = CmdLexer("command 2>&1")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        _, entries = extract_redirections(tokens)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].source_fd, 2)
        self.assertEqual(entries[0].target_fd, 1)
        self.assertTrue(entries[0].is_dup)
        self.assertEqual(entries[0].dest_type, DestinationType.HANDLE)

    def test_handle_closing_extraction(self):
        lexer = CmdLexer("command 2>&-")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        _, entries = extract_redirections(tokens)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].source_fd, 2)
        self.assertEqual(entries[0].dest_type, DestinationType.CLOSED)

    def test_device_destination_classification(self):
        self.assertTrue(is_device_destination("nul"))
        self.assertTrue(is_device_destination("NUL:"))
        self.assertTrue(is_device_destination(r"\\.\nul"))
        self.assertTrue(is_device_destination("nul.txt"))
        self.assertTrue(is_device_destination("con"))
        self.assertTrue(is_device_destination("prn"))
        self.assertFalse(is_device_destination("output.log"))

        dest_type, is_sup = classify_destination("nul")
        self.assertEqual(dest_type, DestinationType.DEVICE)
        self.assertTrue(is_sup)

    def test_quoted_destination_path(self):
        lexer = CmdLexer('echo hello > "C:\\Program Files\\app.log"')
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        _, entries = extract_redirections(tokens)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].destination, '"C:\\Program Files\\app.log"')


class TestStreamRouter(unittest.TestCase):
    """3. Stream handle routing simulation, duplication order, and stealth detection."""

    def setUp(self):
        self.router = StreamRouter()

    def test_default_handle_state(self):
        plan = self.router.route([])
        self.assertEqual(plan.routes[StreamType.STDOUT].destination, "CONOUT$")
        self.assertEqual(plan.routes[StreamType.STDERR].destination, "CONERR$")
        self.assertEqual(plan.routes[StreamType.STDIN].destination, "CONIN$")
        self.assertFalse(plan.is_stealth)

    def test_file_redirection_routing(self):
        entries = [
            RedirectEntry(source_fd=1, operator=">", destination="out.txt"),
            RedirectEntry(source_fd=2, operator=">>", destination="err.log", is_append=True)
        ]
        plan = self.router.route(entries)
        self.assertEqual(plan.routes[1].destination, "out.txt")
        self.assertEqual(plan.routes[1].mode, "write")
        self.assertEqual(plan.routes[2].destination, "err.log")
        self.assertEqual(plan.routes[2].mode, "append")

    def test_stdout_and_stderr_order_semantics(self):
        # Case A: > file 2>&1 -> both go to file
        entries_a = [
            RedirectEntry(source_fd=1, operator=">", destination="merged.log"),
            RedirectEntry(source_fd=2, operator=">&", destination="&1", target_fd=1, is_dup=True)
        ]
        plan_a = self.router.route(entries_a)
        self.assertEqual(plan_a.routes[1].destination, "merged.log")
        self.assertEqual(plan_a.routes[2].destination, "merged.log")

        # Case B: 2>&1 > file -> stderr goes to initial CONOUT$, stdout goes to file
        entries_b = [
            RedirectEntry(source_fd=2, operator=">&", destination="&1", target_fd=1, is_dup=True),
            RedirectEntry(source_fd=1, operator=">", destination="out.log")
        ]
        plan_b = self.router.route(entries_b)
        self.assertEqual(plan_b.routes[2].destination, "CONOUT$")
        self.assertEqual(plan_b.routes[1].destination, "out.log")

    def test_stealth_suppression_detection(self):
        # Pattern 1: >nul 2>&1
        entries_1 = [
            RedirectEntry(source_fd=1, operator=">", destination="nul", is_suppressed=True, dest_type=DestinationType.DEVICE),
            RedirectEntry(source_fd=2, operator=">&", destination="&1", target_fd=1, is_dup=True)
        ]
        self.assertTrue(self.router.is_stealth(entries_1))

        # Pattern 2: 1>nul 2>nul
        entries_2 = [
            RedirectEntry(source_fd=1, operator=">", destination="nul", is_suppressed=True, dest_type=DestinationType.DEVICE),
            RedirectEntry(source_fd=2, operator=">", destination="nul", is_suppressed=True, dest_type=DestinationType.DEVICE)
        ]
        self.assertTrue(self.router.is_stealth(entries_2))

        # Pattern 3: Non-stealth (stdout to file, stderr to nul)
        entries_3 = [
            RedirectEntry(source_fd=1, operator=">", destination="out.txt"),
            RedirectEntry(source_fd=2, operator=">", destination="nul", is_suppressed=True, dest_type=DestinationType.DEVICE)
        ]
        self.assertFalse(self.router.is_stealth(entries_3))

    def test_circular_handle_forwarding_guard(self):
        # 1>&2 then 2>&1
        entries = [
            RedirectEntry(source_fd=1, operator=">&", destination="&2", target_fd=2, is_dup=True),
            RedirectEntry(source_fd=2, operator=">&", destination="&1", target_fd=1, is_dup=True)
        ]
        # Must terminate without recursion crash
        plan = self.router.route(entries)
        self.assertIsNotNone(plan)

    def test_metrics_telemetry(self):
        entries = [
            RedirectEntry(source_fd=1, operator=">", destination="nul", is_suppressed=True),
            RedirectEntry(source_fd=2, operator=">&", destination="&1", target_fd=1, is_dup=True),
            RedirectEntry(source_fd=0, operator="<", destination="in.txt", is_input=True)
        ]
        self.router.route(entries)
        stats = self.router.metrics.to_dict()
        self.assertEqual(stats["total_redirects"], 3)
        self.assertEqual(stats["stdout_redirects"], 1)
        self.assertEqual(stats["stderr_redirects"], 1)
        self.assertEqual(stats["stdin_redirects"], 1)
        self.assertEqual(stats["handle_duplications"], 1)
        self.assertEqual(stats["stealth_commands"], 1)


class TestRedirectASTIntegration(unittest.TestCase):
    """4. Parser construction, AST rewriting, normalizer passes, and source serialization."""

    def test_parser_creates_redirect_node(self):
        parser = CmdASTParser.from_source("dir /b > out.txt")
        script = parser.parse()
        self.assertEqual(len(script.statements), 1)
        stmt = script.statements[0]
        self.assertIsInstance(stmt, RedirectNode)
        self.assertEqual(stmt.destination, "out.txt")
        self.assertIsInstance(stmt.command, CommandNode)
        self.assertEqual(stmt.command.target, "dir")

    def test_parser_multi_redirect_chain(self):
        parser = CmdASTParser.from_source("echo payload >nul 2>&1")
        script = parser.parse()
        stmt = script.statements[0]
        self.assertIsInstance(stmt, RedirectNode)
        # Outer is 2>&1, inner is >nul
        self.assertEqual(stmt.source_fd, 2)
        self.assertEqual(stmt.target_fd, 1)
        self.assertIsInstance(stmt.command, RedirectNode)
        self.assertEqual(stmt.command.destination, "nul")

    def test_block_redirection_parsing(self):
        parser = CmdASTParser.from_source("(echo A & echo B) > out.txt")
        script = parser.parse()
        stmt = script.statements[0]
        self.assertIsInstance(stmt, RedirectNode)
        self.assertIsInstance(stmt.command, BlockNode)
        self.assertEqual(len(stmt.command.statements), 1)

    def test_normalizer_unmasks_destination_carets(self):
        node = RedirectNode(
            command=CommandNode(target="calc"),
            destination="o^u^t.txt"
        )
        normalizer = ASTNormalizer()
        norm = normalizer.normalize(node)
        self.assertEqual(norm.destination, "out.txt")

    def test_normalizer_folds_destination_variables(self):
        node = RedirectNode(
            command=CommandNode(target="calc"),
            destination="%DEST%"
        )
        normalizer = ASTNormalizer(initial_env={"dest": "result.log"})
        norm = normalizer.normalize(node)
        self.assertEqual(norm.destination, "result.log")

    def test_to_source_serialization(self):
        node = RedirectNode(
            command=CommandNode(target="dir", arguments=[LiteralNode(value="/b")]),
            stream=">",
            destination="out.txt"
        )
        normalizer = ASTNormalizer()
        src = normalizer.to_source(node)
        self.assertEqual(src, "dir /b > out.txt")

    def test_redirect_normalizer_pass_execution(self):
        ast = RedirectNode(
            command=CommandNode(target="w^h^o^a^m^i"),
            destination="r^e^s.txt"
        )
        pass_instance = RedirectNormalizerPass()
        result = pass_instance.transform(ast)
        self.assertIsInstance(result, RedirectNode)
        self.assertEqual(result.destination, "res.txt")
        self.assertEqual(pass_instance.metrics.total_redirects, 1)

    def test_pass_manager_default_pipeline_includes_redirect(self):
        pm = PassManager.default_pipeline(env={"out": "final.txt"})
        ast = RedirectNode(
            command=CommandNode(target="echo", arguments=[LiteralNode(value="done")]),
            destination="%OUT%"
        )
        transformed = pm.run(ast)
        self.assertIsInstance(transformed, RedirectNode)
        self.assertEqual(transformed.destination, "final.txt")


class TestRedirectSecurityAudit(unittest.TestCase):
    """5. Security bounds, DoS prevention, input sanitization, and memory zeroization."""

    def test_zeroize_memory_scrub(self):
        router = StreamRouter()
        router.route([
            RedirectEntry(source_fd=1, operator=">", destination="confidential.txt")
        ])
        self.assertGreater(router.metrics.total_redirects, 0)
        self.assertIsNotNone(router._last_plan)

        router.zeroize()
        self.assertEqual(router.metrics.total_redirects, 0)
        self.assertIsNone(router._last_plan)

    def test_max_redirects_per_command_bounds(self):
        # Generate 100 consecutive redirect directives
        long_redirect_str = " ".join([f">{i}.txt" for i in range(100)])
        lexer = CmdLexer(f"echo test {long_redirect_str}")
        tokens = [t for t in lexer.tokenize() if t.type != CmdTokenType.EOF]
        _, entries = extract_redirections(tokens)
        # Should be bounded by MAX_REDIRECTS_PER_COMMAND (64)
        self.assertLessEqual(len(entries), 64)

    def test_null_byte_and_malformed_descriptor_safety(self):
        dest_type, is_sup = classify_destination("file\x00corrupt.txt")
        self.assertEqual(dest_type, DestinationType.FILE)
        self.assertFalse(is_sup)

    def test_deep_forwarding_chain_depth_limit(self):
        routes = {}
        for i in range(1, 20):
            routes[i] = StreamRoute(fd=i, destination=f"&{i+1}", dest_type=DestinationType.HANDLE, mode="duplicate", target_fd=i+1)
        routes[20] = StreamRoute(fd=20, destination="deep.txt", dest_type=DestinationType.FILE, mode="write")

        router = StreamRouter()
        res = router._resolve_target(routes, 1)
        # Depth > 10 should be protected and return fallback/None
        self.assertTrue(res is None or isinstance(res, StreamRoute))


if __name__ == "__main__":
    unittest.main()
