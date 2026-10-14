"""
Unit and Integration Test Suite for Batch Packer Detection and Control Flow De-flattening (M14).
Tests 0xidiz3r signature detection, CertUtil payload extraction, CFF state machine analysis,
state linearizer unrolling, DeflatPass AST transformation, and memory zeroization.
"""

import unittest
import base64
import binascii

from src.parser import CmdASTParser
from src.normalizer import ASTNormalizer
from src.ast_nodes import (
    ScriptNode, CommandNode, LiteralNode, AssignmentNode,
    IfNode, BlockNode, GotoNode, LabelNode, ExitNode
)
from src.packers import (
    PackerType, PackerSignatureDetector, PackerUnpacker, PackerDetectionResult
)
from src.cff import (
    CFFPatternType, CFFAnalyzer, CFFLinearizer, CFFStateMachine, DeflatMetrics
)
from src.transforms.deflat_pass import DeflatPass
from src.transforms.base import PassManager


class TestBatchPackerAndDeflatSuite(unittest.TestCase):
    """Test suite for 0xidiz3r and batch packer detection, unpacking, and Anti-CFF de-flattening."""

    def setUp(self):
        self.detector = PackerSignatureDetector()
        self.unpacker = PackerUnpacker(detector=self.detector)
        self.analyzer = CFFAnalyzer()
        self.linearizer = CFFLinearizer()

    # -------------------------------------------------------------------------
    # 1. Packer Signature Detection Tests
    # -------------------------------------------------------------------------

    def test_packer_detector_0xidiz3r_signature(self):
        source = (
            ":: 0xidiz3r v2.0 - Batch Obfuscator\n"
            "set \"__0x1a=po\"\n"
            "set \"__0x2b=wer\"\n"
            "set \"__0x3c=shell\"\n"
            "set \"noise1=deadbeef1234\"\n"
            "set \"noise2=feedface5678\"\n"
            ":dispatch\n"
            "if \"%state%\"==\"1\" goto :b1\n"
            "if \"%state%\"==\"2\" goto :b2\n"
            "goto :dispatch\n"
        )
        res = self.detector.detect(source)
        self.assertTrue(res.is_packed)
        self.assertEqual(res.primary_packer, PackerType.OXIDIZ3R)
        self.assertGreaterEqual(res.confidence, 0.70)
        self.assertTrue(any("0xidiz3r" in ind.lower() for ind in res.detected_signatures[0].indicators))

    def test_packer_detector_certutil_base64_pem(self):
        source = (
            "@echo off\n"
            "certutil -decode %~f0 %temp%\\payload.bat & %temp%\\payload.bat\n"
            "exit /b\n"
            "-----BEGIN CERTIFICATE-----\n"
            "ZWNobyBIZWxsbw==\n"
            "-----END CERTIFICATE-----\n"
        )
        res = self.detector.detect(source)
        self.assertTrue(res.is_packed)
        self.assertEqual(res.primary_packer, PackerType.CERTUTIL_BASE64)
        self.assertGreaterEqual(res.confidence, 0.80)

    def test_packer_detector_certutil_hex(self):
        source = (
            "@echo off\n"
            "certutil -decodehex %temp%\\code.hex %temp%\\bin.exe\n"
            "call %temp%\\bin.exe\n"
        )
        res = self.detector.detect(source)
        self.assertTrue(res.is_packed)
        self.assertEqual(res.primary_packer, PackerType.CERTUTIL_HEX)

    def test_packer_detector_clean_script(self):
        source = (
            "@echo off\n"
            "echo Starting backup job...\n"
            "dir C:\\Users /b\n"
        )
        res = self.detector.detect(source)
        self.assertFalse(res.is_packed)
        self.assertEqual(res.primary_packer, PackerType.CLEAN_BATCH)
        self.assertEqual(res.confidence, 0.0)

    # -------------------------------------------------------------------------
    # 2. Packer Payload Extraction & Unpacking Tests
    # -------------------------------------------------------------------------

    def test_unpacker_certutil_base64_pem_payload(self):
        payload_code = "@echo off\nwhoami /all\nnet user\n"
        b64_data = base64.b64encode(payload_code.encode("utf-8")).decode("ascii")

        wrapped_script = (
            "@echo off\n"
            "certutil -decode %~f0 %temp%\\run.bat & call %temp%\\run.bat\n"
            "exit /b\n"
            "-----BEGIN CERTIFICATE-----\n"
            f"{b64_data}\n"
            "-----END CERTIFICATE-----\n"
        )
        res = self.unpacker.unpack(wrapped_script)
        self.assertIsNotNone(res.unpacked_source)
        self.assertIn("whoami /all", res.unpacked_source)
        self.assertIn("net user", res.unpacked_source)

    def test_unpacker_certutil_trailing_base64_payload(self):
        payload_code = "cmd.exe /c echo Recovered Payload"
        b64_data = base64.b64encode(payload_code.encode("utf-8")).decode("ascii")

        wrapped_script = (
            "@echo off\n"
            "certutil -decode %~f0 payload.bat\n"
            "goto :eof\n"
            f"{b64_data}\n"
        )
        res = self.unpacker.unpack(wrapped_script)
        self.assertIsNotNone(res.unpacked_source)
        self.assertIn("Recovered Payload", res.unpacked_source)

    def test_unpacker_0xidiz3r_clean_anti_debug_and_banners(self):
        source = (
            ":: 0xidiz3r v1.5 obfuscation\n"
            "rem packed by 0xidiz3r\n"
            "if \"%~nx0\" neq \"sample.bat\" exit /b\n"
            "echo Actual Core Payload\n"
        )
        res = self.unpacker.unpack(source)
        self.assertIsNotNone(res.unpacked_source)
        self.assertNotIn("0xidiz3r", res.unpacked_source)
        self.assertNotIn("%~nx0", res.unpacked_source)
        self.assertIn("echo Actual Core Payload", res.unpacked_source)
        self.assertGreaterEqual(res.metrics.noise_lines_stripped, 2)

    # -------------------------------------------------------------------------
    # 3. CFF State Machine Analyzer Tests
    # -------------------------------------------------------------------------

    def test_cff_analyzer_switch_dispatcher(self):
        code = (
            "set state=1\n"
            ":dispatch\n"
            "if \"%state%\"==\"1\" goto :b_one\n"
            "if \"%state%\"==\"2\" goto :b_two\n"
            "goto :dispatch\n"
            ":b_one\n"
            "echo Block 1 Action\n"
            "set state=2\n"
            "goto :dispatch\n"
            ":b_two\n"
            "echo Block 2 Action\n"
            "exit\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)

        self.assertIsNotNone(sm)
        self.assertEqual(sm.state_var, "state")
        self.assertEqual(sm.initial_state, "1")
        self.assertEqual(sm.dispatcher_label, "dispatch")
        self.assertEqual(sm.pattern_type, CFFPatternType.SWITCH_DISPATCHER)
        self.assertEqual(len(sm.blocks), 2)
        self.assertIn("1", sm.blocks)
        self.assertIn("2", sm.blocks)
        self.assertEqual(sm.blocks["1"].next_state, "2")
        self.assertTrue(sm.blocks["2"].is_terminal)

    def test_cff_analyzer_computed_goto(self):
        code = (
            "set s=entry\n"
            ":hub\n"
            "goto :step_%s%\n"
            ":step_entry\n"
            "echo Init System\n"
            "set s=finish\n"
            "goto :hub\n"
            ":step_finish\n"
            "echo Done\n"
            "goto :eof\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)

        self.assertIsNotNone(sm)
        self.assertEqual(sm.state_var, "s")
        self.assertEqual(sm.dispatcher_label, "hub")
        self.assertEqual(sm.pattern_type, CFFPatternType.COMPUTED_GOTO)
        self.assertIn("entry", sm.blocks)
        self.assertIn("finish", sm.blocks)

    # -------------------------------------------------------------------------
    # 4. CFF Linearizer & De-flattening Tests
    # -------------------------------------------------------------------------

    def test_cff_linearizer_linear_sequence(self):
        code = (
            "set state=start\n"
            ":dispatch\n"
            "if \"%state%\"==\"start\" goto :block_a\n"
            "if \"%state%\"==\"mid\" goto :block_b\n"
            "if \"%state%\"==\"end\" goto :block_c\n"
            "goto :dispatch\n"
            ":block_a\n"
            "echo Operation Alpha\n"
            "set state=mid\n"
            "goto :dispatch\n"
            ":block_b\n"
            "echo Operation Beta\n"
            "set state=end\n"
            "goto :dispatch\n"
            ":block_c\n"
            "echo Operation Gamma\n"
            "exit /b 0\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)

        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.states_unrolled, 3)
        self.assertEqual(res.metrics.blocks_linearized, 3)
        self.assertEqual(res.metrics.dead_jumps_pruned, 2)

        # Verify linearized output contains Alpha, Beta, Gamma in sequence
        norm = ASTNormalizer()
        script = norm.to_source(ScriptNode(statements=res.linearized_nodes))
        self.assertIn("Operation Alpha", script)
        self.assertIn("Operation Beta", script)
        self.assertIn("Operation Gamma", script)
        self.assertNotIn("goto :dispatch", script)
        self.assertNotIn("set state=", script)

    def test_cff_linearizer_conditional_branching(self):
        code = (
            "set state=chk\n"
            ":dispatch\n"
            "if \"%state%\"==\"chk\" goto :block_chk\n"
            "if \"%state%\"==\"then_act\" goto :block_then\n"
            "if \"%state%\"==\"else_act\" goto :block_else\n"
            "goto :dispatch\n"
            ":block_chk\n"
            "if \"%mode%\"==\"admin\" (set state=then_act) else (set state=else_act)\n"
            "goto :dispatch\n"
            ":block_then\n"
            "net localgroup administrators\n"
            "exit\n"
            ":block_else\n"
            "whoami\n"
            "exit\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)

        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.conditional_branches_recovered, 1)

        norm = ASTNormalizer()
        script = norm.to_source(ScriptNode(statements=res.linearized_nodes))
        self.assertIn('if "%mode%"=="admin"', script)
        self.assertIn("net localgroup administrators", script)
        self.assertIn("whoami", script)

    def test_cff_linearizer_loop_reconstruction(self):
        code = (
            "set state=0\n"
            ":dispatch\n"
            "if \"%state%\"==\"0\" goto :b_loop\n"
            "goto :dispatch\n"
            ":b_loop\n"
            "echo Running iteration\n"
            "set state=0\n"
            "goto :dispatch\n"
        )
        ast = CmdASTParser.from_source(code).parse()
        sm = self.analyzer.analyze(ast)
        self.assertIsNotNone(sm)

        res = self.linearizer.linearize(sm)
        self.assertTrue(res.success)
        self.assertEqual(res.metrics.loops_reconstructed, 1)

    # -------------------------------------------------------------------------
    # 5. DeflatPass AST Integration Tests
    # -------------------------------------------------------------------------

    def test_deflat_pass_full_pipeline(self):
        source = (
            "@echo off\n"
            "title TaskRunner\n"
            "set state=1\n"
            ":dispatch\n"
            "if \"%state%\"==\"1\" goto :step1\n"
            "if \"%state%\"==\"2\" goto :step2\n"
            "goto :dispatch\n"
            ":step1\n"
            "echo Step One\n"
            "set state=2\n"
            "goto :dispatch\n"
            ":step2\n"
            "echo Step Two\n"
            "exit\n"
            ":helper_routine\n"
            "echo Helper Function\n"
            "goto :eof\n"
        )
        ast = CmdASTParser.from_source(source).parse()
        pass_mgr = PassManager.default_pipeline()
        clean_ast = pass_mgr.run(ast)

        norm = ASTNormalizer()
        clean_code = norm.to_source(clean_ast)

        self.assertIn("title TaskRunner", clean_code)
        self.assertIn("echo Step One", clean_code)
        self.assertIn("echo Step Two", clean_code)
        self.assertIn(":helper_routine", clean_code)
        self.assertNotIn("goto :dispatch", clean_code)
        self.assertNotIn(":step1", clean_code)
        self.assertNotIn(":step2", clean_code)

    def test_deflat_pass_with_0xidiz3r_packed_wrapper(self):
        source = (
            ":: 0xidiz3r v2.1\n"
            "set \"__0x1=ca\"\n"
            "set \"__0x2=lc\"\n"
            "set state=entry\n"
            ":dispatch\n"
            "if \"%state%\"==\"entry\" goto :b_run\n"
            "goto :dispatch\n"
            ":b_run\n"
            "%__0x1%%__0x2%\n"
            "exit\n"
        )
        ast = CmdASTParser.from_source(source).parse()
        pass_mgr = PassManager.default_pipeline()
        clean_ast = pass_mgr.run(ast)

        norm = ASTNormalizer()
        clean_code = norm.to_source(clean_ast)

        self.assertIn("calc", clean_code)
        self.assertNotIn("0xidiz3r", clean_code)
        self.assertNotIn("goto :dispatch", clean_code)

    # -------------------------------------------------------------------------
    # 6. Memory Zeroization & Telemetry Tests
    # -------------------------------------------------------------------------

    def test_memory_zeroization_and_metrics(self):
        metrics = DeflatMetrics(
            dispatchers_detected=3,
            states_unrolled=12,
            blocks_linearized=10,
            dead_jumps_pruned=9,
            conditional_branches_recovered=2,
            loops_reconstructed=1
        )
        self.assertEqual(metrics.to_dict()["dispatchers_detected"], 3)
        metrics.zeroize()
        self.assertEqual(metrics.dispatchers_detected, 0)
        self.assertEqual(metrics.states_unrolled, 0)

        p_res = PackerDetectionResult(
            primary_packer=PackerType.CERTUTIL_BASE64,
            is_packed=True,
            confidence=0.95,
            unpacked_source="sensitive decrypted payload string"
        )
        p_res.zeroize()
        self.assertIsNone(p_res.unpacked_source)
        self.assertEqual(len(p_res.detected_signatures), 0)


if __name__ == "__main__":
    unittest.main()
