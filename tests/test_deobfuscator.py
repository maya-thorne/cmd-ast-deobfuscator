#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit test suite for cmd-ast-deobfuscator verifying 5-Phase cmd.exe parser normalization.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from deobfuscator_engine import BatchDeobfuscator


class TestBatchDeobfuscator(unittest.TestCase):
    def setUp(self):
        self.engine = BatchDeobfuscator()

    def test_caret_escaping_outside_quotes(self):
        obf = 'w^h^o^a^m^i /a^l^l'
        self.assertEqual(self.engine.deobfuscate(obf), 'whoami /all')

    def test_empty_quote_concatenation(self):
        obf = 'c""m""d.exe /c w""h""o""a""m""i'
        self.assertEqual(self.engine.deobfuscate(obf), 'cmd.exe /c whoami')

    def test_environment_variable_slicing(self):
        script = (
            'set "src=abcdefghijklmnopqrstuvwxyz /-_:"\n'
            '%src:~2,1%%src:~12,1%%src:~3,1%%src:~26,1%%src:~27,1%%src:~2,1%%src:~26,1%'
            '%src:~22,1%%src:~7,1%%src:~14,1%%src:~0,1%%src:~12,1%%src:~8,1%'
        )
        res = self.engine.deobfuscate(script).splitlines()
        self.assertEqual(res[-1], 'cmd /c whoami')

    def test_builtin_env_negative_slicing(self):
        obf = '%ComSpec:~-7,3%'
        self.assertEqual(self.engine.deobfuscate(obf).lower(), 'cmd')

    def test_string_substitution(self):
        script = 'set "payload=cXXXmXXXd /c dir"\n%payload:XXX=%'
        res = self.engine.deobfuscate(script).splitlines()
        self.assertEqual(res[-1], 'cmd /c dir')

    def test_bootstrap_set_chain(self):
        script = (
            'set a1=s\n'
            '%a1%et a2=e\n'
            '%a1%%a2%t a3=t\n'
            '%a1%%a2%%a3% target=whoami\n'
            '%target%'
        )
        res = self.engine.deobfuscate(script).splitlines()
        self.assertEqual(res[-1], 'whoami')


if __name__ == "__main__":
    unittest.main()
