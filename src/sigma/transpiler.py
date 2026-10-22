"""
Enterprise SIEM Query Transpiler for Sigma Rule Conversion.
"""

import json
from typing import Any, Dict, List, Optional

from src.sigma.models import SIEMTarget, SigmaRule


class SIEMTranspiler:
    """Transpiles Sigma rules into target enterprise SIEM query languages."""

    def transpile(self, rule: SigmaRule, target: SIEMTarget = SIEMTarget.YAML) -> str:
        """Translates a SigmaRule into the specified query dialect."""
        if target == SIEMTarget.YAML:
            return rule.to_yaml()
        elif target == SIEMTarget.SPLUNK:
            return self.to_splunk_spl(rule)
        elif target == SIEMTarget.ELASTIC:
            return self.to_elastic_eql(rule)
        elif target == SIEMTarget.SENTINEL:
            return self.to_sentinel_kql(rule)
        elif target == SIEMTarget.QRADAR:
            return self.to_qradar_aql(rule)
        elif target == SIEMTarget.JSON:
            return json.dumps(rule.to_dict(), indent=2)
        else:
            return rule.to_yaml()

    def to_splunk_spl(self, rule: SigmaRule) -> str:
        """Generates Splunk Search Processing Language (SPL) query."""
        clauses: List[str] = []
        detection = rule.detection

        for sel_name, sel_val in detection.items():
            if sel_name == "condition":
                continue
            if isinstance(sel_val, dict):
                for field_key, field_vals in sel_val.items():
                    clean_field = field_key.split("|")[0]
                    if isinstance(field_vals, list):
                        disjunctions = [f'{clean_field}="*{self._escape_spl(str(v))}*"' for v in field_vals]
                        clauses.append("(" + " OR ".join(disjunctions) + ")")
                    else:
                        clauses.append(f'{clean_field}="*{self._escape_spl(str(field_vals))}*"')

        condition = detection.get("condition", "")
        if "1 of selection_*" in condition or " or " in condition.lower():
            combined = " OR ".join(clauses) if clauses else "CommandLine=*"
        else:
            combined = " AND ".join(clauses) if clauses else "CommandLine=*"

        comment = f"# Title: {rule.title} (ID: {rule.rule_id})\n"
        return f"{comment}index=* sourcetype=WinEventLog:Security EventCode=4688 {combined}"

    def to_elastic_eql(self, rule: SigmaRule) -> str:
        """Generates Elasticsearch Event Query Language (EQL) query."""
        clauses: List[str] = []
        detection = rule.detection

        for sel_name, sel_val in detection.items():
            if sel_name == "condition":
                continue
            if isinstance(sel_val, dict):
                for field_key, field_vals in sel_val.items():
                    # Map CommandLine -> process.command_line
                    field_name = "process.command_line" if "commandline" in field_key.lower() else field_key.split("|")[0]
                    if isinstance(field_vals, list):
                        terms = [f'"{self._escape_eql(str(v))}"' for v in field_vals]
                        clauses.append(f"{field_name} in ({', '.join(terms)})")
                    else:
                        clauses.append(f'{field_name} == "*{self._escape_eql(str(field_vals))}*"')

        condition = detection.get("condition", "")
        joiner = " or " if ("1 of selection_*" in condition or " or " in condition.lower()) else " and "
        body = joiner.join(clauses) if clauses else "process.command_line == *"

        comment = f"// Title: {rule.title}\n"
        return f"{comment}process where {body}"

    def to_sentinel_kql(self, rule: SigmaRule) -> str:
        """Generates Microsoft Sentinel / Azure Kusto Query Language (KQL) query."""
        clauses: List[str] = []
        detection = rule.detection

        for sel_name, sel_val in detection.items():
            if sel_name == "condition":
                continue
            if isinstance(sel_val, dict):
                for field_key, field_vals in sel_val.items():
                    if isinstance(field_vals, list):
                        escaped_vals = [f'"{self._escape_kql(str(v))}"' for v in field_vals]
                        clauses.append(f"ProcessCommandLine has_any ({', '.join(escaped_vals)})")
                    else:
                        clauses.append(f'ProcessCommandLine contains "{self._escape_kql(str(field_vals))}"')

        condition = detection.get("condition", "")
        joiner = " or " if ("1 of selection_*" in condition or " or " in condition.lower()) else " and "
        body = joiner.join(clauses) if clauses else "true"

        lines = [
            f"// Title: {rule.title} (Level: {rule.level})",
            "DeviceProcessEvents",
            f"| where {body}",
            "| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine",
        ]
        return "\n".join(lines)

    def to_qradar_aql(self, rule: SigmaRule) -> str:
        """Generates IBM QRadar Ariel Query Language (AQL) query."""
        clauses: List[str] = []
        detection = rule.detection

        for sel_name, sel_val in detection.items():
            if sel_name == "condition":
                continue
            if isinstance(sel_val, dict):
                for field_key, field_vals in sel_val.items():
                    if isinstance(field_vals, list):
                        disjunctions = [f'"Process CommandLine" ILIKE \'%{self._escape_aql(str(v))}%\'' for v in field_vals]
                        clauses.append("(" + " OR ".join(disjunctions) + ")")
                    else:
                        clauses.append(f'"Process CommandLine" ILIKE \'%{self._escape_aql(str(field_vals))}%\'')

        condition = detection.get("condition", "")
        joiner = " OR " if ("1 of selection_*" in condition or " or " in condition.lower()) else " AND "
        body = joiner.join(clauses) if clauses else "1=1"

        return (
            f"-- Title: {rule.title}\n"
            f"SELECT UTF8(payload) AS RawPayload, \"Process CommandLine\", UserName, HostName "
            f"FROM events WHERE {body} START '{rule.date}'"
        )

    @staticmethod
    def _escape_spl(val: str) -> str:
        return val.replace('"', '\\"').replace("\n", " ")

    @staticmethod
    def _escape_eql(val: str) -> str:
        return val.replace('"', '\\"').replace("\n", " ")

    @staticmethod
    def _escape_kql(val: str) -> str:
        return val.replace('"', '""').replace("\n", " ")

    @staticmethod
    def _escape_aql(val: str) -> str:
        return val.replace("'", "''").replace("\n", " ")
