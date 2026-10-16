"""
Multi-format exporters for AST-based Malware IOC extraction results.
Supports CSV, Markdown summary tables, JSON, and OASIS STIX 2.1 Threat Intelligence bundles.
"""

import csv
from datetime import datetime, timezone
import io
import json
from typing import Any, Dict, List, Set
import uuid

from .models import IOCExtractionResult, IOCItem, IOCType, MitreAttackMapping


# =========================================================================
# 1. CSV Serialization
# =========================================================================

def export_csv(result: IOCExtractionResult) -> str:
    """Serializes extracted IOCs into standard CSV format."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([
        "ioc_type",
        "value",
        "defanged_value",
        "line_number",
        "confidence",
        "severity",
        "mitre_id",
        "mitre_name",
        "mitre_tactic",
        "context",
    ])

    for item in result.iocs:
        mitre_id = item.mitre_attack.technique_id if item.mitre_attack else ""
        mitre_name = item.mitre_attack.technique_name if item.mitre_attack else ""
        mitre_tactic = (
            item.mitre_attack.tactic.value
            if item.mitre_attack and hasattr(item.mitre_attack.tactic, "value")
            else (item.mitre_attack.tactic if item.mitre_attack else "")
        )
        ctx = item.context.replace("\r", " ").replace("\n", " ").strip() if item.context else ""
        writer.writerow([
            item.ioc_type.value,
            item.value,
            item.defanged_value,
            item.line_number or "",
            f"{item.confidence:.2f}",
            item.severity.value,
            mitre_id,
            mitre_name,
            mitre_tactic,
            ctx,
        ])

    return output.getvalue()


# =========================================================================
# 2. Markdown Summary Report
# =========================================================================

def export_markdown(result: IOCExtractionResult) -> str:
    """Generates a comprehensive Markdown report of extracted IOCs and MITRE behaviors."""
    lines: List[str] = [
        "# Malware Indicators of Compromise (IOC) Report",
        "",
        "## Summary Metrics",
        "",
        f"- **Total IOCs Extracted**: {result.metrics.total_iocs_found}",
        f"- **Unique IOCs**: {result.metrics.unique_iocs}",
        f"- **IP Addresses**: {result.metrics.ips_found}",
        f"- **URLs / Endpoints**: {result.metrics.urls_found}",
        f"- **Domains / Hostnames**: {result.metrics.domains_found}",
        f"- **File & Payload Drops**: {result.metrics.files_dropped}",
        f"- **LOLBins Identified**: {result.metrics.lolbins_detected}",
        f"- **Hashes Identified**: {result.metrics.hashes_found}",
        f"- **MITRE ATT&CK Techniques**: {result.metrics.mitre_techniques_matched}",
        "",
    ]

    if result.source_file:
        lines.append(f"**Target Script**: `{result.source_file}`\n")

    # MITRE ATT&CK Technique Breakdown
    mitre_groups: Dict[str, List[IOCItem]] = {}
    for item in result.iocs:
        if item.mitre_attack:
            tid = item.mitre_attack.technique_id
            if tid not in mitre_groups:
                mitre_groups[tid] = []
            mitre_groups[tid].append(item)

    if mitre_groups:
        lines.extend([
            "## MITRE ATT&CK Mapping",
            "",
            "| Technique ID | Technique Name | Tactic | Associated Indicators |",
            "|---|---|---|---|",
        ])
        for tid, items in sorted(mitre_groups.items()):
            tech = items[0].mitre_attack
            tname = tech.technique_name if tech else "Unknown"
            tactic = (
                tech.tactic.value
                if tech and hasattr(tech.tactic, "value")
                else (tech.tactic if tech else "Unknown")
            )
            val_samples = ", ".join(f"`{i.defanged_value.replace('|', '\\|').replace('`', '\'')}`" for i in items[:3])
            if len(items) > 3:
                val_samples += f" (+{len(items)-3} more)"
            lines.append(f"| [{tid}]({tech.reference_url}) | {tname} | {tactic} | {val_samples} |")
        lines.append("")

    # Indicator Details Table
    lines.extend([
        "## Extracted Indicators",
        "",
        "| Type | Defanged Value | Severity | Confidence | MITRE ID | Context |",
        "|---|---|---|---|---|---|",
    ])

    if not result.iocs:
        lines.append("| - | *No indicators identified* | - | - | - | - |")
    else:
        for item in result.iocs:
            mid = item.mitre_attack.technique_id if item.mitre_attack else "-"
            raw_ctx = item.context.replace("\r", " ").replace("\n", " ")
            ctx = (raw_ctx[:60] + "...") if len(raw_ctx) > 60 else raw_ctx
            # Escape pipe characters for markdown table
            ctx = ctx.replace("|", "\\|")
            d_val = item.defanged_value.replace("|", "\\|").replace("`", "'")
            lines.append(
                f"| `{item.ioc_type.value}` | `{d_val}` | {item.severity.value} | "
                f"{item.confidence:.2f} | {mid} | `{ctx}` |"
            )

    lines.append("")
    return "\n".join(lines)


# =========================================================================
# 3. OASIS STIX 2.1 Threat Intelligence Bundle
# =========================================================================

def _stix_pattern_for_ioc(item: IOCItem) -> str:
    """Constructs compliant STIX 2.1 Pattern for given IOC item."""
    val = (
        item.value.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )
    t = item.ioc_type

    if t == IOCType.IPV4:
        ip_only = val.split(":", 1)[0]
        return f"[ipv4-addr:value = '{ip_only}']"
    elif t == IOCType.IPV6:
        ip_only = val.split("%", 1)[0]
        return f"[ipv6-addr:value = '{ip_only}']"
    elif t == IOCType.URL:
        return f"[url:value = '{val}']"
    elif t == IOCType.DOMAIN:
        return f"[domain-name:value = '{val}']"
    elif t == IOCType.FILE_DROP or t == IOCType.FILE_PATH:
        return f"[file:name = '{val}']"
    elif t == IOCType.HASH_MD5:
        return f"[file:hashes.MD5 = '{val}']"
    elif t == IOCType.HASH_SHA1:
        return f"[file:hashes.'SHA-1' = '{val}']"
    elif t == IOCType.HASH_SHA256:
        return f"[file:hashes.'SHA-256' = '{val}']"
    elif t == IOCType.LOLBIN:
        return f"[process:name = '{val}']"
    elif t == IOCType.COMMAND_LINE:
        return f"[process:command_line = '{val}']"
    elif t == IOCType.EMAIL:
        return f"[email-addr:value = '{val}']"
    elif t == IOCType.REGISTRY_KEY:
        return f"[windows-registry-key:key = '{val}']"
    return f"[x-cmd-ast:value = '{val}']"



def export_stix_bundle(result: IOCExtractionResult) -> Dict[str, Any]:
    """Generates an OASIS STIX 2.1 JSON Threat Intelligence Bundle."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    bundle_id = f"bundle--{uuid.uuid4()}"

    stix_objects: List[Dict[str, Any]] = []
    attack_pattern_ids: Dict[str, str] = {}
    created_indicators: Set[str] = set()
    created_relationships: Set[str] = set()

    # 1. Create Attack-Pattern objects for observed MITRE techniques
    for item in result.iocs:
        if item.mitre_attack:
            tid = item.mitre_attack.technique_id
            if tid not in attack_pattern_ids:
                ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, f'mitre:{tid}')}"
                attack_pattern_ids[tid] = ap_id
                tactic_val = (
                    item.mitre_attack.tactic.value
                    if hasattr(item.mitre_attack.tactic, "value")
                    else str(item.mitre_attack.tactic)
                )
                ap_obj = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": item.mitre_attack.technique_name,
                    "description": f"MITRE ATT&CK Technique {tid} under tactic {tactic_val}",
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": tactic_val.lower().replace(" ", "-"),
                        }
                    ],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tid,
                            "url": item.mitre_attack.reference_url,
                        }
                    ],
                }
                stix_objects.append(ap_obj)

    # 2. Create Indicator objects and Relationships
    for item in result.iocs:
        pattern = _stix_pattern_for_ioc(item)
        ind_key = f"{item.ioc_type.value}:{item.value}"
        ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, ind_key)}"

        if ind_id not in created_indicators:
            created_indicators.add(ind_id)
            ind_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_iso,
                "modified": now_iso,
                "name": item.value,
                "description": f"Extracted {item.ioc_type.value} indicator ({item.defanged_value})",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": now_iso,
                "confidence": int(round(item.confidence * 100)),
            }
            stix_objects.append(ind_obj)

        # 3. Create relationship to attack pattern if technique matched
        if item.mitre_attack:
            tid = item.mitre_attack.technique_id
            target_ap_id = attack_pattern_ids.get(tid)
            if target_ap_id:
                rel_id = f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{ind_id}->{target_ap_id}')}"
                if rel_id not in created_relationships:
                    created_relationships.add(rel_id)
                    rel_obj = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": rel_id,
                        "created": now_iso,
                        "modified": now_iso,
                        "relationship_type": "indicates",
                        "source_ref": ind_id,
                        "target_ref": target_ap_id,
                        "description": f"Indicator indicates {tid}",
                    }
                    stix_objects.append(rel_obj)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects,
    }
