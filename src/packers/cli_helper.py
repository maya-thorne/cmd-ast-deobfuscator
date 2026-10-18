"""
CLI formatting and presentation helper for batch packer detection and multi-stage unpacking.
Formats detection results and layered unpack transitions in text, JSON, and Markdown formats.
"""

import json
import os
import sys
from typing import Optional, Any
from .models import PackerDetectionResult, LayeredUnpackResult
from .detector import PackerSignatureDetector
from .engine import MultiStagePackerEngine


def format_detection_markdown(result: PackerDetectionResult) -> str:
    """Formats PackerDetectionResult as a structured Markdown document."""
    lines = [
        "# Batch Packer & Obfuscator Detection Report",
        "",
        "## Summary",
        "",
        f"- **Primary Packer**: `{result.primary_packer.value}`",
        f"- **Is Packed**: `{result.is_packed}`",
        f"- **Confidence Score**: `{result.confidence:.2f}`",
        f"- **Signatures Identified**: `{len(result.detected_signatures)}`",
        "",
        "## Detected Signatures",
        "",
        "| Packer Type | Name | Confidence | Indicators |",
        "|---|---|---:|---|",
    ]
    for sig in result.detected_signatures:
        ind_str = "<br>".join(sig.indicators) if sig.indicators else "-"
        lines.append(f"| `{sig.packer_type.value}` | {sig.name} | {sig.confidence:.2f} | {ind_str} |")
    lines.append("")
    return "\n".join(lines)


def format_layers_markdown(result: LayeredUnpackResult) -> str:
    """Formats LayeredUnpackResult as a Markdown report with transition provenance tables."""
    lines = [
        "# Multi-Stage Batch Packer Layer Transitions Report",
        "",
        "## Overview",
        "",
        f"- **Primary Packer**: `{result.primary_packer.value}`",
        f"- **Layers Unpacked**: `{result.layers_unpacked}`",
        f"- **Overall Confidence**: `{result.overall_confidence:.2f}`",
        f"- **Cycle Detected**: `{result.cycle_detected}`",
        f"- **Depth Limit Reached**: `{result.depth_limit_reached}`",
        f"- **Total Entropy Reduction**: `{result.metrics.entropy_reduction:.4f}` bits/byte",
        f"- **Total Payload Recovered**: `{result.metrics.payload_bytes_recovered}` bytes",
        "",
        "## Layer Transitions Provenance",
        "",
        "| Depth | Strategy | From Packer | To Packer | In Entropy | Out Entropy | Delta | Payload SHA-256 |",
        "|---:|---|---|---|---:|---:|---:|---|",
    ]
    for t in result.transitions:
        sha_short = t.payload_sha256[:16] + "..." if len(t.payload_sha256) > 16 else t.payload_sha256
        lines.append(
            f"| {t.depth} | `{t.unpacker_strategy}` | `{t.from_packer.value}` | `{t.to_packer.value}` | "
            f"{t.input_entropy:.4f} | {t.output_entropy:.4f} | {t.entropy_delta:+.4f} | `{sha_short}` |"
        )
    lines.append("")
    return "\n".join(lines)


def handle_packers_cli(source: str, args: Any) -> bool:
    """
    Executes CLI actions for packer detection, unpacking, and layer transition reporting.
    Returns True if a packer CLI command was executed.
    """
    is_detect = getattr(args, "packers_detect", False) or getattr(args, "packer_detect", False)
    is_unpack = getattr(args, "packers_unpack", False)
    is_layers = getattr(args, "packers_layers", False)

    if not (is_detect or is_unpack or is_layers):
        return False

    use_json = getattr(args, "json", False)
    use_md = getattr(args, "md", False) or getattr(args, "packers_md", False)

    detector = PackerSignatureDetector()
    engine = MultiStagePackerEngine(detector=detector)

    if is_unpack or is_layers:
        layered_res = engine.unpack(source)

        if use_json:
            print(json.dumps(layered_res.to_dict(), indent=2))
        elif use_md:
            print(format_layers_markdown(layered_res))
            if is_unpack and layered_res.final_source:
                print("## Unpacked Script Payload\n\n```cmd\n" + layered_res.final_source + "\n```")
        else:
            print("\n=== [MULTI-STAGE PACKER UNPACKING REPORT] ===")
            print(f"  Primary packer     : {layered_res.primary_packer.value}")
            print(f"  Layers unpacked    : {layered_res.layers_unpacked}")
            print(f"  Overall confidence : {layered_res.overall_confidence:.2f}")
            print(f"  Entropy reduction  : {layered_res.metrics.entropy_reduction:.4f} bits/byte")
            print(f"  Cycles halted      : {layered_res.metrics.cycles_halted}")
            print(f"  Payload recovered  : {layered_res.metrics.payload_bytes_recovered} bytes")

            if layered_res.transitions:
                print("\n  --- Layer Transitions Provenance ---")
                for t in layered_res.transitions:
                    print(f"  [Layer {t.depth}] {t.unpacker_strategy}")
                    print(f"      Transition: {t.from_packer.value} -> {t.to_packer.value}")
                    print(f"      Entropy   : {t.input_entropy:.4f} -> {t.output_entropy:.4f} (delta: {t.entropy_delta:+.4f})")
                    print(f"      Size (B)  : {t.input_bytes} -> {t.output_bytes}")
                    print(f"      SHA-256   : {t.payload_sha256}")
                    for ind in t.indicators:
                        print(f"      * {ind}")

            if is_unpack:
                if getattr(args, "output", None):
                    with open(args.output, "w", encoding="utf-8") as f:
                        f.write(layered_res.final_source + "\n")
                    print(f"\n[✓] Unpacked script payload written to {args.output}")
                else:
                    print("\n=== [UNPACKED PAYLOAD] ===")
                    print(layered_res.final_source)
        return True

    # Otherwise detect-only
    det_res = detector.detect(source)
    if use_json:
        print(json.dumps(det_res.to_dict(), indent=2))
    elif use_md:
        print(format_detection_markdown(det_res))
    else:
        print("\n=== [BATCH PACKER & OBFUSCATOR DETECTION] ===")
        print(f"  Primary packer : {det_res.primary_packer.value}")
        print(f"  Is packed      : {det_res.is_packed}")
        print(f"  Confidence     : {det_res.confidence:.2f}")
        for sig in det_res.detected_signatures:
            print(f"  - [{sig.packer_type.value}] {sig.name} (conf: {sig.confidence:.2f})")
            for ind in sig.indicators:
                print(f"      * {ind}")
    return True
