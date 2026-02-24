"""
labels.py — Ground truth, taint, sanitizer label生成 + マーカー解決

テンプレート内の SOURCE/SINK/SANITIZER マーカーを行番号に解決し、
ground_truth_labels.csv, taint/sanitizer flow labels, manifest.json を生成する。
"""

import csv
import json
import re
from dataclasses import dataclass, field, asdict
from io import StringIO
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class VulnInstance:
    """A single vulnerability instance defined by SOURCE-SINK-SANITIZER tuple."""
    instance_id: str        # e.g., "v001-i01"
    category: str           # "unencrypted_output" / "weak_input_validation" / "shared_memory_overwrite"
    category_jp: str        # 日本語カテゴリ名
    function_name: str      # function containing the SINK
    source_line: int = 0    # resolved line number of SOURCE marker
    sink_line: int = 0      # resolved line number of SINK marker (= ground truth代表行)
    sanitizer_line: Optional[int] = None  # resolved line of SANITIZER (None if absent)


@dataclass
class TaintCheckpoint:
    """A single checkpoint in the taint propagation path."""
    checkpoint_id: str      # e.g., "EP", "SOURCE:v001-i01", "SINK:v001-i01"
    function: str
    line: int               # resolved line number (0 = to be resolved)
    var: str
    role: str               # "source" / "propagated" / "sink_arg" / "secret_source" / "result"
    origin: str             # "REE" / "TA"
    note: str


@dataclass
class SanitizerEntry:
    """A sanitizer/validation point."""
    flow: str               # category prefix: "UDO" / "IVW" / "DUS"
    function: str
    line: int               # resolved line number (0 = to be resolved)
    expression: str         # e.g., 'enc(enc_out);'
    kind: str               # "param_type_check" / "encryption_sanitizer" / "content_check" / "upper_bound_check" / "lower_bound_check"
    protects_vars: str      # e.g., "enc_out"
    note: str


# ---------------------------------------------------------------------------
# Category mappings
# ---------------------------------------------------------------------------

CATEGORY_MAP = {
    "UDO": ("unencrypted_output", "未暗号化出力"),
    "IVW": ("weak_input_validation", "入力検証不足"),
    "DUS": ("shared_memory_overwrite", "共有メモリ不適切利用"),
}

CATEGORY_PREFIX_MAP = {
    "unencrypted_output": "UDO",
    "weak_input_validation": "IVW",
    "shared_memory_overwrite": "SMO",
}


# ---------------------------------------------------------------------------
# Marker extraction
# ---------------------------------------------------------------------------

# Markers: /* SOURCE:v001-i01 */  /* SINK:v001-i01 */  /* SANITIZER:v001-i01 */
MARKER_RE = re.compile(r'/\*\s*(SOURCE|SINK|SANITIZER):(\S+)\s*\*/')


def extract_markers(source_code: str) -> dict[str, dict[str, int]]:
    """Extract SOURCE/SINK/SANITIZER markers from source code.

    Returns:
        Dict of {instance_id: {"SOURCE": line, "SINK": line, "SANITIZER": line}}
    """
    markers: dict[str, dict[str, int]] = {}
    for line_num, line in enumerate(source_code.splitlines(), start=1):
        for match in MARKER_RE.finditer(line):
            marker_type = match.group(1)  # SOURCE / SINK / SANITIZER
            instance_id = match.group(2)  # v001-i01
            if instance_id not in markers:
                markers[instance_id] = {}
            markers[instance_id][marker_type] = line_num
    return markers


def extract_sink_lines(source_code: str) -> list[int]:
    """Extract all SINK marker line numbers from source code."""
    lines = []
    for line_num, line in enumerate(source_code.splitlines(), start=1):
        for match in MARKER_RE.finditer(line):
            if match.group(1) == "SINK":
                lines.append(line_num)
    return lines


# ---------------------------------------------------------------------------
# Safe invariant validation
# ---------------------------------------------------------------------------

# Secret variable names used in UDO templates
SECRET_VAR_PATTERN = re.compile(r'\bsecret\b')


def validate_safe_invariant(safe_source: str, category: str) -> list[str]:
    """Validate that safe version's SINK lines don't reference 'secret' variable.

    Only applicable to UDO variants.

    Returns:
        List of error messages (empty = passed)
    """
    if category != "unencrypted_output":
        return []

    errors = []
    markers = extract_markers(safe_source)
    lines = safe_source.splitlines()

    for instance_id, marker_lines in markers.items():
        sink_line = marker_lines.get("SINK")
        if sink_line is None:
            continue
        # Check the SINK line itself
        line_content = lines[sink_line - 1] if sink_line <= len(lines) else ""
        # Remove the marker comment itself before checking
        line_content_no_marker = MARKER_RE.sub("", line_content)
        if SECRET_VAR_PATTERN.search(line_content_no_marker):
            errors.append(
                f"Safe invariant violation: 'secret' found on SINK line {sink_line} "
                f"for instance {instance_id}"
            )
    return errors


# ---------------------------------------------------------------------------
# Ground truth CSV
# ---------------------------------------------------------------------------

def build_ground_truth_rows(
    vuln_instances: list[VulnInstance],
) -> list[dict]:
    """Build ground truth label rows.

    Each row: Line Number, Category, Category_JP, Function, Label ID, Group
    The representative line = SINK marker line.
    """
    rows = []
    for vi in vuln_instances:
        prefix = CATEGORY_PREFIX_MAP.get(vi.category, "UNK")
        rows.append({
            "Line Number": vi.sink_line,
            "Category": vi.category,
            "Category_JP": vi.category_jp,
            "Function": vi.function_name,
            "Label ID": vi.instance_id,
            "Group": f"{prefix}-{vi.instance_id}",
        })
    return rows


def write_ground_truth_csv(rows: list[dict], output_path: Path) -> None:
    """Write ground truth labels CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["Line Number", "Category", "Category_JP", "Function", "Label ID", "Group"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Taint / Sanitizer flow labels
# ---------------------------------------------------------------------------

def write_taint_labels_csv(
    checkpoints: list[TaintCheckpoint],
    output_path: Path,
) -> None:
    """Write taint labels CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["checkpoint_id", "function", "line", "var", "role", "origin", "note"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for cp in checkpoints:
            writer.writerow({
                "checkpoint_id": cp.checkpoint_id,
                "function": cp.function,
                "line": cp.line,
                "var": cp.var,
                "role": cp.role,
                "origin": cp.origin,
                "note": cp.note,
            })


def write_sanitizer_labels_csv(
    entries: list[SanitizerEntry],
    output_path: Path,
) -> None:
    """Write sanitizer labels CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["flow", "function", "line", "expression", "kind", "protects_vars", "note"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for se in entries:
            writer.writerow({
                "flow": se.flow,
                "function": se.function,
                "line": se.line,
                "expression": se.expression,
                "kind": se.kind,
                "protects_vars": se.protects_vars,
                "note": se.note,
            })


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def write_manifest(
    variant_id: str,
    variant_name: str,
    category_key: str,
    variant_type: str,
    structural_features: dict,
    safe_fix_description: str,
    vuln_instances: list[VulnInstance],
    output_path: Path,
) -> None:
    """Write manifest.json for a variant."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    category, category_jp = CATEGORY_MAP.get(category_key, (category_key, ""))
    manifest = {
        "variant_id": variant_id,
        "variant_name": variant_name,
        "category": category,
        "category_jp": category_jp,
        "variant_type": variant_type,
        "structural_features": structural_features,
        "safe_fix_description": safe_fix_description,
        "instance_count": len(vuln_instances),
        "labels": [
            {
                "instance_id": vi.instance_id,
                "sink_line": vi.sink_line,
                "source_line": vi.source_line,
                "sanitizer_line": vi.sanitizer_line,
                "function": vi.function_name,
            }
            for vi in vuln_instances
        ],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Resolve markers in template results
# ---------------------------------------------------------------------------

def resolve_vuln_instances(
    source_code: str,
    vuln_markers: list[dict],
    category_key: str,
) -> list[VulnInstance]:
    """Resolve SINK/SOURCE/SANITIZER markers to line numbers and build VulnInstances.

    Args:
        source_code: Complete entry.c source
        vuln_markers: List of {"id": "v001-i01", "function": "func_name"}
        category_key: "UDO" / "IVW" / "DUS"

    Returns:
        List of VulnInstance with resolved line numbers
    """
    markers = extract_markers(source_code)
    category, category_jp = CATEGORY_MAP.get(category_key, (category_key, ""))

    instances = []
    for vm in vuln_markers:
        instance_id = vm["id"]
        function_name = vm["function"]
        resolved = markers.get(instance_id, {})

        instances.append(VulnInstance(
            instance_id=instance_id,
            category=category,
            category_jp=category_jp,
            function_name=function_name,
            source_line=resolved.get("SOURCE", 0),
            sink_line=resolved.get("SINK", 0),
            sanitizer_line=resolved.get("SANITIZER"),
        ))

    return instances
