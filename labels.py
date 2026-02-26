"""
labels.py — Ground truth, taint, sanitizer label生成 + マーカー解決

テンプレート内の SOURCE/SINK/SANITIZER マーカーを行番号に解決し、
ground_truth_labels.csv, taint/sanitizer flow labels, manifest.json を生成する。

Validation functions are in validators.py.
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
    sink_line: int = 0      # resolved line number of SINK marker (= ラベル行 / 代表行)
    sanitizer_line: Optional[int] = None  # resolved line of SANITIZER (None if absent)
    group_start: int = 0    # 検知グループ先頭行 (inclusive)
    group_end: int = 0      # 検知グループ末尾行 (inclusive)


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
    "shared_memory_overwrite": "DUS",
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
# Detection group computation
# ---------------------------------------------------------------------------

_MAX_GROUP_EXPAND = 5  # safety limit for backward/forward expansion


def _is_stmt_boundary(line_text: str) -> bool:
    """Return True if line_text ends a C statement (;) or block ({/})."""
    clean = MARKER_RE.sub("", line_text).strip()
    if not clean:
        return True
    return clean[-1] in (";", "{", "}")


def compute_detection_group(source_code: str, sink_line: int) -> tuple[int, int]:
    """Compute the detection group line range around a SINK line.

    The detection group covers the full C statement containing the SINK,
    including multi-line function calls (e.g. snprintf spanning 2 lines).
    A tool reporting ANY line within [group_start, group_end] is counted
    as having detected this vulnerability instance.

    Returns:
        (group_start, group_end) — 1-indexed, inclusive
    """
    lines = source_code.splitlines()
    n = len(lines)
    if sink_line < 1 or sink_line > n:
        return (sink_line, sink_line)

    # Walk backward: include continuation lines of the same statement
    start = sink_line
    for _ in range(_MAX_GROUP_EXPAND):
        if start <= 1:
            break
        if _is_stmt_boundary(lines[start - 2]):  # line above is a boundary
            break
        start -= 1

    # Walk forward: current line may not yet end the statement
    end = sink_line
    for _ in range(_MAX_GROUP_EXPAND):
        if _is_stmt_boundary(lines[end - 1]):
            break
        if end >= n:
            break
        end += 1

    return (start, end)


# ---------------------------------------------------------------------------
# Ground truth CSV
# ---------------------------------------------------------------------------

def build_ground_truth_rows(
    vuln_instances: list[VulnInstance],
) -> list[dict]:
    """Build ground truth label rows.

    Each row contains:
    - Line Number: ラベル行 (SINK marker line = 代表行)
    - Det Start / Det End: 検知グループ (同一処理範囲)
    - Category, Category_JP, Function, Label ID, Group
    """
    rows = []
    for vi in vuln_instances:
        prefix = CATEGORY_PREFIX_MAP.get(vi.category, "UNK")
        rows.append({
            "Line Number": vi.sink_line,
            "Det Start": vi.group_start,
            "Det End": vi.group_end,
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
    fieldnames = [
        "Line Number", "Det Start", "Det End",
        "Category", "Category_JP", "Function", "Label ID", "Group",
    ]
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
    vuln_markers: Optional[list[dict]] = None,
) -> None:
    """Write manifest.json for a variant."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    category, category_jp = CATEGORY_MAP.get(category_key, (category_key, ""))

    # Build a lookup for shared references
    marker_by_id: dict[str, dict] = {}
    if vuln_markers:
        for vm in vuln_markers:
            marker_by_id[vm["id"]] = vm

    labels = []
    for vi in vuln_instances:
        entry: dict = {
            "instance_id": vi.instance_id,
            "sink_line": vi.sink_line,
            "det_group": [vi.group_start, vi.group_end],
            "source_line": vi.source_line,
            "sanitizer_line": vi.sanitizer_line,
            "function": vi.function_name,
        }
        vm = marker_by_id.get(vi.instance_id, {})
        if "shared_source" in vm:
            entry["shared_source"] = vm["shared_source"]
        if "shared_sanitizer" in vm:
            entry["shared_sanitizer"] = vm["shared_sanitizer"]
        labels.append(entry)

    manifest = {
        "variant_id": variant_id,
        "variant_name": variant_name,
        "category": category,
        "category_jp": category_jp,
        "variant_type": variant_type,
        "structural_features": structural_features,
        "safe_fix_description": safe_fix_description,
        "instance_count": len(vuln_instances),
        "labels": labels,
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
    safe_source: Optional[str] = None,
) -> list[VulnInstance]:
    """Resolve SINK/SOURCE/SANITIZER markers to line numbers and build VulnInstances.

    Two-pass resolution:
      1. Resolve all instances that have their own markers in C code.
      2. For instances with shared_source/shared_sanitizer, inherit line numbers
         from the referenced instance.

    Args:
        source_code: Complete entry.c source (unsafe version)
        vuln_markers: List of {"id": "v001-i01", "function": "func_name",
                       "shared_source": "v001-i01",      (optional)
                       "shared_sanitizer": "v001-i01"}    (optional)
        category_key: "UDO" / "IVW" / "DUS"
        safe_source: Complete entry.c source (safe version) for SANITIZER resolution

    Returns:
        List of VulnInstance with resolved line numbers
    """
    markers = extract_markers(source_code)
    safe_markers = extract_markers(safe_source) if safe_source else {}
    category, category_jp = CATEGORY_MAP.get(category_key, (category_key, ""))

    # Pass 1: resolve instances from their own markers
    instances = []
    instance_map: dict[str, VulnInstance] = {}
    for vm in vuln_markers:
        instance_id = vm["id"]
        function_name = vm["function"]
        resolved = markers.get(instance_id, {})
        safe_resolved = safe_markers.get(instance_id, {})

        vi = VulnInstance(
            instance_id=instance_id,
            category=category,
            category_jp=category_jp,
            function_name=function_name,
            source_line=resolved.get("SOURCE", 0),
            sink_line=resolved.get("SINK", 0),
            sanitizer_line=safe_resolved.get("SANITIZER") or resolved.get("SANITIZER"),
        )
        instances.append(vi)
        instance_map[instance_id] = vi

    # Pass 2: inherit from shared references
    for vm, vi in zip(vuln_markers, instances):
        shared_src = vm.get("shared_source")
        if shared_src and shared_src in instance_map:
            vi.source_line = instance_map[shared_src].source_line

        shared_san = vm.get("shared_sanitizer")
        if shared_san and shared_san in instance_map:
            vi.sanitizer_line = instance_map[shared_san].sanitizer_line

    return instances
