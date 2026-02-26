#!/usr/bin/env python3
"""
main.py — RQ3 Dataset Generator

CLI entry point and pipeline orchestration for generating
OP-TEE TA bad partitioning vulnerability test cases.

Scaffold files are embedded from OP-TEE official optee_examples/hello_world
(BSD-2-Clause). No external scaffold directory is required.

Usage:
    python3 main.py --output-dir TA_Dataset
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from templates import TEMPLATE_REGISTRY, TemplateResult
from emitters import assemble_entry_c, write_variant_project, write_toctou_oracle
from labels import (
    CATEGORY_MAP,
    extract_sink_lines,
    extract_markers,
    resolve_vuln_instances,
    compute_detection_group,
    build_ground_truth_rows,
    write_ground_truth_csv,
    write_taint_labels_csv,
    write_sanitizer_labels_csv,
    write_manifest,
    TaintCheckpoint,
    SanitizerEntry,
)
from validators import (
    validate_safe_invariant,
    validate_marker_consistency,
    validate_safe_sink_args,
    validate_unsafe_safe_consistency,
    validate_ivw_safe_invariant,
    validate_dus_safe_invariant,
    validate_round_trip,
    validate_file_existence,
    validate_unsafe_safe_diff,
    validate_sink_line_content,
    validate_udo_unsafe_not_sanitized,
    validate_source_line_content,
    validate_udo_safe_enc_exists,
)
from metrics import compute_structural_shift_metrics


# ---------------------------------------------------------------------------
# Variant specifications
# ---------------------------------------------------------------------------

@dataclass
class VariantSpec:
    variant_id: str
    variant_name: str
    category_key: str       # "UDO" / "IVW" / "DUS"
    variant_type: str       # descriptive name
    structural_features: dict
    safe_fix_description: str


VARIANTS: list[VariantSpec] = [
    # UDO (v001-v008)
    VariantSpec("v001", "udo_deep_call_chain", "UDO", "deep_function_call_chain",
                {"call_depth": 3, "sink_api": "memcpy", "alias": "none", "control_flow": "linear"},
                "enc(secret)→enc_out→sink chain"),
    VariantSpec("v002", "udo_struct_member", "UDO", "struct_member_access",
                {"call_depth": 1, "sink_api": "TEE_MemMove", "alias": "struct_member", "control_flow": "linear"},
                "enc(struct->key)→enc_out→sink"),
    VariantSpec("v003", "udo_switch_dispatch", "UDO", "switch_case_dispatch",
                {"call_depth": 0, "sink_api": "memcpy/strncpy", "alias": "none", "control_flow": "switch"},
                "enc() before switch"),
    VariantSpec("v004", "udo_double_pointer", "UDO", "double_pointer_indirection",
                {"call_depth": 1, "sink_api": "snprintf", "alias": "double_pointer", "control_flow": "linear"},
                "enc(*ptr)→enc_out→sink"),
    VariantSpec("v005", "udo_conditional_encrypt", "UDO", "dead_conditional_sanitizer",
                {"call_depth": 0, "sink_api": "TEE_MemMove", "alias": "none", "control_flow": "if_dead"},
                "Fix conditional to always-true"),
    VariantSpec("v006", "udo_xor_derivation", "UDO", "xor_shift_derivation",
                {"call_depth": 1, "sink_api": "memcpy", "alias": "none", "control_flow": "loop"},
                "enc(derived)→enc_out→sink"),
    VariantSpec("v007", "udo_loop_multi_buffer", "UDO", "loop_multi_buffer_output",
                {"call_depth": 0, "sink_api": "TEE_MemMove", "alias": "none", "control_flow": "for_loop"},
                "enc() inside loop"),
    VariantSpec("v008", "udo_partial_encrypt", "UDO", "partial_encrypt_leak",
                {"call_depth": 0, "sink_api": "snprintf", "alias": "none", "control_flow": "linear"},
                "enc() on both key and IV"),

    # IVW (v009-v016)
    VariantSpec("v009", "ivw_pointer_arith", "IVW", "pointer_arithmetic_access",
                {"guard": "none", "sink_api": "pointer_deref", "derivation": "direct", "control_flow": "linear"},
                "Add bounds check before ptr+offset"),
    VariantSpec("v010", "ivw_while_loop", "IVW", "while_loop_unbounded",
                {"guard": "none", "sink_api": "TEE_Malloc", "derivation": "direct", "control_flow": "while_loop"},
                "Add if(size>MAX) return before while"),
    VariantSpec("v011", "ivw_signed_unsigned", "IVW", "signed_unsigned_mismatch",
                {"guard": "wrong_type", "sink_api": "TEE_Malloc", "derivation": "direct", "control_flow": "if_check"},
                "Use uint32_t with proper upper bound"),
    VariantSpec("v012", "ivw_unreachable_guard", "IVW", "unreachable_guard_scope",
                {"guard": "unreachable", "sink_api": "array_access", "derivation": "direct", "control_flow": "nested_if"},
                "Move guard before usage"),
    VariantSpec("v013", "ivw_off_by_one", "IVW", "off_by_one_check",
                {"guard": "off_by_one", "sink_api": "array_access", "derivation": "direct", "control_flow": "if_check"},
                "Fix <= to <"),
    VariantSpec("v014", "ivw_computed_index", "IVW", "multi_step_computed_index",
                {"guard": "none", "sink_api": "array_access", "derivation": "arithmetic", "control_flow": "linear"},
                "Add bounds check on computed result"),
    VariantSpec("v015", "ivw_wrong_operator", "IVW", "wrong_logical_operator",
                {"guard": "wrong_operator", "sink_api": "TEE_MemMove", "derivation": "direct", "control_flow": "if_check"},
                "Fix || to &&"),
    VariantSpec("v016", "ivw_wrapper_func", "IVW", "wrapper_function_hidden_taint",
                {"guard": "none", "sink_api": "wrapper_TEE_Malloc", "derivation": "direct", "control_flow": "2_level_call"},
                "Add check before wrapper call"),

    # DUS (v017-v025)
    VariantSpec("v017", "dus_wait_typedef", "DUS", "typedef_alias_tee_wait",
                {"alias": "typedef", "compare_api": "strcmp", "toctou_window": "TEE_Wait", "control_flow": "linear"},
                "memcpy(local,shm)→local使用"),
    VariantSpec("v018", "dus_wait_struct", "DUS", "struct_field_tee_wait",
                {"alias": "struct_member", "compare_api": "strcmp", "toctou_window": "TEE_Wait", "control_flow": "linear"},
                "memcpy(local,shm)→local使用"),
    VariantSpec("v019", "dus_wait_reread", "DUS", "direct_ptr_tee_wait_reread",
                {"alias": "direct_ptr", "compare_api": "TEE_MemCompare", "toctou_window": "TEE_Wait", "control_flow": "linear"},
                "memcpy(local,shm)→local使用"),
    VariantSpec("v020", "dus_nested_reread", "DUS", "nested_if_reread",
                {"alias": "direct_ptr", "compare_api": "strcmp", "toctou_window": "function_call", "control_flow": "nested_if"},
                "Use local copy in inner block"),
    VariantSpec("v021", "dus_while_recheck", "DUS", "while_loop_recheck",
                {"alias": "direct_ptr", "compare_api": "strcmp", "toctou_window": "loop_iteration", "control_flow": "while_loop"},
                "Copy to local before loop"),
    VariantSpec("v022", "dus_callback", "DUS", "function_pointer_callback",
                {"alias": "func_ptr", "compare_api": "strcmp", "toctou_window": "indirect_call", "control_flow": "callback"},
                "Pass local copy to callback"),
    VariantSpec("v023", "dus_memcmp_libc", "DUS", "memcmp_libc_usage",
                {"alias": "direct_ptr", "compare_api": "memcmp", "toctou_window": "function_call", "control_flow": "linear"},
                "Copy to local first"),
    VariantSpec("v024", "dus_partial_copy", "DUS", "partial_copy_split_access",
                {"alias": "split_alias", "compare_api": "strcmp", "toctou_window": "split_access", "control_flow": "linear"},
                "Full copy to local"),
    VariantSpec("v025", "dus_return_ignored", "DUS", "return_value_ignored",
                {"alias": "return_ignored", "compare_api": "strcmp", "toctou_window": "function_call", "control_flow": "linear"},
                "Use returned safe copy"),
]


# ---------------------------------------------------------------------------
# PAD adjustment
# ---------------------------------------------------------------------------

LINE_THRESHOLD = 195
MAX_PAD_ATTEMPTS = 5


def compute_pad(category_key: str, body: str) -> int:
    """Compute initial PAD lines for line number alignment.

    UDO: all SINK lines must be < 195
    IVW: all SINK lines must be > 195
    DUS: no constraint
    """
    if category_key == "DUS":
        return 0

    # Try with 0 pad first to measure
    test_source = assemble_entry_c(body, pad_lines=0)
    sink_lines = extract_sink_lines(test_source)

    if not sink_lines:
        return 0

    if category_key == "UDO":
        max_sink = max(sink_lines)
        if max_sink < LINE_THRESHOLD:
            return 0
        # This shouldn't happen for well-designed UDO templates
        # (boilerplate is ~95 lines, body should be < 100 lines)
        return 0
    elif category_key == "IVW":
        min_sink = min(sink_lines)
        if min_sink > LINE_THRESHOLD:
            return 0
        # Need to push lines down
        return LINE_THRESHOLD - min_sink + 5
    return 0


def adjust_and_assemble(category_key: str, body: str) -> tuple[str, dict]:
    """Assemble entry.c with PAD auto-adjustment loop.

    Returns:
        Tuple of (assembled source code, PAD convergence metadata)
    """
    pad = compute_pad(category_key, body)
    converged = False
    attempts_used = 0

    for attempt in range(MAX_PAD_ATTEMPTS):
        attempts_used = attempt + 1
        source = assemble_entry_c(body, pad_lines=pad)
        sink_lines = extract_sink_lines(source)

        if not sink_lines:
            converged = True
            break

        if category_key == "UDO":
            if all(l < LINE_THRESHOLD for l in sink_lines):
                converged = True
                break
            excess = max(sink_lines) - LINE_THRESHOLD + 1
            pad = max(0, pad - excess)
        elif category_key == "IVW":
            if all(l > LINE_THRESHOLD for l in sink_lines):
                converged = True
                break
            deficit = LINE_THRESHOLD - min(sink_lines) + 5
            pad += deficit
        elif category_key == "DUS":
            converged = True
            break
    else:
        print(f"WARNING: Failed to align line numbers after {MAX_PAD_ATTEMPTS} attempts",
              file=sys.stderr)

    pad_info = {
        "pad_lines": pad,
        "attempts": attempts_used,
        "converged": converged,
        "sink_lines": sink_lines if sink_lines else [],
        "threshold": LINE_THRESHOLD,
        "constraint": f"< {LINE_THRESHOLD}" if category_key == "UDO"
                      else f"> {LINE_THRESHOLD}" if category_key == "IVW"
                      else "none",
    }
    return source, pad_info


# ---------------------------------------------------------------------------
# README generation
# ---------------------------------------------------------------------------

def generate_readme(variants: list[VariantSpec], output_dir: Path) -> None:
    """Generate README.md for the dataset."""
    lines = [
        "# RQ3 Dataset: Distribution Shift Evaluation",
        "",
        "## Overview",
        f"This dataset contains {len(variants)} OP-TEE TA variants for evaluating",
        "distribution shift resilience of DITING and LLM-based analyzers.",
        "",
        "Each variant is an **unsafe/safe pair**:",
        "- `unsafe/`: Contains intentional bad partitioning vulnerabilities",
        "- `safe/`: Same structure with vulnerabilities patched",
        "",
        "## Variant Summary",
        "",
        "| ID | Name | Category | Structural Variation |",
        "|----|------|----------|---------------------|",
    ]
    for v in variants:
        lines.append(f"| {v.variant_id} | {v.variant_name} | {v.category_key} | {v.variant_type} |")

    # ------------------------------------------------------------------
    # Structural Shift Comparison: original benchmark vs RQ3 variants
    # ------------------------------------------------------------------
    lines.extend([
        "",
        "## Distribution Shift: Structural Feature Comparison",
        "",
        "The table below compares the structural features present in the **original "
        "PartitioningE-Bench** (bad-partitioning, 75 instances) with those introduced "
        "in the RQ3 variants. Features marked **New** are outside the original "
        "benchmark distribution and constitute the structural shift being evaluated.",
        "",
        "### Feature Envelope Comparison",
        "",
        "| Structural Dimension | Original Benchmark (bad-partitioning) | RQ3 Dataset (this dataset) |",
        "|---|---|---|",
        "| Max call depth (from handler) | 2 | **3** (v001) |",
        "| Data indirection | direct char[], TEE_Param member, void* ptr, "
        "simple index arithmetic (a-3) | + **double pointer** (v004), **typedef alias** (v017), "
        "**struct-based handle** (v002,v018), **multi-step computed** (v014: val\\*4+3), "
        "**pointer arithmetic** (v009: *(base+offset)), **XOR derivation** (v006) |",
        "| Control flow at sink | if/early-return, for-loop | + **switch per-case sinks** (v003), "
        "**while-loop** (v010,v021), **dead-code conditional** (v005), "
        "**nested if/else scope** (v012,v020), **loop over params[]** (v007) |",
        "| Sink API | TEE_MemMove, snprintf, TEE_Malloc, strcmp, TEE_MemCompare, "
        "arr[], value.a= | + **memcpy** (v001,v006), **strncpy** (v003), "
        "**memcmp** (v023), **pointer deref** (v009) |",
        "| Guard flaw type | (none — guards in original are correct or absent) | "
        "**off-by-one** (v013), **wrong operator** (v015: \\|\\|→&&), "
        "**signed/unsigned cast** (v011), **unreachable scope** (v012), "
        "**dead-code sanitizer** (v005), **partial encrypt** (v008), "
        "**wrapper hiding taint** (v016) |",
        "| TOCTOU mechanism | TEE_Wait only, pointer aliasing | + **function call gap** (v020,v023,v025), "
        "**loop re-read** (v021), **callback via function pointer** (v022), "
        "**partial copy split access** (v024), **return value ignored** (v025) |",
        "| Language features | (none user-defined) | **typedef** (v017), "
        "**function pointer + callback** (v022) |",
        "| Source pattern (IVW) | params[] direct at sink | params[] → **local variable** "
        "(int, uint32_t, etc.) → derived use |",
        "",
        "### Per-Variant Structural Novelty",
        "",
        "Each row indicates which features of the variant are **absent from the "
        "original benchmark**. This justifies each variant as a distribution-shift "
        "test case.",
        "",
        "| ID | Category | Novel Features (not in original benchmark) |",
        "|-----|----------|---------------------------------------------|",
        "| v001 | UDO | Call depth 3, memcpy sink, 4 user-defined functions |",
        "| v002 | UDO | Secret in user-defined struct (not TEE_Param), "
        "struct member access via -> |",
        "| v003 | UDO | switch-case with per-case different sink APIs "
        "(memcpy/strncpy/snprintf), strncpy sink |",
        "| v004 | UDO | Double pointer (char\\*\\*) indirection |",
        "| v005 | UDO | Dead-code sanitizer (enc() inside always-false conditional) |",
        "| v006 | UDO | XOR/shift data derivation before output, memcpy sink, "
        "value.a assignment as output channel |",
        "| v007 | UDO | for-loop iterating over params[0..2] array "
        "(original loops over buffer content, not params array) |",
        "| v008 | UDO | Partial encryption (key encrypted, IV leaked in same output) |",
        "| v009 | IVW | Pointer arithmetic \\*(base+offset) instead of arr[idx] |",
        "| v010 | IVW | while-loop with tainted bound, "
        "two separate REE sources (memref.size + value.a) |",
        "| v011 | IVW | Signed/unsigned type mismatch (int cast of uint32_t) |",
        "| v012 | IVW | Guard in wrong scope (unreachable: inside else branch) |",
        "| v013 | IVW | Off-by-one (\\<= vs \\<) |",
        "| v014 | IVW | Multi-step computed index (val\\*4+3), "
        "arithmetic amplification of tainted value |",
        "| v015 | IVW | Wrong logical operator (\\|\\| vs &&) |",
        "| v016 | IVW | Wrapper function hiding taint path (my\\_alloc → TEE\\_Malloc) |",
        "| v017 | DUS | typedef alias for shm pointer (typedef char\\* shm\\_buf\\_t) |",
        "| v018 | DUS | struct field storing shm pointer (struct shm\\_handle) |",
        "| v019 | DUS | Explicit re-read from params[] after TEE\\_Wait "
        "(original uses only cached void\\*) |",
        "| v020 | DUS | Nested if + shm re-read in inner block, "
        "function call gap TOCTOU |",
        "| v021 | DUS | while-loop re-check TOCTOU (loop iteration gap) |",
        "| v022 | DUS | Function pointer typedef, callback invocation, "
        "indirect call TOCTOU |",
        "| v023 | DUS | memcmp (libc) instead of TEE\\_MemCompare |",
        "| v024 | DUS | Partial copy (header local, payload still shm), "
        "split-access TOCTOU |",
        "| v025 | DUS | Return value ignored "
        "(validation func returns safe copy, caller uses original shm) |",
    ])

    # ------------------------------------------------------------------
    # Quantitative Structural Shift Metrics (computed from feature vectors)
    # ------------------------------------------------------------------
    metrics = compute_structural_shift_metrics()
    agg = metrics["aggregate"]
    dims = metrics["per_dim"]
    pvs = metrics["per_variant"]

    lines.extend([
        "",
        "### Quantitative Shift Metrics",
        "",
        "Structural features are encoded as a binary feature vector across 7 dimensions "
        f"({agg['n_features_total']} features total). "
        "Each variant and the original benchmark are represented as subsets of this space.",
        "",
        "#### Aggregate Statistics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total features in taxonomy | {agg['n_features_total']} |",
        f"| Features in original benchmark | {agg['n_original']} |",
        f"| Novel features (not in original) | {agg['n_novel_defined']} |",
        f"| Features used by RQ3 variants | {agg['n_rq3_used']} |",
        f"| of which: in-distribution | {agg['n_rq3_shared']} |",
        f"| of which: out-of-distribution (novel) | {agg['n_rq3_novel_used']} |",
        f"| Novel feature ratio (novel / used) | {agg['novel_ratio']:.1%} |",
        f"| Jaccard distance (orig vs RQ3) | {agg['jaccard_distance']:.3f} |",
        "",
        "**Jaccard distance** = 1 − |F_orig ∩ F_RQ3| / |F_orig ∪ F_RQ3| ; "
        "0 = identical feature sets, 1 = no overlap.",
        "",
        "#### Per-Dimension Expansion",
        "",
        "| Dimension | Features in Original | Novel in RQ3 | Total | Expansion Ratio |",
        "|-----------|---------------------|--------------|-------|-----------------|",
    ])
    for dim_key in sorted(dims.keys()):
        d = dims[dim_key]
        lines.append(
            f"| {d['label']} | {d['n_original']} | {d['n_novel_used']} | "
            f"{d['n_original'] + d['n_novel_used']} | "
            f"×{d['expansion']:.2f} |"
        )

    lines.extend([
        "",
        "#### Per-Variant Novelty Score",
        "",
        "Novelty score = (# novel features) / (# total features of variant). "
        "Higher score indicates greater structural distance from original benchmark.",
        "",
        "| ID | Cat. | Features | Novel | In-dist. | Novelty Score |",
        "|-----|------|----------|-------|----------|---------------|",
    ])
    for vid in sorted(pvs.keys()):
        p = pvs[vid]
        cat = next((v.category_key for v in variants if v.variant_id == vid), "?")
        lines.append(
            f"| {vid} | {cat} | {p['n_total']} | {p['n_novel']} | "
            f"{p['n_original']} | {p['novelty_score']:.2f} |"
        )

    # Average novelty score
    avg_novelty = sum(p["novelty_score"] for p in pvs.values()) / len(pvs) if pvs else 0.0
    lines.extend([
        f"| **Average** | | | | | **{avg_novelty:.2f}** |",
    ])

    lines.extend([
        "",
        "## Label Files",
        "- `ground_truth_labels.csv`: Aggregated category labels (SINK line = representative line)",
        "- Per-variant: `variant_NNN/ground_truth_labels.csv`",
        "- Per-variant: `variant_NNN/flow_labels/{category}_taint_labels.csv`",
        "- Per-variant: `variant_NNN/flow_labels/{category}_sanitizer_labels.csv`",
        "- Per-variant: `variant_NNN/manifest.json`",
        "",
        "## Instance ID Convention",
        "- Format: `vNNN-iNN` (e.g., `v001-i01`)",
        "- Markers: `/* SOURCE:id */`, `/* SINK:id */`, `/* SANITIZER:id */`",
        "- Ground truth representative line = SINK marker line",
        "- Group: `{CATEGORY_PREFIX}-{instance_id}`",
        "",
        "## Safe Invariants",
        "- **UDO**: `secret[]` and `enc_out[]` are always separate buffers.",
        "  Safe version's sink only references `enc_out` (never `secret`).",
        "  `enc(enc_out)` is called before any sink operation.",
        "- **IVW**: Safe version has correct bounds check before every sink.",
        "- **DUS**: Safe version copies shared memory to local buffer before",
        "  any validation or use. All subsequent operations use the local copy.",
        "",
        "## Compatibility",
        "- **DITING**: Run vanilla `synthsis_analysis.py` (no modification needed)",
        "- **tee-flow-inspector**: `compile_commands.json` pre-generated in each `ta/`",
        "",
        "## Derivation",
        "Scaffold derived from OP-TEE official `optee_examples/hello_world` (BSD-2-Clause).",
        "TA source (`entry.c`) generated by `ta-dataset-generator/main.py`",
        "(template + parametric, no LLM code generation).",
    ])

    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def generate_dataset(output_dir: Path) -> None:
    """Generate the complete RQ3 dataset."""
    output_dir.mkdir(parents=True, exist_ok=True)

    all_gt_rows = []
    all_instance_ids = set()
    errors = []
    verification_log = {}  # variant_id → verification details

    for spec in VARIANTS:
        print(f"Generating {spec.variant_id}: {spec.variant_name} ({spec.category_key})")

        vlog: dict = {"variant_id": spec.variant_id, "category": spec.category_key}

        # 1. Get template result
        tpl_func = TEMPLATE_REGISTRY[spec.variant_id]
        result: TemplateResult = tpl_func()

        # 2. Assemble entry.c with PAD adjustment
        # Compute PAD from unsafe body (which has SINK markers), then apply
        # the SAME PAD to safe body so both versions have identical line structure.
        unsafe_source, unsafe_pad = adjust_and_assemble(spec.category_key, result.unsafe_body)
        safe_source = assemble_entry_c(result.safe_body, pad_lines=unsafe_pad["pad_lines"])
        safe_pad = {
            "pad_lines": unsafe_pad["pad_lines"],
            "attempts": 0,
            "converged": True,
            "sink_lines": extract_sink_lines(safe_source),
            "threshold": LINE_THRESHOLD,
            "constraint": unsafe_pad["constraint"],
            "note": "Reuses unsafe PAD for structural consistency",
        }

        # Log PAD convergence
        vlog["pad"] = {
            "unsafe": unsafe_pad,
            "safe": safe_pad,
        }

        # 3. Write project directories
        unsafe_dir, safe_dir = write_variant_project(
            output_dir=output_dir,
            variant_id=spec.variant_id,
            unsafe_source=unsafe_source,
            safe_source=safe_source,
        )

        # 4. Resolve markers → VulnInstances
        vuln_instances = resolve_vuln_instances(
            unsafe_source, result.vuln_markers, spec.category_key,
            safe_source=safe_source,
        )

        # 4b. Compute detection groups
        for vi in vuln_instances:
            vi.group_start, vi.group_end = compute_detection_group(
                unsafe_source, vi.sink_line,
            )

        # 5. Validate
        variant_errors = []

        # 5a. Instance ID uniqueness
        for vi in vuln_instances:
            if vi.instance_id in all_instance_ids:
                variant_errors.append(f"Duplicate instance_id: {vi.instance_id}")
            all_instance_ids.add(vi.instance_id)

        # 5b. SINK line resolution
        for vi in vuln_instances:
            if vi.sink_line == 0:
                variant_errors.append(f"SINK marker not found for {vi.instance_id}")

        # 5c. Line number band (UDO < 195, IVW > 195)
        for vi in vuln_instances:
            if spec.category_key == "UDO" and vi.sink_line >= LINE_THRESHOLD:
                variant_errors.append(
                    f"UDO SINK line {vi.sink_line} >= {LINE_THRESHOLD} for {vi.instance_id}"
                )
            elif spec.category_key == "IVW" and vi.sink_line <= LINE_THRESHOLD:
                variant_errors.append(
                    f"IVW SINK line {vi.sink_line} <= {LINE_THRESHOLD} for {vi.instance_id}"
                )

        # 5d. Marker consistency (unsafe SINK ↔ safe SANITIZER)
        mc_errors = validate_marker_consistency(
            unsafe_source, safe_source, result.vuln_markers, spec.category_key,
        )
        variant_errors.extend(mc_errors)

        # 5e. Safe invariant — secret not on SINK line (UDO only)
        si_errors = validate_safe_invariant(
            safe_source, vuln_instances[0].category if vuln_instances else "",
        )
        variant_errors.extend(si_errors)

        # 5f. Safe sink args — enc_out only, no secret at sink API (UDO only)
        sa_errors = validate_safe_sink_args(
            safe_source, vuln_instances[0].category if vuln_instances else "",
        )
        variant_errors.extend(sa_errors)

        # 5g. SOURCE line resolution (G1)
        for vi in vuln_instances:
            if vi.source_line == 0:
                variant_errors.append(f"SOURCE not resolved for {vi.instance_id}")

        # 5h. SANITIZER line resolution (G2)
        for vi in vuln_instances:
            if vi.sanitizer_line is None or vi.sanitizer_line == 0:
                variant_errors.append(f"SANITIZER not resolved for {vi.instance_id}")

        # 5i. shared reference target validity (G3)
        all_marker_ids = {vm["id"] for vm in result.vuln_markers}
        for vm in result.vuln_markers:
            ref = vm.get("shared_source")
            if ref and ref not in all_marker_ids:
                variant_errors.append(
                    f"shared_source '{ref}' not found for {vm['id']}"
                )
            ref = vm.get("shared_sanitizer")
            if ref and ref not in all_marker_ids:
                variant_errors.append(
                    f"shared_sanitizer '{ref}' not found for {vm['id']}"
                )

        # 5j. PAD convergence (G4)
        if not unsafe_pad["converged"]:
            variant_errors.append(
                f"PAD failed to converge after {unsafe_pad['attempts']} attempts"
            )

        # 5k. Detection group validity
        for vi in vuln_instances:
            if not (vi.group_start <= vi.sink_line <= vi.group_end):
                variant_errors.append(
                    f"Detection group [{vi.group_start},{vi.group_end}] "
                    f"does not contain sink_line {vi.sink_line} for {vi.instance_id}"
                )

        # 5l. Unsafe/safe line count consistency (FP2)
        # Line count difference is expected (safe adds sanitizer code).
        # Log as info, not error.
        uc_notes = validate_unsafe_safe_consistency(unsafe_source, safe_source)
        if uc_notes:
            vlog["line_count_diff"] = uc_notes[0]

        # 5m. IVW safe invariant: bounds check before sink (FP3)
        ivw_errors = validate_ivw_safe_invariant(safe_source, spec.category_key)
        variant_errors.extend(ivw_errors)

        # 5n. DUS safe invariant: local copy pattern present (FP3)
        dus_errors = validate_dus_safe_invariant(safe_source, spec.category_key)
        variant_errors.extend(dus_errors)

        # 5o. File existence on disk (FP4)
        fe_errors = validate_file_existence(unsafe_dir)
        fe_errors.extend(validate_file_existence(safe_dir))
        variant_errors.extend(fe_errors)

        # 5p. Round-trip verification: disk entry.c matches in-memory (FP5)
        rt_errors = validate_round_trip(unsafe_dir / "ta" / "entry.c", unsafe_source)
        rt_errors.extend(validate_round_trip(safe_dir / "ta" / "entry.c", safe_source))
        variant_errors.extend(rt_errors)

        # 5q. Unsafe ≠ safe code diff (FP6)
        diff_errors = validate_unsafe_safe_diff(unsafe_source, safe_source)
        variant_errors.extend(diff_errors)

        # 5r. SINK line content — must contain executable code (FP7)
        slc_errors = validate_sink_line_content(unsafe_source, result.vuln_markers)
        variant_errors.extend(slc_errors)

        # 5s. UDO unsafe must not already be sanitized (FP8)
        uas_errors = validate_udo_unsafe_not_sanitized(
            unsafe_source, result.vuln_markers, spec.category_key,
        )
        variant_errors.extend(uas_errors)

        # 5t. SOURCE line content — must contain executable code (FP9)
        src_errors = validate_source_line_content(unsafe_source, result.vuln_markers)
        variant_errors.extend(src_errors)

        # 5u. UDO safe must actually call enc() (FP10)
        enc_errors = validate_udo_safe_enc_exists(safe_source, spec.category_key)
        variant_errors.extend(enc_errors)

        # Log validation results

        # Resolved per-instance triad (after shared_source/shared_sanitizer inheritance)
        vlog["resolved_instances"] = {}
        for vi in vuln_instances:
            vm_entry = next((vm for vm in result.vuln_markers if vm["id"] == vi.instance_id), {})
            inst_info: dict = {
                "source_line": vi.source_line,
                "sink_line": vi.sink_line,
                "sanitizer_line": vi.sanitizer_line,
                "function": vi.function_name,
                "complete": (vi.source_line > 0
                             and vi.sink_line > 0
                             and vi.sanitizer_line is not None
                             and vi.sanitizer_line > 0),
            }
            if "shared_source" in vm_entry:
                inst_info["source_inherited_from"] = vm_entry["shared_source"]
            if "shared_sanitizer" in vm_entry:
                inst_info["sanitizer_inherited_from"] = vm_entry["shared_sanitizer"]
            vlog["resolved_instances"][vi.instance_id] = inst_info

        # Raw markers present in C source (for auditing code-level presence)
        vlog["markers"] = {
            "unsafe": {iid: list(m.keys()) for iid, m in extract_markers(unsafe_source).items()},
            "safe": {iid: list(m.keys()) for iid, m in extract_markers(safe_source).items()},
        }
        vlog["validation"] = {
            "passed": len(variant_errors) == 0,
            "errors": variant_errors,
        }
        errors.extend(variant_errors)

        # 6. Build ground truth rows
        gt_rows = build_ground_truth_rows(vuln_instances)
        all_gt_rows.extend(gt_rows)

        # 7. Write per-variant labels
        seq = int(spec.variant_id.replace("v", ""))
        variant_dir = output_dir / f"variant_{seq:03d}"

        # Per-variant ground truth
        write_ground_truth_csv(gt_rows, variant_dir / "ground_truth_labels.csv")

        # Flow labels
        flow_dir = variant_dir / "flow_labels"

        # Taint labels (from template result)
        if result.taint_flow:
            write_taint_labels_csv(result.taint_flow, flow_dir / f"{spec.category_key.lower()}_taint_labels.csv")
        else:
            taint_cps = _generate_basic_taint_flow(unsafe_source, vuln_instances, spec.category_key)
            write_taint_labels_csv(taint_cps, flow_dir / f"{spec.category_key.lower()}_taint_labels.csv")

        # Sanitizer labels (from template result)
        if result.sanitizers:
            write_sanitizer_labels_csv(result.sanitizers, flow_dir / f"{spec.category_key.lower()}_sanitizer_labels.csv")
        else:
            san_entries = _generate_basic_sanitizer_labels(safe_source, vuln_instances, spec.category_key)
            write_sanitizer_labels_csv(san_entries, flow_dir / f"{spec.category_key.lower()}_sanitizer_labels.csv")

        # Manifest
        write_manifest(
            variant_id=spec.variant_id,
            variant_name=spec.variant_name,
            category_key=spec.category_key,
            variant_type=spec.variant_type,
            structural_features=spec.structural_features,
            safe_fix_description=spec.safe_fix_description,
            vuln_instances=vuln_instances,
            output_path=variant_dir / "manifest.json",
            vuln_markers=result.vuln_markers,
        )

        # 8. DUS-TOCTOU oracle (TEE_Wait variants only)
        if spec.category_key == "DUS" and spec.structural_features.get("toctou_window") == "TEE_Wait":
            write_toctou_oracle(unsafe_dir, safe_dir)

        verification_log[spec.variant_id] = vlog

    # 9. Cross-variant checks (G5: ground truth row count)
    if len(all_gt_rows) != len(all_instance_ids):
        errors.append(
            f"Ground truth row count ({len(all_gt_rows)}) != "
            f"instance count ({len(all_instance_ids)})"
        )

    # 10. Write aggregated ground truth
    write_ground_truth_csv(all_gt_rows, output_dir / "ground_truth_labels.csv")

    # 11. Write verification log
    vlog_path = output_dir / "verification_log.json"
    with open(vlog_path, "w", encoding="utf-8") as f:
        json.dump(verification_log, f, indent=2, ensure_ascii=False)

    # 12. Generate README
    generate_readme(VARIANTS, output_dir)

    # 13. Report
    print(f"\nDataset generated: {output_dir}")
    print(f"  Variants: {len(VARIANTS)}")
    print(f"  Total instances: {len(all_gt_rows)}")
    print(f"  Verification log: {vlog_path}")

    if errors:
        print(f"\nERRORS ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("  All validations passed.")


# ---------------------------------------------------------------------------
# Helper functions for basic label generation
# ---------------------------------------------------------------------------

def _find_enclosing_function(source: str, target_line: int) -> str:
    """Find the C function name that encloses the given line number.

    Scans backward from *target_line* looking for a top-level function
    definition — i.e. a non-indented line that contains ``identifier(``
    and is not a keyword / preprocessor directive / type definition.
    Falls back to ``"(unknown)"`` if no match is found.
    """
    _SKIP = frozenset(('if', 'while', 'for', 'switch', 'do',
                        'typedef', 'struct', 'enum', 'union'))
    lines = source.splitlines()
    for i in range(target_line - 1, -1, -1):
        raw = lines[i]
        # Only consider non-indented lines (function defs start at col 0)
        if not raw or raw[0] in (' ', '\t', '#', '/', '{', '}', '*'):
            continue
        m = re.search(r'\b(\w+)\s*\(', raw)
        if m and m.group(1) not in _SKIP:
            return m.group(1)
    return "(unknown)"


def _generate_basic_taint_flow(
    source: str,
    vuln_instances: list,
    category_key: str,
) -> list[TaintCheckpoint]:
    """Generate basic taint flow labels from resolved markers."""
    markers = extract_markers(source)

    cps = []
    # Entry point
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if "TA_InvokeCommandEntryPoint" in line and "TEE_Result" in line:
            cps.append(TaintCheckpoint(
                checkpoint_id="EP",
                function="TA_InvokeCommandEntryPoint",
                line=i,
                var="params[0..3]",
                role="source",
                origin="REE",
                note="NWから渡されるパラメータ",
            ))
            break

    for vi in vuln_instances:
        resolved = markers.get(vi.instance_id, {})

        if "SOURCE" in resolved:
            role = "secret_source" if category_key == "UDO" else "propagated"
            src_func = _find_enclosing_function(source, resolved["SOURCE"])
            cps.append(TaintCheckpoint(
                checkpoint_id=f"SOURCE:{vi.instance_id}",
                function=src_func,
                line=resolved["SOURCE"],
                var="(see source code)",
                role=role,
                origin="TA" if category_key == "UDO" else "REE",
                note=f"Source for {vi.instance_id}",
            ))

        if "SINK" in resolved:
            cps.append(TaintCheckpoint(
                checkpoint_id=f"SINK:{vi.instance_id}",
                function=vi.function_name,
                line=resolved["SINK"],
                var="(see source code)",
                role="sink_arg",
                origin="REE",
                note=f"Sink for {vi.instance_id}",
            ))

    return cps


def _generate_basic_sanitizer_labels(
    safe_source: str,
    vuln_instances: list,
    category_key: str,
) -> list[SanitizerEntry]:
    """Generate basic sanitizer labels from safe version markers."""
    markers = extract_markers(safe_source)

    flow_name = {"UDO": "UDO", "IVW": "IVW", "DUS": "DUS"}.get(category_key, category_key)
    kind_map = {
        "UDO": "encryption_sanitizer",
        "IVW": "upper_bound_check",
        "DUS": "local_copy_sanitizer",
    }

    entries = []
    # param_type_check (always present in cmd_process)
    lines = safe_source.splitlines()
    for i, line in enumerate(lines, 1):
        if "param_types != exp" in line:
            entries.append(SanitizerEntry(
                flow=flow_name,
                function="cmd_process",
                line=i,
                expression="if (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;",
                kind="param_type_check",
                protects_vars="param_types, params[*]",
                note="パラメータ型チェック",
            ))
            break

    for vi in vuln_instances:
        resolved = markers.get(vi.instance_id, {})
        if "SANITIZER" in resolved:
            san_func = _find_enclosing_function(safe_source, resolved["SANITIZER"])
            entries.append(SanitizerEntry(
                flow=flow_name,
                function=san_func,
                line=resolved["SANITIZER"],
                expression="(see source code)",
                kind=kind_map.get(category_key, "unknown"),
                protects_vars=vi.instance_id,
                note=f"Sanitizer for {vi.instance_id}",
            ))

    return entries


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate RQ3 bad partitioning dataset for TEE vulnerability evaluation"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("TA_Dataset"),
        help="Output directory (default: TA_Dataset)",
    )
    args = parser.parse_args()

    print(f"Scaffold: embedded (OP-TEE optee_examples/hello_world, BSD-2-Clause)")
    print(f"Output:   {args.output_dir}")
    print()

    generate_dataset(args.output_dir)


if __name__ == "__main__":
    main()
