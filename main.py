#!/usr/bin/env python3
"""
main.py — RQ3 Dataset Generator

CLI entry point and pipeline orchestration for generating
OP-TEE TA bad partitioning vulnerability test cases.

Scaffold files are embedded from OP-TEE official optee_examples/hello_world
(BSD-2-Clause). No external scaffold directory is required.

Usage:
    python3 main.py --output-dir RQ3_Dataset
"""

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from templates import TEMPLATE_REGISTRY, TemplateResult
from emitters import assemble_entry_c, write_variant_project
from labels import (
    CATEGORY_MAP,
    extract_sink_lines,
    resolve_vuln_instances,
    build_ground_truth_rows,
    write_ground_truth_csv,
    write_taint_labels_csv,
    write_sanitizer_labels_csv,
    write_manifest,
    validate_safe_invariant,
    TaintCheckpoint,
    SanitizerEntry,
)


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


def adjust_and_assemble(category_key: str, body: str) -> str:
    """Assemble entry.c with PAD auto-adjustment loop.

    Returns the assembled source code with correct line alignment.
    """
    pad = compute_pad(category_key, body)

    for attempt in range(MAX_PAD_ATTEMPTS):
        source = assemble_entry_c(body, pad_lines=pad)
        sink_lines = extract_sink_lines(source)

        if not sink_lines:
            break

        if category_key == "UDO":
            if all(l < LINE_THRESHOLD for l in sink_lines):
                break
            # Reduce pad (shouldn't normally happen)
            excess = max(sink_lines) - LINE_THRESHOLD + 1
            pad = max(0, pad - excess)
        elif category_key == "IVW":
            if all(l > LINE_THRESHOLD for l in sink_lines):
                break
            deficit = LINE_THRESHOLD - min(sink_lines) + 5
            pad += deficit
        elif category_key == "DUS":
            break
    else:
        print(f"WARNING: Failed to align line numbers after {MAX_PAD_ATTEMPTS} attempts",
              file=sys.stderr)

    return source


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
        "TA source (`entry.c`) generated by `rq3_dataset_generator/main.py`",
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

    for spec in VARIANTS:
        print(f"Generating {spec.variant_id}: {spec.variant_name} ({spec.category_key})")

        # 1. Get template result
        tpl_func = TEMPLATE_REGISTRY[spec.variant_id]
        result: TemplateResult = tpl_func()

        # 2. Assemble entry.c with PAD adjustment
        unsafe_source = adjust_and_assemble(spec.category_key, result.unsafe_body)
        safe_source = adjust_and_assemble(spec.category_key, result.safe_body)

        # 3. Write project directories
        unsafe_dir, safe_dir = write_variant_project(
            output_dir=output_dir,
            variant_id=spec.variant_id,
            variant_name=spec.variant_name,
            unsafe_source=unsafe_source,
            safe_source=safe_source,
        )

        # 4. Resolve markers → VulnInstances
        vuln_instances = resolve_vuln_instances(
            unsafe_source, result.vuln_markers, spec.category_key,
        )

        # 5. Validate
        # 5a. Instance ID uniqueness
        for vi in vuln_instances:
            if vi.instance_id in all_instance_ids:
                errors.append(f"Duplicate instance_id: {vi.instance_id}")
            all_instance_ids.add(vi.instance_id)

        # 5b. SINK line resolution
        for vi in vuln_instances:
            if vi.sink_line == 0:
                errors.append(f"SINK marker not found for {vi.instance_id}")

        # 5c. Line number band (UDO < 195, IVW > 195)
        for vi in vuln_instances:
            if spec.category_key == "UDO" and vi.sink_line >= LINE_THRESHOLD:
                errors.append(
                    f"UDO SINK line {vi.sink_line} >= {LINE_THRESHOLD} for {vi.instance_id}"
                )
            elif spec.category_key == "IVW" and vi.sink_line <= LINE_THRESHOLD:
                errors.append(
                    f"IVW SINK line {vi.sink_line} <= {LINE_THRESHOLD} for {vi.instance_id}"
                )

        # 5d. Safe invariant (UDO only)
        safe_errors = validate_safe_invariant(safe_source, vuln_instances[0].category if vuln_instances else "")
        errors.extend(safe_errors)

        # 6. Build ground truth rows
        gt_rows = build_ground_truth_rows(vuln_instances)
        all_gt_rows.extend(gt_rows)

        # 7. Write per-variant labels
        seq = int(spec.variant_id.replace("v", ""))
        variant_dir = output_dir / f"variant_{seq:03d}_{spec.variant_name}"

        # Per-variant ground truth
        write_ground_truth_csv(gt_rows, variant_dir / "ground_truth_labels.csv")

        # Flow labels
        category_en, _ = CATEGORY_MAP.get(spec.category_key, (spec.category_key, ""))
        category_prefix = category_en.split("_")[0]  # "unencrypted" / "weak" / "shared"
        flow_dir = variant_dir / "flow_labels"

        # Taint labels (from template result)
        if result.taint_flow:
            write_taint_labels_csv(result.taint_flow, flow_dir / f"{spec.category_key.lower()}_taint_labels.csv")
        else:
            # Generate minimal taint labels from markers
            taint_cps = _generate_basic_taint_flow(unsafe_source, vuln_instances, spec.category_key)
            write_taint_labels_csv(taint_cps, flow_dir / f"{spec.category_key.lower()}_taint_labels.csv")

        # Sanitizer labels (from template result)
        if result.sanitizers:
            write_sanitizer_labels_csv(result.sanitizers, flow_dir / f"{spec.category_key.lower()}_sanitizer_labels.csv")
        else:
            # Generate minimal sanitizer labels from markers
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
        )

    # 8. Write aggregated ground truth
    write_ground_truth_csv(all_gt_rows, output_dir / "ground_truth_labels.csv")

    # 9. Generate README
    generate_readme(VARIANTS, output_dir)

    # 10. Report
    print(f"\nDataset generated: {output_dir}")
    print(f"  Variants: {len(VARIANTS)}")
    print(f"  Total instances: {len(all_gt_rows)}")

    if errors:
        print(f"\nWARNINGS ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("  All validations passed.")


def _generate_basic_taint_flow(
    source: str,
    vuln_instances: list,
    category_key: str,
) -> list[TaintCheckpoint]:
    """Generate basic taint flow labels from resolved markers."""
    from labels import extract_markers
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
            cps.append(TaintCheckpoint(
                checkpoint_id=f"SOURCE:{vi.instance_id}",
                function=vi.function_name,
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
    from labels import extract_markers
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
            entries.append(SanitizerEntry(
                flow=flow_name,
                function=vi.function_name,
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
        default=Path("RQ3_Dataset"),
        help="Output directory (default: RQ3_Dataset)",
    )
    args = parser.parse_args()

    print(f"Scaffold: embedded (OP-TEE optee_examples/hello_world, BSD-2-Clause)")
    print(f"Output:   {args.output_dir}")
    print()

    generate_dataset(args.output_dir)


if __name__ == "__main__":
    main()
