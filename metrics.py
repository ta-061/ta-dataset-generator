"""
metrics.py — Structural shift quantification

Extracted from main.py to separate concerns.
Contains the feature taxonomy, per-variant feature sets,
and Jaccard/novelty score computation.
"""

# ---------------------------------------------------------------------------
# Structural Shift Quantification
# ---------------------------------------------------------------------------

# Each feature belongs to a dimension (D1-D7).
# "in_original" = True  → present in the original bad-partitioning benchmark
# "in_original" = False → novel in RQ3 (= structural shift)

FEATURE_TAXONOMY: dict[str, dict] = {
    # --- D1: Call depth (from command handler) ---
    "D1_depth_0":           {"dim": "D1_call_depth", "label": "depth 0 (inline)",        "in_original": True},
    "D1_depth_1":           {"dim": "D1_call_depth", "label": "depth 1",                 "in_original": True},
    "D1_depth_2":           {"dim": "D1_call_depth", "label": "depth 2",                 "in_original": True},
    "D1_depth_3":           {"dim": "D1_call_depth", "label": "depth 3+",                "in_original": False},
    # --- D2: Data indirection ---
    "D2_direct_char":       {"dim": "D2_data_indirection", "label": "direct char[]",             "in_original": True},
    "D2_tee_param_member":  {"dim": "D2_data_indirection", "label": "TEE_Param member",          "in_original": True},
    "D2_void_ptr":          {"dim": "D2_data_indirection", "label": "void* pointer",             "in_original": True},
    "D2_simple_arith":      {"dim": "D2_data_indirection", "label": "simple index arith (a-3)",  "in_original": True},
    "D2_param_forward":     {"dim": "D2_data_indirection", "label": "parameter forwarding",      "in_original": True},
    "D2_double_ptr":        {"dim": "D2_data_indirection", "label": "double pointer (char**)",   "in_original": False},
    "D2_user_struct":       {"dim": "D2_data_indirection", "label": "user-defined struct member", "in_original": False},
    "D2_typedef_alias":     {"dim": "D2_data_indirection", "label": "typedef alias",             "in_original": False},
    "D2_ptr_arith":         {"dim": "D2_data_indirection", "label": "pointer arithmetic *(b+o)", "in_original": False},
    "D2_multi_step_idx":    {"dim": "D2_data_indirection", "label": "multi-step computed index", "in_original": False},
    "D2_xor_derivation":    {"dim": "D2_data_indirection", "label": "XOR/shift derivation",     "in_original": False},
    # --- D3: Control flow ---
    "D3_linear":            {"dim": "D3_control_flow", "label": "linear",                  "in_original": True},
    "D3_if_early_return":   {"dim": "D3_control_flow", "label": "if / early return",       "in_original": True},
    "D3_for_loop":          {"dim": "D3_control_flow", "label": "for-loop",                "in_original": True},
    "D3_switch_dispatch":   {"dim": "D3_control_flow", "label": "switch (entry dispatch)",  "in_original": True},
    "D3_while_loop":        {"dim": "D3_control_flow", "label": "while-loop",              "in_original": False},
    "D3_switch_per_case":   {"dim": "D3_control_flow", "label": "switch per-case sinks",   "in_original": False},
    "D3_dead_code":         {"dim": "D3_control_flow", "label": "dead-code conditional",   "in_original": False},
    "D3_nested_if_scope":   {"dim": "D3_control_flow", "label": "nested if/else scope",    "in_original": False},
    "D3_loop_over_params":  {"dim": "D3_control_flow", "label": "loop over params[]",      "in_original": False},
    # --- D4: Sink API ---
    "D4_TEE_MemMove":       {"dim": "D4_sink_api", "label": "TEE_MemMove",      "in_original": True},
    "D4_snprintf":          {"dim": "D4_sink_api", "label": "snprintf",          "in_original": True},
    "D4_TEE_Malloc":        {"dim": "D4_sink_api", "label": "TEE_Malloc",        "in_original": True},
    "D4_strcmp":             {"dim": "D4_sink_api", "label": "strcmp",            "in_original": True},
    "D4_TEE_MemCompare":    {"dim": "D4_sink_api", "label": "TEE_MemCompare",   "in_original": True},
    "D4_array_index":       {"dim": "D4_sink_api", "label": "array[]",          "in_original": True},
    "D4_value_a_assign":    {"dim": "D4_sink_api", "label": "value.a=",         "in_original": True},
    "D4_dec":               {"dim": "D4_sink_api", "label": "dec()",            "in_original": True},
    "D4_memcpy":            {"dim": "D4_sink_api", "label": "memcpy",           "in_original": False},
    "D4_strncpy":           {"dim": "D4_sink_api", "label": "strncpy",          "in_original": False},
    "D4_memcmp":            {"dim": "D4_sink_api", "label": "memcmp (libc)",    "in_original": False},
    "D4_ptr_deref":         {"dim": "D4_sink_api", "label": "pointer deref",    "in_original": False},
    # --- D5: Guard flaw type ---
    "D5_correct_or_absent": {"dim": "D5_guard_flaw", "label": "correct / absent",        "in_original": True},
    "D5_off_by_one":        {"dim": "D5_guard_flaw", "label": "off-by-one",              "in_original": False},
    "D5_wrong_operator":    {"dim": "D5_guard_flaw", "label": "wrong logical operator",  "in_original": False},
    "D5_signed_unsigned":   {"dim": "D5_guard_flaw", "label": "signed/unsigned cast",    "in_original": False},
    "D5_unreachable":       {"dim": "D5_guard_flaw", "label": "unreachable scope",       "in_original": False},
    "D5_dead_sanitizer":    {"dim": "D5_guard_flaw", "label": "dead-code sanitizer",     "in_original": False},
    "D5_partial_encrypt":   {"dim": "D5_guard_flaw", "label": "partial encryption",      "in_original": False},
    "D5_wrapper_hide":      {"dim": "D5_guard_flaw", "label": "wrapper hiding taint",    "in_original": False},
    # --- D6: TOCTOU mechanism ---
    "D6_TEE_Wait":          {"dim": "D6_toctou", "label": "TEE_Wait",                   "in_original": True},
    "D6_ptr_alias":         {"dim": "D6_toctou", "label": "pointer aliasing",           "in_original": True},
    "D6_local_copy":        {"dim": "D6_toctou", "label": "local copy (safe pattern)",  "in_original": True},
    "D6_func_call_gap":     {"dim": "D6_toctou", "label": "function call gap",          "in_original": False},
    "D6_loop_reread":       {"dim": "D6_toctou", "label": "loop re-read",               "in_original": False},
    "D6_callback":          {"dim": "D6_toctou", "label": "callback indirect",          "in_original": False},
    "D6_partial_copy":      {"dim": "D6_toctou", "label": "partial copy / split access", "in_original": False},
    "D6_return_ignored":    {"dim": "D6_toctou", "label": "return value ignored",       "in_original": False},
    "D6_shm_reread":        {"dim": "D6_toctou", "label": "explicit shm re-read",       "in_original": False},
    # --- D7: Language features ---
    "D7_none":              {"dim": "D7_language", "label": "none (plain C)",     "in_original": True},
    "D7_user_typedef":      {"dim": "D7_language", "label": "user-defined typedef", "in_original": False},
    "D7_func_ptr":          {"dim": "D7_language", "label": "function pointer",   "in_original": False},
    "D7_callback":          {"dim": "D7_language", "label": "callback pattern",   "in_original": False},
}

# Per-variant feature sets — each variant's active structural features
VARIANT_FEATURES: dict[str, set[str]] = {
    "v001": {"D1_depth_3", "D2_direct_char", "D2_param_forward", "D3_linear",
             "D4_memcpy", "D4_snprintf", "D5_correct_or_absent", "D7_none"},
    "v002": {"D1_depth_1", "D2_user_struct", "D3_linear",
             "D4_TEE_MemMove", "D4_snprintf", "D5_correct_or_absent", "D7_none"},
    "v003": {"D1_depth_0", "D2_direct_char", "D3_switch_per_case",
             "D4_memcpy", "D4_strncpy", "D4_snprintf", "D5_correct_or_absent", "D7_none"},
    "v004": {"D1_depth_1", "D2_double_ptr", "D3_linear",
             "D4_snprintf", "D4_TEE_MemMove", "D5_correct_or_absent", "D7_none"},
    "v005": {"D1_depth_0", "D2_direct_char", "D3_dead_code",
             "D4_TEE_MemMove", "D4_snprintf", "D5_dead_sanitizer", "D7_none"},
    "v006": {"D1_depth_1", "D2_xor_derivation", "D3_for_loop",
             "D4_memcpy", "D4_value_a_assign", "D5_correct_or_absent", "D7_none"},
    "v007": {"D1_depth_0", "D2_direct_char", "D3_loop_over_params",
             "D4_TEE_MemMove", "D5_correct_or_absent", "D7_none"},
    "v008": {"D1_depth_0", "D2_direct_char", "D3_linear",
             "D4_snprintf", "D4_TEE_MemMove", "D5_partial_encrypt", "D7_none"},
    "v009": {"D1_depth_0", "D2_ptr_arith", "D2_tee_param_member", "D3_linear",
             "D4_ptr_deref", "D5_correct_or_absent", "D7_none"},
    "v010": {"D1_depth_0", "D2_tee_param_member", "D3_while_loop",
             "D4_array_index", "D4_TEE_Malloc", "D5_correct_or_absent", "D7_none"},
    "v011": {"D1_depth_0", "D2_tee_param_member", "D3_if_early_return",
             "D4_TEE_Malloc", "D4_TEE_MemMove", "D5_signed_unsigned", "D7_none"},
    "v012": {"D1_depth_0", "D2_tee_param_member", "D3_nested_if_scope",
             "D4_array_index", "D4_TEE_Malloc", "D5_unreachable", "D7_none"},
    "v013": {"D1_depth_0", "D2_tee_param_member", "D3_if_early_return",
             "D4_array_index", "D5_off_by_one", "D7_none"},
    "v014": {"D1_depth_0", "D2_multi_step_idx", "D2_tee_param_member", "D3_linear",
             "D4_array_index", "D4_TEE_Malloc", "D5_correct_or_absent", "D7_none"},
    "v015": {"D1_depth_0", "D2_tee_param_member", "D3_if_early_return",
             "D4_array_index", "D4_TEE_MemMove", "D5_wrong_operator", "D7_none"},
    "v016": {"D1_depth_1", "D2_tee_param_member", "D3_linear",
             "D4_TEE_Malloc", "D4_array_index", "D5_wrapper_hide", "D7_none"},
    "v017": {"D1_depth_0", "D2_typedef_alias", "D2_void_ptr", "D3_if_early_return",
             "D4_strcmp", "D4_dec", "D4_TEE_MemCompare", "D5_correct_or_absent",
             "D6_TEE_Wait", "D6_ptr_alias", "D7_user_typedef"},
    "v018": {"D1_depth_0", "D2_user_struct", "D2_void_ptr", "D3_if_early_return",
             "D4_strcmp", "D4_dec", "D5_correct_or_absent",
             "D6_TEE_Wait", "D6_ptr_alias", "D7_none"},
    "v019": {"D1_depth_0", "D2_void_ptr", "D2_tee_param_member", "D3_if_early_return",
             "D4_strcmp", "D4_TEE_MemCompare", "D4_dec", "D5_correct_or_absent",
             "D6_TEE_Wait", "D6_shm_reread", "D7_none"},
    "v020": {"D1_depth_1", "D2_void_ptr", "D2_tee_param_member", "D3_nested_if_scope",
             "D4_strcmp", "D4_dec", "D5_correct_or_absent",
             "D6_func_call_gap", "D6_shm_reread", "D7_none"},
    "v021": {"D1_depth_0", "D2_void_ptr", "D3_while_loop",
             "D4_strcmp", "D4_dec", "D5_correct_or_absent",
             "D6_loop_reread", "D6_ptr_alias", "D7_none"},
    "v022": {"D1_depth_1", "D2_void_ptr", "D2_tee_param_member", "D3_if_early_return",
             "D4_strcmp", "D4_dec", "D5_correct_or_absent",
             "D6_callback", "D6_shm_reread", "D7_user_typedef", "D7_func_ptr", "D7_callback"},
    "v023": {"D1_depth_0", "D2_void_ptr", "D2_tee_param_member", "D3_if_early_return",
             "D4_memcmp", "D4_dec", "D5_correct_or_absent",
             "D6_func_call_gap", "D6_shm_reread", "D7_none"},
    "v024": {"D1_depth_0", "D2_void_ptr", "D2_ptr_arith", "D3_if_early_return",
             "D4_strcmp", "D4_dec", "D5_correct_or_absent",
             "D6_partial_copy", "D6_shm_reread", "D7_none"},
    "v025": {"D1_depth_1", "D2_void_ptr", "D3_if_early_return",
             "D4_strcmp", "D4_dec", "D5_correct_or_absent",
             "D6_func_call_gap", "D6_return_ignored", "D7_none"},
}

# Dimension labels for display
DIMENSION_LABELS = {
    "D1_call_depth":      "D1: Call depth",
    "D2_data_indirection": "D2: Data indirection",
    "D3_control_flow":    "D3: Control flow",
    "D4_sink_api":        "D4: Sink API",
    "D5_guard_flaw":      "D5: Guard flaw type",
    "D6_toctou":          "D6: TOCTOU mechanism",
    "D7_language":        "D7: Language features",
}


def compute_structural_shift_metrics() -> dict:
    """Compute quantitative structural shift metrics.

    Returns dict with:
        - per_dim: per-dimension counts (original vs novel)
        - per_variant: per-variant novelty scores
        - aggregate: global Jaccard distance and counts
    """
    # Original benchmark feature set
    orig_features = {fid for fid, info in FEATURE_TAXONOMY.items() if info["in_original"]}
    novel_features = {fid for fid, info in FEATURE_TAXONOMY.items() if not info["in_original"]}

    # Union of all features used by RQ3 variants
    rq3_used = set()
    for vf in VARIANT_FEATURES.values():
        rq3_used |= vf

    rq3_novel_used = rq3_used & novel_features
    rq3_shared = rq3_used & orig_features
    union_all = orig_features | rq3_used

    # Jaccard distance = 1 - |intersection| / |union|
    jaccard = 1.0 - len(rq3_shared) / len(union_all) if union_all else 0.0

    # Per-dimension
    dims = {}
    for dim_key, dim_label in DIMENSION_LABELS.items():
        dim_features = {fid for fid, info in FEATURE_TAXONOMY.items()
                        if info["dim"] == dim_key}
        dim_orig = {fid for fid in dim_features
                    if FEATURE_TAXONOMY[fid]["in_original"]}
        dim_novel = dim_features - dim_orig
        dim_rq3_novel = dim_novel & rq3_used
        dims[dim_key] = {
            "label": dim_label,
            "n_original": len(dim_orig),
            "n_novel_defined": len(dim_novel),
            "n_novel_used": len(dim_rq3_novel),
            "n_total": len(dim_features),
            "expansion": (len(dim_orig) + len(dim_rq3_novel)) / len(dim_orig)
                         if dim_orig else float("inf"),
        }

    # Per-variant
    per_variant = {}
    for vid, vf in sorted(VARIANT_FEATURES.items()):
        v_novel = vf & novel_features
        v_orig = vf & orig_features
        total = len(vf)
        novelty_score = len(v_novel) / total if total else 0.0
        per_variant[vid] = {
            "n_total": total,
            "n_novel": len(v_novel),
            "n_original": len(v_orig),
            "novelty_score": novelty_score,
            "novel_features": sorted(v_novel),
        }

    return {
        "per_dim": dims,
        "per_variant": per_variant,
        "aggregate": {
            "n_features_total": len(FEATURE_TAXONOMY),
            "n_original": len(orig_features),
            "n_novel_defined": len(novel_features),
            "n_rq3_used": len(rq3_used),
            "n_rq3_novel_used": len(rq3_novel_used),
            "n_rq3_shared": len(rq3_shared),
            "jaccard_distance": jaccard,
            "novel_ratio": len(rq3_novel_used) / len(rq3_used) if rq3_used else 0.0,
        },
    }
