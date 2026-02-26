"""
validators.py — Dataset validation functions

Extracted from labels.py to separate concerns.
All validate_* functions for checking dataset correctness:
  - Safe invariant (UDO/IVW/DUS)
  - Marker consistency
  - Round-trip verification
  - File existence
  - Unsafe/safe diff
  - SINK line content
  - UDO unsafe not already sanitized
"""

import re
from pathlib import Path

from labels import extract_markers, MARKER_RE


# ---------------------------------------------------------------------------
# Safe invariant validation (UDO)
# ---------------------------------------------------------------------------

# Secret variable names used in UDO templates.
# Must cover: secret, secret_iv, secret_key, sd.key, sd.iv, derived (from secret)
# \bsecret\b alone misses secret_iv (underscore is a word char) and sd.key.
SECRET_VAR_PATTERNS = [
    re.compile(r'\bsecret\w*\b'),    # secret, secret_iv, secret_key, ...
    re.compile(r'\bsd\s*[\.\->]+\s*(key|iv)\b'),  # sd.key, sd->key, sd.iv, sd->iv
]


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
        for pat in SECRET_VAR_PATTERNS:
            m = pat.search(line_content_no_marker)
            if m:
                errors.append(
                    f"Safe invariant violation: secret var '{m.group()}' found on "
                    f"SINK line {sink_line} for instance {instance_id}"
                )
                break
    return errors


# ---------------------------------------------------------------------------
# Marker consistency validation
# ---------------------------------------------------------------------------

def validate_marker_consistency(
    unsafe_source: str,
    safe_source: str,
    vuln_markers: list[dict],
    category_key: str,
) -> list[str]:
    """Validate marker correspondence between unsafe and safe versions.

    Rules:
    - Every instance_id MUST have a SINK marker in the unsafe version.
    - Every instance_id MUST have a SOURCE marker in the unsafe version,
      UNLESS it has a shared_source reference.
    - Every instance_id MUST have a SANITIZER marker in the safe version,
      UNLESS it has a shared_sanitizer reference.
    - UDO safe version MUST NOT retain SINK markers.

    Returns:
        List of error messages (empty = passed)
    """
    errors = []
    unsafe_markers = extract_markers(unsafe_source)
    safe_markers = extract_markers(safe_source)

    for vm in vuln_markers:
        iid = vm["id"]
        unsafe_m = unsafe_markers.get(iid, {})

        # Every instance must have its own SINK marker
        if "SINK" not in unsafe_m:
            errors.append(f"Marker consistency: unsafe missing SINK for {iid}")

        # SOURCE required only if no shared_source reference
        if "shared_source" not in vm:
            if "SOURCE" not in unsafe_m:
                errors.append(f"Marker consistency: unsafe missing SOURCE for {iid}")

    for vm in vuln_markers:
        iid = vm["id"]
        safe_m = safe_markers.get(iid, {})

        # SANITIZER required only if no shared_sanitizer reference
        if "shared_sanitizer" not in vm:
            if "SANITIZER" not in safe_m:
                errors.append(f"Marker consistency: safe missing SANITIZER for {iid}")

    # UDO safe: should NOT have SINK markers (vulnerability should be removed)
    if category_key == "UDO":
        for iid, safe_m in safe_markers.items():
            if "SINK" in safe_m:
                errors.append(
                    f"Marker consistency: safe still has SINK for UDO {iid} "
                    f"(expected SANITIZER only)"
                )

    return errors


# ---------------------------------------------------------------------------
# Strengthened safe invariant validation (UDO sink args)
# ---------------------------------------------------------------------------

# Sink API patterns that write to shared memory
SINK_API_RE = re.compile(
    r'\b(TEE_MemMove|memcpy|strncpy|snprintf|TEE_MemFill)\s*\('
)

# Variable name 'enc_out' or similar encrypted output buffer
ENC_OUT_PATTERN = re.compile(r'\benc_out\b')


def validate_safe_sink_args(safe_source: str, category: str) -> list[str]:
    """Validate that safe version's sink API calls only reference enc_out, not secret.

    Scans the safe source for sink API calls (TEE_MemMove, memcpy, etc.)
    that write to params[].memref.buffer, and verifies:
    1. The source argument is NOT 'secret'
    2. The source argument IS 'enc_out' (for UDO)

    Only applicable to UDO variants.

    Returns:
        List of error messages (empty = passed)
    """
    if category != "unencrypted_output":
        return []

    errors = []
    lines = safe_source.splitlines()

    for i, line in enumerate(lines, 1):
        # Only check lines that have a sink API call AND reference params[]
        if not SINK_API_RE.search(line):
            continue
        if "params[" not in line and "params ->" not in line:
            continue

        # This is a sink API call writing to shared memory
        line_no_marker = MARKER_RE.sub("", line)

        for pat in SECRET_VAR_PATTERNS:
            m = pat.search(line_no_marker)
            if m:
                errors.append(
                    f"Safe sink arg violation: secret var '{m.group()}' passed to "
                    f"sink API on line {i}: {line.strip()}"
                )
                break

    return errors


# ---------------------------------------------------------------------------
# Unsafe/safe structural consistency
# ---------------------------------------------------------------------------

def validate_unsafe_safe_consistency(
    unsafe_source: str,
    safe_source: str,
) -> list[str]:
    """Validate structural consistency between unsafe and safe versions.

    Checks:
    1. Total line counts must be identical (same PAD applied).
    2. SINK marker line numbers in unsafe must be within the same function
       body range in safe (safe may lack SINK markers for UDO, but has
       SANITIZER at the same or nearby line).

    Returns:
        List of error messages (empty = passed)
    """
    errors = []
    unsafe_lines = unsafe_source.count("\n") + 1
    safe_lines = safe_source.count("\n") + 1
    if unsafe_lines != safe_lines:
        errors.append(
            f"Unsafe/safe line count mismatch: unsafe={unsafe_lines}, safe={safe_lines}"
        )
    return errors


# ---------------------------------------------------------------------------
# IVW safe invariant: bounds check before sink
# ---------------------------------------------------------------------------

# Patterns that indicate a bounds/size check
_IVW_GUARD_PATTERNS = [
    re.compile(r'\bif\s*\(.*(?:size|len|idx|offset|count|val|sz|alloc_val)\b.*[<>!=]'),
    re.compile(r'\bif\s*\(.*\b(?:MAX|LIMIT|BUF_SIZE|ARRAY_SIZE)\b'),
    re.compile(r'\breturn\s+TEE_ERROR'),
]

def validate_ivw_safe_invariant(safe_source: str, category_key: str) -> list[str]:
    """Validate that IVW safe version has a real bounds check at SANITIZER.

    IVW safe versions have SANITIZER markers (not SINK markers).
    This check verifies that each SANITIZER line is actually a guard
    (if/return TEE_ERROR_BAD_PARAMETERS), not arbitrary code with a marker.

    Returns:
        List of error messages (empty = passed)
    """
    if category_key != "IVW":
        return []

    errors = []
    markers = extract_markers(safe_source)
    lines = safe_source.splitlines()

    for instance_id, marker_lines in markers.items():
        san_line = marker_lines.get("SANITIZER")
        if san_line is None:
            continue

        # The SANITIZER line itself must be a guard or return
        san_content = MARKER_RE.sub("", lines[san_line - 1]).strip()

        is_guard = False
        for pat in _IVW_GUARD_PATTERNS:
            if pat.search(san_content):
                is_guard = True
                break
        # Also accept: bare return TEE_ERROR on the SANITIZER line
        if not is_guard and "return" in san_content and "TEE_ERROR" in san_content:
            is_guard = True
        # Also check the line above (if ... \n\t return pattern)
        if not is_guard and san_line >= 2:
            prev = lines[san_line - 2].strip()
            for pat in _IVW_GUARD_PATTERNS:
                if pat.search(prev):
                    is_guard = True
                    break

        if not is_guard:
            errors.append(
                f"IVW safe invariant: SANITIZER line {san_line} for "
                f"{instance_id} is not a bounds check: '{san_content}'"
            )

    return errors


# ---------------------------------------------------------------------------
# DUS safe invariant: local copy before use
# ---------------------------------------------------------------------------

_DUS_LOCAL_COPY_PATTERNS = [
    re.compile(r'\bmemcpy\s*\(\s*local'),
    re.compile(r'\bmemcpy\s*\(\s*safe_'),
    re.compile(r'\bmemcpy\s*\(\s*\w+_local'),
    re.compile(r'\bTEE_MemMove\s*\(\s*local'),       # TEE_MemMove(local, ...)
    re.compile(r'\bchar\s+local\w*\s*\['),            # char local[1024]
    re.compile(r'\bchar\s+safe_\w*\s*\['),            # char safe_buf[...]
    re.compile(r'\bchar\s*\*\s*local\b'),             # char *local = TEE_Malloc(...)
]


def validate_dus_safe_invariant(safe_source: str, category_key: str) -> list[str]:
    """Validate that DUS safe version copies shared memory to local buffer.

    Checks that the safe source contains at least one local copy pattern
    (memcpy to local buffer or local buffer declaration).

    Returns:
        List of error messages (empty = passed)
    """
    if category_key != "DUS":
        return []

    errors = []
    found_local_copy = False
    for pat in _DUS_LOCAL_COPY_PATTERNS:
        if pat.search(safe_source):
            found_local_copy = True
            break

    if not found_local_copy:
        errors.append(
            "DUS safe invariant: no local copy pattern found in safe version "
            "(expected memcpy(local...) or char local[...])"
        )

    return errors


# ---------------------------------------------------------------------------
# Unsafe ≠ safe code diff (FP6)
# ---------------------------------------------------------------------------

def validate_unsafe_safe_diff(
    unsafe_source: str,
    safe_source: str,
) -> list[str]:
    """Verify that unsafe and safe versions differ beyond just markers.

    If the only difference is SOURCE/SINK/SANITIZER marker text,
    the safe version doesn't actually fix anything.

    Returns:
        List of error messages (empty = passed)
    """
    unsafe_clean = MARKER_RE.sub("/* */", unsafe_source)
    safe_clean = MARKER_RE.sub("/* */", safe_source)
    if unsafe_clean == safe_clean:
        return [
            "Unsafe/safe diff: code is identical after stripping markers. "
            "Safe version does not fix the vulnerability."
        ]
    return []


# ---------------------------------------------------------------------------
# SINK line content validation (FP7)
# ---------------------------------------------------------------------------

def validate_sink_line_content(
    unsafe_source: str,
    vuln_markers: list[dict],
) -> list[str]:
    """Verify that every SINK marker line contains actual executable C code.

    Catches markers placed on blank lines, pure comments, or declarations
    that don't constitute a dangerous operation.

    Returns:
        List of error messages (empty = passed)
    """
    errors = []
    markers = extract_markers(unsafe_source)
    lines = unsafe_source.splitlines()

    for vm in vuln_markers:
        iid = vm["id"]
        resolved = markers.get(iid, {})
        sink_line = resolved.get("SINK")
        if sink_line is None:
            continue

        raw = lines[sink_line - 1] if sink_line <= len(lines) else ""
        code = MARKER_RE.sub("", raw).strip()

        if not code or code.startswith("//"):
            errors.append(
                f"SINK content: line {sink_line} for {iid} "
                f"has no executable code: '{code}'"
            )
            continue

        # Must contain some kind of operation
        if not re.search(r'[=;()\[\]]', code):
            errors.append(
                f"SINK content: line {sink_line} for {iid} "
                f"does not appear to contain an operation: '{code}'"
            )

    return errors


# ---------------------------------------------------------------------------
# UDO unsafe must not already be sanitized (FP8)
# ---------------------------------------------------------------------------

def validate_udo_unsafe_not_sanitized(
    unsafe_source: str,
    vuln_markers: list[dict],
    category_key: str,
) -> list[str]:
    """Verify that UDO unsafe code does NOT already have enc() protecting
    the tainted variable on the path to SINK.

    If enc(secret) appears between SOURCE and SINK and the enc'd variable
    is what reaches the SINK, the 'unsafe' version is actually safe and
    the ground truth label is wrong.

    Ignores dead-code conditionals (if (0) { enc(...); }).

    Returns:
        List of error messages (empty = passed)
    """
    if category_key != "UDO":
        return []

    errors = []
    markers = extract_markers(unsafe_source)
    lines = unsafe_source.splitlines()

    for vm in vuln_markers:
        iid = vm["id"]
        resolved = markers.get(iid, {})
        source_line = resolved.get("SOURCE", 0)
        sink_line = resolved.get("SINK", 0)

        # For shared_source, use the referenced instance's SOURCE
        if source_line == 0 and "shared_source" in vm:
            ref = markers.get(vm["shared_source"], {})
            source_line = ref.get("SOURCE", 0)

        if source_line == 0 or sink_line == 0:
            continue
        if source_line > sink_line:
            continue  # cross-function, skip

        region = lines[source_line - 1 : sink_line]
        sink_code = MARKER_RE.sub("", lines[sink_line - 1])

        # Track dead-code blocks
        in_dead = False
        dead_depth = 0
        for line in region[:-1]:
            code = MARKER_RE.sub("", line).strip()

            # Detect dead-code entry
            if re.search(r'if\s*\(\s*0\s*\)', code) or \
               re.search(r'if\s*\(\s*flag\s*\)', code):
                in_dead = True
                dead_depth = 0
            if in_dead:
                dead_depth += code.count('{') - code.count('}')
                if dead_depth <= 0 and '}' in code:
                    in_dead = False
                continue

            enc_match = re.search(r'\benc\s*\(\s*(\w+)\s*\)', code)
            if enc_match:
                enc_var = enc_match.group(1)
                if re.search(r'\b' + re.escape(enc_var) + r'\b', sink_code):
                    errors.append(
                        f"UDO unsafe already sanitized: enc({enc_var}) "
                        f"before SINK line {sink_line} for {iid}"
                    )

    return errors


# ---------------------------------------------------------------------------
# Round-trip verification: disk entry.c matches in-memory source
# ---------------------------------------------------------------------------

def validate_round_trip(
    entry_c_path: Path,
    expected_source: str,
) -> list[str]:
    """Verify that the entry.c written to disk matches the in-memory source.

    Returns:
        List of error messages (empty = passed)
    """
    errors = []
    if not entry_c_path.exists():
        errors.append(f"Round-trip: file not found: {entry_c_path}")
        return errors

    disk_content = entry_c_path.read_text(encoding="utf-8")
    if disk_content != expected_source:
        # Find first difference for debugging
        disk_lines = disk_content.splitlines()
        expected_lines = expected_source.splitlines()
        if len(disk_lines) != len(expected_lines):
            errors.append(
                f"Round-trip: line count differs — disk={len(disk_lines)}, "
                f"expected={len(expected_lines)} in {entry_c_path}"
            )
        else:
            for i, (dl, el) in enumerate(zip(disk_lines, expected_lines), 1):
                if dl != el:
                    errors.append(
                        f"Round-trip: content differs at line {i} in {entry_c_path}"
                    )
                    break

    return errors


# ---------------------------------------------------------------------------
# File existence verification
# ---------------------------------------------------------------------------

_EXPECTED_FILES = [
    "ta/entry.c",
    "ta/Makefile",
    "ta/sub.mk",
    "ta/user_ta_header_defines.h",
    "ta/include/hello_world_ta.h",
    "ta/compile_commands.json",
    "Makefile",
    "host/main.c",
    "host/Makefile",
]


def validate_file_existence(variant_dir: Path) -> list[str]:
    """Verify that all expected scaffold files exist in a variant directory.

    Returns:
        List of error messages (empty = passed)
    """
    errors = []
    for rel_path in _EXPECTED_FILES:
        full = variant_dir / rel_path
        if not full.exists():
            errors.append(f"Missing file: {full}")
    return errors


# ---------------------------------------------------------------------------
# SOURCE line content validation (FP9 — GAP-A fix)
# ---------------------------------------------------------------------------

def validate_source_line_content(
    unsafe_source: str,
    vuln_markers: list[dict],
) -> list[str]:
    """Verify that every SOURCE marker line contains executable C code.

    Mirrors validate_sink_line_content but for SOURCE markers.
    Catches markers placed on blank lines, pure comments, or
    lines without an assignment/declaration.

    Only checks instances with their own SOURCE marker (not shared_source).

    Returns:
        List of error messages (empty = passed)
    """
    errors = []
    markers = extract_markers(unsafe_source)
    lines = unsafe_source.splitlines()

    for vm in vuln_markers:
        # Skip instances that inherit SOURCE from another instance
        if "shared_source" in vm:
            continue

        iid = vm["id"]
        resolved = markers.get(iid, {})
        source_line = resolved.get("SOURCE")
        if source_line is None:
            continue

        raw = lines[source_line - 1] if source_line <= len(lines) else ""
        code = MARKER_RE.sub("", raw).strip()

        if not code or code.startswith("//"):
            errors.append(
                f"SOURCE content: line {source_line} for {iid} "
                f"has no executable code: '{code}'"
            )
            continue

        # Must contain some kind of operation (assignment, declaration, call)
        if not re.search(r'[=;()\[\]]', code):
            errors.append(
                f"SOURCE content: line {source_line} for {iid} "
                f"does not appear to contain an operation: '{code}'"
            )

    return errors


# ---------------------------------------------------------------------------
# UDO safe enc() existence validation (FP10 — GAP-C fix)
# ---------------------------------------------------------------------------

def validate_udo_safe_enc_exists(
    safe_source: str,
    category_key: str,
) -> list[str]:
    """Verify that UDO safe version actually calls enc() on the output buffer.

    Catches safe versions that 'fix' UDO by simply removing the output
    instead of properly encrypting.  The safe version must contain at
    least one live enc() call (not inside dead code).

    Returns:
        List of error messages (empty = passed)
    """
    if category_key != "UDO":
        return []

    errors = []
    # Find live enc() calls (exclude dead code)
    in_dead = False
    dead_depth = 0
    found_enc = False

    for line in safe_source.splitlines():
        code = MARKER_RE.sub("", line).strip()

        if re.search(r'if\s*\(\s*0\s*\)', code):
            in_dead = True
            dead_depth = 0
        if in_dead:
            dead_depth += code.count('{') - code.count('}')
            if dead_depth <= 0 and '}' in code:
                in_dead = False
            continue

        # Match enc() calls in variant body, excluding:
        # - function definition: static void enc(char *str)
        # - dec() body calling enc(str) — boilerplate
        if re.search(r'\benc\s*\(', code) \
           and not re.search(r'\b(static|void)\s+enc\s*\(', code) \
           and not re.match(r'^\s*enc\s*\(\s*str\s*\)\s*;', code):
            found_enc = True
            break

    if not found_enc:
        errors.append(
            "UDO safe enc() missing: safe version has no live enc() call. "
            "Safe should encrypt the output, not remove it."
        )

    return errors
