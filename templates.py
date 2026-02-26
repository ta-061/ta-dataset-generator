"""
templates.py — 25 template functions for RQ3 dataset generation.

Each template function returns a TemplateResult containing:
- unsafe_body / safe_body: C function code for the variant
- vuln_markers: list of {"id": "vNNN-iNN", "function": "func_name",
                          "shared_source": "vNNN-iNN",    (optional)
                          "shared_sanitizer": "vNNN-iNN"}  (optional)
- taint_flow: list of TaintCheckpoint definitions
- sanitizers: list of SanitizerEntry definitions
- param_types_hex: TEE_PARAM_TYPES value for the host side

Conventions:
- 1 line = 1 marker.  When multiple instances share the same SOURCE or
  SANITIZER, only i01 carries the marker in C code; i02+ reference i01 via
  shared_source / shared_sanitizer in vuln_markers.  resolve_vuln_instances()
  inherits the line number from the referenced instance.
- UDO: secret[] / enc_out[] separation; safe version uses enc_out only at sink
- IVW: safe version adds proper bounds check before sink
- DUS: safe version copies shm to local buffer before validation+use
"""

from dataclasses import dataclass, field
from labels import TaintCheckpoint, SanitizerEntry


@dataclass
class TemplateResult:
    unsafe_body: str
    safe_body: str
    vuln_markers: list[dict]
    taint_flow: list[TaintCheckpoint] = field(default_factory=list)
    sanitizers: list[SanitizerEntry] = field(default_factory=list)
    param_types_hex: int = 0


# ===========================================================================
# UDO Templates (v001 - v008)
# ===========================================================================

def tpl_v001_udo_deep_call_chain() -> TemplateResult:
    """UDO: 3-level helper function chain before sink reaches shared memory."""
    unsafe = """\
static void helper_level1(char *dest, size_t dest_size, const char *data, size_t len)
{
\tmemcpy(dest, data, len); /* SINK:v001-i01 */
}

static void helper_level2(char *out_buf, size_t out_size, const char *src, size_t src_len)
{
\thelper_level1(out_buf, out_size, src, src_len);
}

static void helper_level3(TEE_Param params[4])
{
\tchar secret[64] = "TopSecretKey12345"; /* SOURCE:v001-i01 */
\thelper_level2(params[1].memref.buffer, params[1].memref.size,
\t              secret, strlen(secret));
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "key=%s", secret); /* SINK:v001-i02 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\thelper_level3(params);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static void helper_level1(char *dest, size_t dest_size, const char *data, size_t len)
{
\tmemcpy(dest, data, len);
}

static void helper_level2(char *out_buf, size_t out_size, const char *src, size_t src_len)
{
\thelper_level1(out_buf, out_size, src, src_len);
}

static void helper_level3(TEE_Param params[4])
{
\tchar secret[64] = "TopSecretKey12345";
\tchar enc_out[64];
\tmemcpy(enc_out, secret, strlen(secret) + 1);
\tenc(enc_out); /* SANITIZER:v001-i01 */
\thelper_level2(params[1].memref.buffer, params[1].memref.size,
\t              enc_out, strlen(enc_out));
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "key=%s", enc_out);
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\thelper_level3(params);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v001-i01", "function": "helper_level1"},
            {"id": "v001-i02", "function": "helper_level3",
             "shared_source": "v001-i01", "shared_sanitizer": "v001-i01"},
        ],
        param_types_hex=0x0660,
    )


def tpl_v002_udo_struct_member() -> TemplateResult:
    """UDO: Secret stored in struct, accessed via -> member."""
    unsafe = """\
struct secret_data {
\tchar key[64];
\tchar iv[32];
\tint version;
};

static void output_secret(TEE_Param params[4], struct secret_data *sd)
{
\tTEE_MemMove(params[1].memref.buffer, sd->key, strlen(sd->key)); /* SINK:v002-i01 */
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "v%d:%s", sd->version, sd->iv); /* SINK:v002-i02 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tstruct secret_data sd;
\tmemcpy(sd.key, "AES256KEY_SECRET", 17); /* SOURCE:v002-i01 */
\tmemcpy(sd.iv, "INIT_VECTOR_1234", 17); /* SOURCE:v002-i02 */
\tsd.version = 1;
\toutput_secret(params, &sd);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
struct secret_data {
\tchar key[64];
\tchar iv[32];
\tint version;
};

static void output_secret(TEE_Param params[4], struct secret_data *sd)
{
\tchar enc_out_key[64];
\tchar enc_out_iv[32];
\tmemcpy(enc_out_key, sd->key, strlen(sd->key) + 1);
\tenc(enc_out_key); /* SANITIZER:v002-i01 */
\tmemcpy(enc_out_iv, sd->iv, strlen(sd->iv) + 1);
\tenc(enc_out_iv); /* SANITIZER:v002-i02 */
\tTEE_MemMove(params[1].memref.buffer, enc_out_key, strlen(enc_out_key));
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "v%d:%s", sd->version, enc_out_iv);
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tstruct secret_data sd;
\tmemcpy(sd.key, "AES256KEY_SECRET", 17);
\tmemcpy(sd.iv, "INIT_VECTOR_1234", 17);
\tsd.version = 1;
\toutput_secret(params, &sd);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v002-i01", "function": "output_secret"},
            {"id": "v002-i02", "function": "output_secret"},
        ],
        param_types_hex=0x0660,
    )


def tpl_v003_udo_switch_dispatch() -> TemplateResult:
    """UDO: Different sink APIs dispatched via switch-case."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "SwitchSecret999"; /* SOURCE:v003-i01 */
\tswitch (params[0].value.a) {
\tcase 0:
\t\tmemcpy(params[1].memref.buffer, secret, strlen(secret)); /* SINK:v003-i01 */
\t\tbreak;
\tcase 1:
\t\tstrncpy(params[1].memref.buffer, secret, params[1].memref.size); /* SINK:v003-i02 */
\t\tbreak;
\tdefault:
\t\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t\t         "%s", secret); /* SINK:v003-i03 */
\t\tbreak;
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "SwitchSecret999";
\tchar enc_out[64];
\tmemcpy(enc_out, secret, strlen(secret) + 1);
\tenc(enc_out); /* SANITIZER:v003-i01 */
\tswitch (params[0].value.a) {
\tcase 0:
\t\tmemcpy(params[1].memref.buffer, enc_out, strlen(enc_out));
\t\tbreak;
\tcase 1:
\t\tstrncpy(params[1].memref.buffer, enc_out, params[1].memref.size);
\t\tbreak;
\tdefault:
\t\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t\t         "%s", enc_out);
\t\tbreak;
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v003-i01", "function": "cmd_process"},
            {"id": "v003-i02", "function": "cmd_process",
             "shared_source": "v003-i01", "shared_sanitizer": "v003-i01"},
            {"id": "v003-i03", "function": "cmd_process",
             "shared_source": "v003-i01", "shared_sanitizer": "v003-i01"},
        ],
        param_types_hex=0x0660,
    )


def tpl_v004_udo_double_pointer() -> TemplateResult:
    """UDO: char** double pointer indirection before output."""
    unsafe = """\
static void write_via_ptr(char **pp, TEE_Param params[4])
{
\tsnprintf(params[1].memref.buffer, params[1].memref.size,
\t         "data=%s", *pp); /* SINK:v004-i01 */
\tTEE_MemMove(params[2].memref.buffer, *pp, strlen(*pp)); /* SINK:v004-i02 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "DoublePtr_Key"; /* SOURCE:v004-i01 */
\tchar *p = secret;
\tchar **pp = &p;
\twrite_via_ptr(pp, params);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static void write_via_ptr(char **pp, TEE_Param params[4])
{
\tchar enc_out[64];
\tmemcpy(enc_out, *pp, strlen(*pp) + 1);
\tenc(enc_out); /* SANITIZER:v004-i01 */
\tsnprintf(params[1].memref.buffer, params[1].memref.size,
\t         "data=%s", enc_out);
\tTEE_MemMove(params[2].memref.buffer, enc_out, strlen(enc_out));
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "DoublePtr_Key";
\tchar *p = secret;
\tchar **pp = &p;
\twrite_via_ptr(pp, params);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v004-i01", "function": "write_via_ptr"},
            {"id": "v004-i02", "function": "write_via_ptr",
             "shared_source": "v004-i01", "shared_sanitizer": "v004-i01"},
        ],
        param_types_hex=0x0660,
    )


def tpl_v005_udo_conditional_encrypt() -> TemplateResult:
    """UDO: enc() inside always-false conditional (dead code sanitizer)."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "ConditionalKey"; /* SOURCE:v005-i01 */
\tint flag = 0;
\tif (flag) {
\t\tenc(secret);
\t}
\tTEE_MemMove(params[1].memref.buffer, secret, strlen(secret)); /* SINK:v005-i01 */
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "%s", secret); /* SINK:v005-i02 */
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "ConditionalKey";
\tchar enc_out[64];
\tmemcpy(enc_out, secret, strlen(secret) + 1);
\tenc(enc_out); /* SANITIZER:v005-i01 */
\tTEE_MemMove(params[1].memref.buffer, enc_out, strlen(enc_out));
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "%s", enc_out);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v005-i01", "function": "cmd_process"},
            {"id": "v005-i02", "function": "cmd_process",
             "shared_source": "v005-i01", "shared_sanitizer": "v005-i01"},
        ],
        param_types_hex=0x0660,
    )


def tpl_v006_udo_xor_derivation() -> TemplateResult:
    """UDO: Secret XOR/shifted before output (data still sensitive)."""
    unsafe = """\
static void derive_and_output(TEE_Param params[4])
{
\tchar secret[64] = "XorDeriveKey567"; /* SOURCE:v006-i01 */
\tchar derived[64];
\tfor (int i = 0; i < (int)strlen(secret); i++) {
\t\tderived[i] = secret[i] ^ 0x55;
\t}
\tderived[strlen(secret)] = '\\0';
\tmemcpy(params[1].memref.buffer, derived, strlen(derived)); /* SINK:v006-i01 */
\tparams[0].value.a = (uint32_t)(secret[0] << 8 | secret[1]); /* SINK:v006-i02 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tderive_and_output(params);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static void derive_and_output(TEE_Param params[4])
{
\tchar secret[64] = "XorDeriveKey567";
\tchar derived[64];
\tfor (int i = 0; i < (int)strlen(secret); i++) {
\t\tderived[i] = secret[i] ^ 0x55;
\t}
\tderived[strlen(secret)] = '\\0';
\tchar enc_out[64];
\tmemcpy(enc_out, derived, strlen(derived) + 1);
\tenc(enc_out); /* SANITIZER:v006-i01 */
\tmemcpy(params[1].memref.buffer, enc_out, strlen(enc_out));
\tparams[0].value.a = 0; /* SANITIZER:v006-i02 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tderive_and_output(params);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v006-i01", "function": "derive_and_output"},
            {"id": "v006-i02", "function": "derive_and_output",
             "shared_source": "v006-i01"},
        ],
        param_types_hex=0x0030,
    )


def tpl_v007_udo_loop_multi_buffer() -> TemplateResult:
    """UDO: Loop over params[] writing secrets to multiple buffers."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "LoopMultiKey"; /* SOURCE:v007-i01 */
\tfor (int i = 0; i < 3; i++) {
\t\tTEE_MemMove(params[i].memref.buffer, secret, strlen(secret)); /* SINK:v007-i01 */
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "LoopMultiKey";
\tchar enc_out[64];
\tmemcpy(enc_out, secret, strlen(secret) + 1);
\tenc(enc_out); /* SANITIZER:v007-i01 */
\tfor (int i = 0; i < 3; i++) {
\t\tTEE_MemMove(params[i].memref.buffer, enc_out, strlen(enc_out));
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v007-i01", "function": "cmd_process"},
        ],
        param_types_hex=0x0666,
    )


def tpl_v008_udo_partial_encrypt() -> TemplateResult:
    """UDO: Key encrypted but IV leaked in same output."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "PartialKey_ABC";
\tchar secret_iv[32] = "IV_LEAKED_XYZ"; /* SOURCE:v008-i01 */
\tenc(secret);
\tTEE_MemMove(params[1].memref.buffer, secret, strlen(secret));
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "%s", secret_iv); /* SINK:v008-i01 */
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar secret[64] = "PartialKey_ABC";
\tchar secret_iv[32] = "IV_LEAKED_XYZ";
\tchar enc_out[64];
\tchar enc_out_iv[32];
\tmemcpy(enc_out, secret, strlen(secret) + 1);
\tenc(enc_out);
\tmemcpy(enc_out_iv, secret_iv, strlen(secret_iv) + 1);
\tenc(enc_out_iv); /* SANITIZER:v008-i01 */
\tTEE_MemMove(params[1].memref.buffer, enc_out, strlen(enc_out));
\tsnprintf(params[2].memref.buffer, params[2].memref.size,
\t         "%s", enc_out_iv);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v008-i01", "function": "cmd_process"},
        ],
        param_types_hex=0x0660,
    )


# ===========================================================================
# IVW Templates (v009 - v016)
# ===========================================================================

def tpl_v009_ivw_pointer_arith() -> TemplateResult:
    """IVW: *(base + offset) instead of arr[idx] with untrusted offset."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar *str = TEE_Malloc(1000, 0);
\tint offset = params[0].value.a; /* SOURCE:v009-i01 */
\t*(str + offset) = 'A'; /* SINK:v009-i01 */
\tchar val = *(str + offset - 1); /* SINK:v009-i02 */
\t(void)val;
\tTEE_Free(str);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar *str = TEE_Malloc(1000, 0);
\tint offset = params[0].value.a;
\tif (offset < 1 || offset >= 1000)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v009-i01 */
\t*(str + offset) = 'A';
\tchar val = *(str + offset - 1);
\t(void)val;
\tTEE_Free(str);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v009-i01", "function": "cmd_process"},
            {"id": "v009-i02", "function": "cmd_process",
             "shared_source": "v009-i01", "shared_sanitizer": "v009-i01"},
        ],
        param_types_hex=0x0001,
    )


def tpl_v010_ivw_while_loop() -> TemplateResult:
    """IVW: while loop with params[].memref.size as bound without check."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar buf[256];
\tuint32_t sz = params[1].memref.size; /* SOURCE:v010-i01 */
\tuint32_t alloc_val = params[0].value.a; /* SOURCE:v010-i02 */
\tuint32_t i = 0;
\twhile (i < sz) { /* SINK:v010-i01 */
\t\tbuf[i] = ((char *)params[1].memref.buffer)[i];
\t\ti++;
\t}
\tint *arr = TEE_Malloc(alloc_val, 0); /* SINK:v010-i02 */
\t(void)arr;
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar buf[256];
\tuint32_t sz = params[1].memref.size;
\tuint32_t alloc_val = params[0].value.a;
\tif (sz > 256)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v010-i01 */
\tif (alloc_val > 10000)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v010-i02 */
\tuint32_t i = 0;
\twhile (i < sz) {
\t\tbuf[i] = ((char *)params[1].memref.buffer)[i];
\t\ti++;
\t}
\tint *arr = TEE_Malloc(alloc_val, 0);
\t(void)arr;
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v010-i01", "function": "cmd_process"},
            {"id": "v010-i02", "function": "cmd_process"},
        ],
        param_types_hex=0x0041,
    )


def tpl_v011_ivw_signed_unsigned() -> TemplateResult:
    """IVW: int cast of uint32_t size causing signed/unsigned mismatch."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INPUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tint size = (int)params[1].memref.size; /* SOURCE:v011-i01 */
\tif (size > 0) {
\t\tchar *buf = TEE_Malloc(size, 0); /* SINK:v011-i01 */
\t\tTEE_MemMove(buf, params[1].memref.buffer, size); /* SINK:v011-i02 */
\t\tTEE_Free(buf);
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INPUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tuint32_t size = params[1].memref.size;
\tif (size > 10000)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v011-i01 */
\tchar *buf = TEE_Malloc(size, 0);
\tTEE_MemMove(buf, params[1].memref.buffer, size);
\tTEE_Free(buf);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v011-i01", "function": "cmd_process"},
            {"id": "v011-i02", "function": "cmd_process",
             "shared_source": "v011-i01", "shared_sanitizer": "v011-i01"},
        ],
        param_types_hex=0x0041,
    )


def tpl_v012_ivw_unreachable_guard() -> TemplateResult:
    """IVW: Guard in wrong scope (inside else, so unreachable before use)."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tuint32_t val = params[0].value.a; /* SOURCE:v012-i01 */
\tchar *str = TEE_Malloc(1000, 0);
\tint tmp_arr[20];
\tif (val > 0) {
\t\ttmp_arr[val] = 42; /* SINK:v012-i01 */
\t\tint *arr = TEE_Malloc(val, 0); /* SINK:v012-i02 */
\t\t(void)arr;
\t} else {
\t\tif (val > 1000) {
\t\t\treturn TEE_ERROR_BAD_PARAMETERS;
\t\t}
\t}
\tTEE_Free(str);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tuint32_t val = params[0].value.a;
\tchar *str = TEE_Malloc(1000, 0);
\tint tmp_arr[20];
\tif (val >= 20)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v012-i01 */
\tif (val > 0) {
\t\ttmp_arr[val] = 42;
\t\tint *arr = TEE_Malloc(val, 0);
\t\t(void)arr;
\t}
\tTEE_Free(str);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v012-i01", "function": "cmd_process"},
            {"id": "v012-i02", "function": "cmd_process",
             "shared_source": "v012-i01", "shared_sanitizer": "v012-i01"},
        ],
        param_types_hex=0x0061,
    )


def tpl_v013_ivw_off_by_one() -> TemplateResult:
    """IVW: <= instead of < in bounds check (off-by-one)."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar buf[256];
\tuint32_t idx = params[0].value.a; /* SOURCE:v013-i01 */
\tif (idx <= 256) {
\t\tbuf[idx] = 'X'; /* SINK:v013-i01 */
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar buf[256];
\tuint32_t idx = params[0].value.a;
\tif (idx < 256) { /* SANITIZER:v013-i01 */
\t\tbuf[idx] = 'X';
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v013-i01", "function": "cmd_process"},
        ],
        param_types_hex=0x0061,
    )


def tpl_v014_ivw_computed_index() -> TemplateResult:
    """IVW: idx = val * 4 + offset, multi-step computed index."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tint arr[100];
\tuint32_t val = params[0].value.a; /* SOURCE:v014-i01 */
\tint idx = val * 4 + 3;
\tarr[idx] = 99; /* SINK:v014-i01 */
\tchar *buf = TEE_Malloc(val * 8, 0); /* SINK:v014-i02 */
\t(void)buf;
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tint arr[100];
\tuint32_t val = params[0].value.a;
\tif (val > 24)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v014-i01 */
\tint idx = val * 4 + 3;
\tarr[idx] = 99;
\tchar *buf = TEE_Malloc(val * 8, 0);
\t(void)buf;
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v014-i01", "function": "cmd_process"},
            {"id": "v014-i02", "function": "cmd_process",
             "shared_source": "v014-i01", "shared_sanitizer": "v014-i01"},
        ],
        param_types_hex=0x0061,
    )


def tpl_v015_ivw_wrong_operator() -> TemplateResult:
    """IVW: || instead of && in guard making it always true."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar *str = TEE_Malloc(1000, 0);
\tuint32_t a = params[0].value.a; /* SOURCE:v015-i01 */
\tuint32_t sz = params[1].memref.size; /* SOURCE:v015-i02 */
\tif (a < 1000 || sz < 1000) {
\t\tstr[a] = 'Z'; /* SINK:v015-i01 */
\t\tTEE_MemMove(str, params[1].memref.buffer, sz); /* SINK:v015-i02 */
\t}
\tTEE_Free(str);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar *str = TEE_Malloc(1000, 0);
\tuint32_t a = params[0].value.a;
\tuint32_t sz = params[1].memref.size;
\tif (a < 1000 && sz < 1000) { /* SANITIZER:v015-i01 */
\t\tstr[a] = 'Z';
\t\tTEE_MemMove(str, params[1].memref.buffer, sz);
\t}
\tTEE_Free(str);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v015-i01", "function": "cmd_process"},
            {"id": "v015-i02", "function": "cmd_process",
             "shared_sanitizer": "v015-i01"},
        ],
        param_types_hex=0x0641,
    )


def tpl_v016_ivw_wrapper_func() -> TemplateResult:
    """IVW: my_alloc() wrapping TEE_Malloc, hiding taint path."""
    unsafe = """\
static void *my_alloc(uint32_t size)
{
\treturn TEE_Malloc(size, 0); /* SINK:v016-i01 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = my_alloc(params[0].value.a); /* SOURCE:v016-i01 */
\tint tmp_arr[20];
\ttmp_arr[params[0].value.a] = 55; /* SINK:v016-i02 */
\t(void)buf;
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static void *my_alloc(uint32_t size)
{
\treturn TEE_Malloc(size, 0);
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
\t                                TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tif (params[0].value.a >= 20)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v016-i01 */
\tvoid *buf = my_alloc(params[0].value.a);
\tint tmp_arr[20];
\ttmp_arr[params[0].value.a] = 55;
\t(void)buf;
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v016-i01", "function": "my_alloc"},
            {"id": "v016-i02", "function": "cmd_process",
             "shared_source": "v016-i01", "shared_sanitizer": "v016-i01"},
        ],
        param_types_hex=0x0061,
    )


# ===========================================================================
# DUS Templates (v017 - v025)
# ===========================================================================

def tpl_v017_dus_wait_typedef() -> TemplateResult:
    """DUS: typedef alias + TEE_Wait between check and use."""
    unsafe = """\
typedef char* shm_buf_t;

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tshm_buf_t buf = (shm_buf_t)params[0].memref.buffer; /* SOURCE:v017-i01 */
\tif (strcmp("123456", buf) == 0) { /* SINK:v017-i01 */
\t\tIMSG("Match!\\n");
\t}
\tTEE_Wait(3000);
\tdec(buf); /* SINK:v017-i02 */
\tif (!TEE_MemCompare(buf, "123456", params[0].memref.size)) { /* SINK:v017-i03 */
\t\tIMSG("Pass!\\n");
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
typedef char* shm_buf_t;

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v017-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tif (strcmp("123456", local) == 0) {
\t\tIMSG("Match!\\n");
\t}
\tTEE_Wait(3000);
\tdec(local);
\tif (!TEE_MemCompare(local, "123456", sz)) {
\t\tIMSG("Pass!\\n");
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v017-i01", "function": "cmd_process"},
            {"id": "v017-i02", "function": "cmd_process",
             "shared_source": "v017-i01", "shared_sanitizer": "v017-i01"},
            {"id": "v017-i03", "function": "cmd_process",
             "shared_source": "v017-i01", "shared_sanitizer": "v017-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v018_dus_wait_struct() -> TemplateResult:
    """DUS: shm ptr stored in struct field + TEE_Wait between check/use."""
    unsafe = """\
struct shm_handle {
\tvoid *buf;
\tuint32_t size;
};

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tstruct shm_handle h;
\th.buf = params[0].memref.buffer; /* SOURCE:v018-i01 */
\th.size = params[0].memref.size;
\tif (strcmp("123456", h.buf) == 0) { /* SINK:v018-i01 */
\t\tIMSG("Match!\\n");
\t}
\tTEE_Wait(5000);
\tdec(h.buf); /* SINK:v018-i02 */
\treturn TEE_SUCCESS;
}
"""
    safe = """\
struct shm_handle {
\tvoid *buf;
\tuint32_t size;
};

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v018-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tif (strcmp("123456", local) == 0) {
\t\tIMSG("Match!\\n");
\t}
\tTEE_Wait(5000);
\tdec(local);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v018-i01", "function": "cmd_process"},
            {"id": "v018-i02", "function": "cmd_process",
             "shared_source": "v018-i01", "shared_sanitizer": "v018-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v019_dus_wait_reread() -> TemplateResult:
    """DUS: Direct ptr + TEE_Wait + explicit re-read from shm."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer; /* SOURCE:v019-i01 */
\tuint32_t sz = params[0].memref.size;
\tif (!strcmp("secret", buf)) { /* SINK:v019-i01 */
\t\tIMSG("Verified!\\n");
\t}
\tTEE_Wait(2000);
\tif (!TEE_MemCompare(params[0].memref.buffer, "secret",
\t                    params[0].memref.size)) { /* SINK:v019-i02 */
\t\tIMSG("Still matches!\\n");
\t}
\tdec(buf); /* SINK:v019-i03 */
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v019-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tif (!strcmp("secret", local)) {
\t\tIMSG("Verified!\\n");
\t}
\tTEE_Wait(2000);
\tif (!TEE_MemCompare(local, "secret", sz)) {
\t\tIMSG("Still matches!\\n");
\t}
\tdec(local);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v019-i01", "function": "cmd_process"},
            {"id": "v019-i02", "function": "cmd_process",
             "shared_source": "v019-i01", "shared_sanitizer": "v019-i01"},
            {"id": "v019-i03", "function": "cmd_process",
             "shared_source": "v019-i01", "shared_sanitizer": "v019-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v020_dus_nested_reread() -> TemplateResult:
    """DUS: Validate in outer if, re-read from shm in inner block."""
    unsafe = """\
static void process_data(void *buf, uint32_t sz)
{
\tdec(buf); /* SINK:v020-i02 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer; /* SOURCE:v020-i01 */
\tuint32_t sz = params[0].memref.size;
\tif (strcmp("auth_token", buf) == 0) { /* SINK:v020-i01 */
\t\tif (sz > 10) {
\t\t\tprocess_data(params[0].memref.buffer, params[0].memref.size);
\t\t}
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static void process_data(char *local_buf, uint32_t sz)
{
\tdec(local_buf);
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v020-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tif (strcmp("auth_token", local) == 0) {
\t\tif (sz > 10) {
\t\t\tprocess_data(local, sz);
\t\t}
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v020-i01", "function": "cmd_process"},
            {"id": "v020-i02", "function": "process_data",
             "shared_source": "v020-i01", "shared_sanitizer": "v020-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v021_dus_while_recheck() -> TemplateResult:
    """DUS: Check then re-check in while loop body."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer; /* SOURCE:v021-i01 */
\tint retries = 3;
\tif (strcmp("valid", buf) == 0) { /* SINK:v021-i01 */
\t\twhile (retries > 0) {
\t\t\tif (strcmp("valid", buf) != 0) { /* SINK:v021-i02 */
\t\t\t\tbreak;
\t\t\t}
\t\t\tdec(buf); /* SINK:v021-i03 */
\t\t\tretries--;
\t\t}
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v021-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tint retries = 3;
\tif (strcmp("valid", local) == 0) {
\t\twhile (retries > 0) {
\t\t\tif (strcmp("valid", local) != 0) {
\t\t\t\tbreak;
\t\t\t}
\t\t\tdec(local);
\t\t\tretries--;
\t\t}
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v021-i01", "function": "cmd_process"},
            {"id": "v021-i02", "function": "cmd_process",
             "shared_source": "v021-i01", "shared_sanitizer": "v021-i01"},
            {"id": "v021-i03", "function": "cmd_process",
             "shared_source": "v021-i01", "shared_sanitizer": "v021-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v022_dus_callback() -> TemplateResult:
    """DUS: Function pointer callback re-reads shared memory."""
    unsafe = """\
typedef void (*process_fn)(void *data, uint32_t size);

static void process_callback(void *data, uint32_t size)
{
\tdec(data); /* SINK:v022-i02 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer; /* SOURCE:v022-i01 */
\tuint32_t sz = params[0].memref.size;
\tif (strcmp("123456", buf) == 0) { /* SINK:v022-i01 */
\t\tIMSG("Verified!\\n");
\t}
\tprocess_fn fn = process_callback;
\tfn(params[0].memref.buffer, params[0].memref.size);
\treturn TEE_SUCCESS;
}
"""
    safe = """\
typedef void (*process_fn)(void *data, uint32_t size);

static void process_callback(void *data, uint32_t size)
{
\tdec(data);
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v022-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tif (strcmp("123456", local) == 0) {
\t\tIMSG("Verified!\\n");
\t}
\tprocess_fn fn = process_callback;
\tfn(local, sz);
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v022-i01", "function": "cmd_process"},
            {"id": "v022-i02", "function": "process_callback",
             "shared_source": "v022-i01", "shared_sanitizer": "v022-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v023_dus_memcmp_libc() -> TemplateResult:
    """DUS: memcmp() (libc) instead of TEE_MemCompare() on shared buffer."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer; /* SOURCE:v023-i01 */
\tuint32_t sz = params[0].memref.size;
\tif (memcmp(buf, "expected", 8) == 0) { /* SINK:v023-i01 */
\t\tIMSG("Match!\\n");
\t}
\tdec(buf); /* SINK:v023-i02 */
\tif (memcmp(params[0].memref.buffer, "expected", 8) == 0) { /* SINK:v023-i03 */
\t\tIMSG("Re-match!\\n");
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v023-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tif (memcmp(local, "expected", 8) == 0) {
\t\tIMSG("Match!\\n");
\t}
\tdec(local);
\tif (memcmp(local, "expected", 8) == 0) {
\t\tIMSG("Re-match!\\n");
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v023-i01", "function": "cmd_process"},
            {"id": "v023-i02", "function": "cmd_process",
             "shared_source": "v023-i01", "shared_sanitizer": "v023-i01"},
            {"id": "v023-i03", "function": "cmd_process",
             "shared_source": "v023-i01", "shared_sanitizer": "v023-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v024_dus_partial_copy() -> TemplateResult:
    """DUS: Part of shm copied to local, rest re-read from shm."""
    unsafe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer; /* SOURCE:v024-i01 */
\tuint32_t sz = params[0].memref.size;
\tchar local_header[16];
\tif (sz > 16) {
\t\tTEE_MemMove(local_header, buf, 16);
\t}
\tif (strcmp("AUTH", local_header) == 0) {
\t\tchar *payload = (char *)buf + 16;
\t\tdec(payload); /* SINK:v024-i01 */
\t}
\tif (strcmp("AUTH", params[0].memref.buffer) == 0) { /* SINK:v024-i02 */
\t\tIMSG("Re-check!\\n");
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tchar local[1024];
\tuint32_t sz = params[0].memref.size;
\tif (sz > 1024)
\t\treturn TEE_ERROR_BAD_PARAMETERS; /* SANITIZER:v024-i01 */
\tTEE_MemMove(local, params[0].memref.buffer, sz);
\tif (strcmp("AUTH", local) == 0) {
\t\tchar *payload = local + 16;
\t\tdec(payload);
\t}
\tif (strcmp("AUTH", local) == 0) {
\t\tIMSG("Re-check!\\n");
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v024-i01", "function": "cmd_process"},
            {"id": "v024-i02", "function": "cmd_process",
             "shared_source": "v024-i01", "shared_sanitizer": "v024-i01"},
        ],
        param_types_hex=0x0006,
    )


def tpl_v025_dus_return_ignored() -> TemplateResult:
    """DUS: Validation func returns safe copy, caller uses original shm ptr."""
    unsafe = """\
static char *validate_and_copy(void *shm_buf, uint32_t sz)
{
\tchar *local = TEE_Malloc(1024, 0);
\tif (sz > 1024) {
\t\tTEE_Free(local);
\t\treturn NULL;
\t}
\tTEE_MemMove(local, shm_buf, sz);
\tif (strcmp("pass", local) != 0) {
\t\tTEE_Free(local);
\t\treturn NULL;
\t}
\treturn local;
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer; /* SOURCE:v025-i01 */
\tuint32_t sz = params[0].memref.size;
\tchar *safe_copy = validate_and_copy(buf, sz);
\tif (safe_copy) {
\t\tdec(buf); /* SINK:v025-i01 */
\t\tif (strcmp("pass", buf) == 0) { /* SINK:v025-i02 */
\t\t\tIMSG("Using original shm!\\n");
\t\t}
\t\tTEE_Free(safe_copy);
\t}
\treturn TEE_SUCCESS;
}
"""
    safe = """\
static char *validate_and_copy(void *shm_buf, uint32_t sz)
{
\tchar *local = TEE_Malloc(1024, 0);
\tif (sz > 1024) {
\t\tTEE_Free(local);
\t\treturn NULL;
\t}
\tTEE_MemMove(local, shm_buf, sz);
\tif (strcmp("pass", local) != 0) {
\t\tTEE_Free(local);
\t\treturn NULL;
\t}
\treturn local; /* SANITIZER:v025-i01 */
}

static TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
\tuint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE,
\t                                TEE_PARAM_TYPE_NONE);
\tif (param_types != exp) return TEE_ERROR_BAD_PARAMETERS;
\tvoid *buf = params[0].memref.buffer;
\tuint32_t sz = params[0].memref.size;
\tchar *safe_copy = validate_and_copy(buf, sz);
\tif (safe_copy) {
\t\tdec(safe_copy);
\t\tif (strcmp("pass", safe_copy) == 0) {
\t\t\tIMSG("Using safe copy!\\n");
\t\t}
\t\tTEE_Free(safe_copy);
\t}
\treturn TEE_SUCCESS;
}
"""
    return TemplateResult(
        unsafe_body=unsafe,
        safe_body=safe,
        vuln_markers=[
            {"id": "v025-i01", "function": "cmd_process"},
            {"id": "v025-i02", "function": "cmd_process",
             "shared_source": "v025-i01", "shared_sanitizer": "v025-i01"},
        ],
        param_types_hex=0x0006,
    )


# ===========================================================================
# Template Registry
# ===========================================================================

TEMPLATE_REGISTRY: dict[str, callable] = {
    "v001": tpl_v001_udo_deep_call_chain,
    "v002": tpl_v002_udo_struct_member,
    "v003": tpl_v003_udo_switch_dispatch,
    "v004": tpl_v004_udo_double_pointer,
    "v005": tpl_v005_udo_conditional_encrypt,
    "v006": tpl_v006_udo_xor_derivation,
    "v007": tpl_v007_udo_loop_multi_buffer,
    "v008": tpl_v008_udo_partial_encrypt,
    "v009": tpl_v009_ivw_pointer_arith,
    "v010": tpl_v010_ivw_while_loop,
    "v011": tpl_v011_ivw_signed_unsigned,
    "v012": tpl_v012_ivw_unreachable_guard,
    "v013": tpl_v013_ivw_off_by_one,
    "v014": tpl_v014_ivw_computed_index,
    "v015": tpl_v015_ivw_wrong_operator,
    "v016": tpl_v016_ivw_wrapper_func,
    "v017": tpl_v017_dus_wait_typedef,
    "v018": tpl_v018_dus_wait_struct,
    "v019": tpl_v019_dus_wait_reread,
    "v020": tpl_v020_dus_nested_reread,
    "v021": tpl_v021_dus_while_recheck,
    "v022": tpl_v022_dus_callback,
    "v023": tpl_v023_dus_memcmp_libc,
    "v024": tpl_v024_dus_partial_copy,
    "v025": tpl_v025_dus_return_ignored,
}
