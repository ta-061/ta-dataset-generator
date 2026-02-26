"""
emitters.py — OP-TEE公式hello_world派生スキャフォールド + entry.c組み立て

OP-TEE公式の optee_examples/hello_world (BSD-2-Clause) を基に
スキャフォールドをジェネレーター内に埋め込み、外部依存なしで
完全なTAプロジェクトを生成する。
"""

import json
import os
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RQ3_UUID_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

# Original hello_world UUID (used as template, replaced per-variant)
HELLO_WORLD_UUID = "8aaaf200-2450-11e4-abe2-0002a5d5c51b"

# ---------------------------------------------------------------------------
# Embedded scaffold files — derived from OP-TEE official optee_examples
# (BSD-2-Clause, Copyright (c) 2016-2017 Linaro Limited)
# ---------------------------------------------------------------------------

# --- Top-level Makefile ---
SCAFFOLD_ROOT_MAKEFILE = """\
export V?=0

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
\t$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
\t$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""

.PHONY: clean
clean:
\t$(MAKE) -C host clean
\t$(MAKE) -C ta clean
"""

# --- host/Makefile ---
SCAFFOLD_HOST_MAKEFILE = """\
CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

OBJS = main.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include
#Add/link other required libraries here
LDADD += -lteec -L$(TEEC_EXPORT)/lib

BINARY = optee_example_hello_world

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
\t$(CC) $(LDFLAGS) -o $@ $< $(LDADD)

.PHONY: clean
clean:
\trm -f $(OBJS) $(BINARY)

%.o: %.c
\t$(CC) $(CFLAGS) -c $< -o $@
"""

# --- host/main.c ---
# Minimal host application that invokes the TA's cmd_process via
# TA_HELLO_WORLD_CMD_VARIANT. Supports MEMREF and VALUE param types.
SCAFFOLD_HOST_MAIN_C = """\
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Derived from OP-TEE optee_examples/hello_world.
 * Modified for RQ3 dataset evaluation.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <hello_world_ta.h>

#define TEST_BUFFER_SIZE 4096

int main(void)
{
\tTEEC_Result res;
\tTEEC_Context ctx;
\tTEEC_Session sess;
\tTEEC_Operation op;
\tTEEC_UUID uuid = TA_HELLO_WORLD_UUID;
\tuint32_t err_origin;

\tres = TEEC_InitializeContext(NULL, &ctx);
\tif (res != TEEC_SUCCESS)
\t\terrx(1, "TEEC_InitializeContext failed with code 0x%x", res);

\tres = TEEC_OpenSession(&ctx, &sess, &uuid,
\t\t\t       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
\tif (res != TEEC_SUCCESS)
\t\terrx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
\t\t\tres, err_origin);

\t/* Invoke the TA command */
\tmemset(&op, 0, sizeof(op));

\tchar buf0[TEST_BUFFER_SIZE] = {0};
\tchar buf1[TEST_BUFFER_SIZE] = {0};
\tchar buf2[TEST_BUFFER_SIZE] = {0};

\top.paramTypes = TEEC_PARAM_TYPES(
\t\tTEEC_MEMREF_TEMP_INOUT,
\t\tTEEC_MEMREF_TEMP_INOUT,
\t\tTEEC_MEMREF_TEMP_INOUT,
\t\tTEEC_NONE);

\top.params[0].tmpref.buffer = buf0;
\top.params[0].tmpref.size = TEST_BUFFER_SIZE;
\top.params[1].tmpref.buffer = buf1;
\top.params[1].tmpref.size = TEST_BUFFER_SIZE;
\top.params[2].tmpref.buffer = buf2;
\top.params[2].tmpref.size = TEST_BUFFER_SIZE;

\tprintf("Invoking TA command...\\n");
\tres = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_VARIANT, &op,
\t\t\t\t &err_origin);
\tif (res != TEEC_SUCCESS)
\t\tprintf("TEEC_InvokeCommand returned 0x%x origin 0x%x\\n",
\t\t\tres, err_origin);
\telse
\t\tprintf("TA command completed successfully\\n");

\tTEEC_CloseSession(&sess);
\tTEEC_FinalizeContext(&ctx);

\treturn 0;
}
"""

# --- ta/Makefile ---
# UUID placeholder {TA_UUID_NO_DASH} will be replaced per-variant
SCAFFOLD_TA_MAKEFILE_TEMPLATE = """\
CFG_TEE_TA_LOG_LEVEL ?= 4
CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y

# The UUID for the Trusted Application
BINARY={ta_uuid_no_dash}

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
\t@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
\t@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
"""

# --- ta/sub.mk ---
# Modified from official: hello_world_ta.c → entry.c
SCAFFOLD_TA_SUB_MK = """\
global-incdirs-y += include
srcs-y += entry.c
"""

# --- ta/user_ta_header_defines.h ---
SCAFFOLD_USER_TA_HEADER_DEFINES = """\
/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <hello_world_ta.h>

#define TA_UUID\t\t\t\tTA_HELLO_WORLD_UUID

#define TA_FLAGS\t\t\t0

#define TA_STACK_SIZE\t\t\t(2 * 1024)

#define TA_DATA_SIZE\t\t\t(32 * 1024)

#define TA_VERSION\t"1.0"

#define TA_DESCRIPTION\t"RQ3 Dataset TA variant"

#endif /* USER_TA_HEADER_DEFINES_H */
"""

# --- ta/include/hello_world_ta.h ---
# UUID placeholder {uuid_hex_fields} will be replaced per-variant
# Added TA_HELLO_WORLD_CMD_VARIANT for our generated entry points
SCAFFOLD_HELLO_WORLD_TA_H_TEMPLATE = """\
/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_HELLO_WORLD_H
#define TA_HELLO_WORLD_H

#define TA_HELLO_WORLD_UUID \\
\t{{ {uuid_hex_fields} }}

/* The function IDs implemented in this TA */
#define TA_HELLO_WORLD_CMD_VARIANT\t\t0

#endif /*TA_HELLO_WORLD_H*/
"""


# ---------------------------------------------------------------------------
# entry.c boilerplate (used by assemble_entry_c)
# ---------------------------------------------------------------------------

COPYRIGHT_HEADER = """\
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Derived from OP-TEE optee_examples/hello_world.
 * Modified for RQ3 dataset evaluation.
 */
"""

INCLUDES = """\
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <hello_world_ta.h>

#include <string.h>
"""

ENTRY_POINTS_STUB = """\
/*
 * Called when the instance of the TA is created.
 */
TEE_Result TA_CreateEntryPoint(void)
{
\tDMSG("has been called");
\treturn TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed.
 */
void TA_DestroyEntryPoint(void)
{
\tDMSG("has been called");
}

/*
 * Called when a new session is opened to the TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
\t\tTEE_Param __maybe_unused params[4],
\t\tvoid __maybe_unused **sess_ctx)
{
\tuint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
\t\t\t\t\t   TEE_PARAM_TYPE_NONE,
\t\t\t\t\t   TEE_PARAM_TYPE_NONE,
\t\t\t\t\t   TEE_PARAM_TYPE_NONE);

\tDMSG("has been called");

\tif (param_types != exp_param_types)
\t\treturn TEE_ERROR_BAD_PARAMETERS;

\t(void)&params;
\t(void)&sess_ctx;

\tIMSG("Hello World!\\n");
\treturn TEE_SUCCESS;
}

/*
 * Called when a session is closed.
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
\t(void)&sess_ctx;
\tIMSG("Goodbye!\\n");
}
"""

ENC_DEC_STUBS = """\
/*
 * Simple XOR-based encryption/decryption.
 * In a real TA this would use TEE Crypto API (AES, etc.).
 */
static const char xor_key[] = "TA_ENCRYPT_KEY_2024";

static void enc(char *str)
{
\tsize_t key_len = sizeof(xor_key) - 1;
\tsize_t i;
\tfor (i = 0; str[i] != '\\0'; i++)
\t\tstr[i] ^= xor_key[i % key_len];
}

static void dec(char *str)
{
\t/* XOR encryption is symmetric: dec == enc */
\tenc(str);
}
"""

INVOKE_TEMPLATE = """\
/*
 * Called when a TA is invoked.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
\t\t\tuint32_t cmd_id,
\t\t\tuint32_t param_types, TEE_Param params[4])
{
\t(void)&sess_ctx;

\tswitch (cmd_id) {
\tcase TA_HELLO_WORLD_CMD_VARIANT:
\t\treturn cmd_process(param_types, params);
\tdefault:
\t\treturn TEE_ERROR_BAD_PARAMETERS;
\t}
}
"""


# ---------------------------------------------------------------------------
# compile_commands.json template
# ---------------------------------------------------------------------------

def _build_compile_commands(ta_dir: str) -> list[dict]:
    """Build compile_commands.json entries with full ARM cross-compile flags.

    Flags match the OP-TEE build system output for TA compilation.
    """
    return [{
        "arguments": [
            "/usr/bin/arm-linux-gnueabihf-gcc",
            "-std=gnu99",
            "-fdiagnostics-show-option",
            "-Wall",
            "-Wcast-align",
            "-Werror-implicit-function-declaration",
            "-Wextra",
            "-Wfloat-equal",
            "-Wformat-nonliteral",
            "-Wformat-security",
            "-Wformat=2",
            "-Winit-self",
            "-Wmissing-declarations",
            "-Wmissing-format-attribute",
            "-Wmissing-include-dirs",
            "-Wmissing-noreturn",
            "-Wmissing-prototypes",
            "-Wnested-externs",
            "-Wpointer-arith",
            "-Wshadow",
            "-Wstrict-prototypes",
            "-Wswitch-default",
            "-Wwrite-strings",
            "-Wno-missing-field-initializers",
            "-Wno-format-zero-length",
            "-Waggregate-return",
            "-Wredundant-decls",
            "-Wold-style-definition",
            "-Wstrict-aliasing=2",
            "-Wundef",
            "-pedantic",
            "-mcpu=cortex-a53",
            "-Wno-error=cast-align",
            "-Os",
            "-g3",
            "-fpie",
            "-mthumb",
            "-mthumb-interwork",
            "-fno-short-enums",
            "-fno-common",
            "-mno-unaligned-access",
            "-mfloat-abi=hard",
            "-funsafe-math-optimizations",
            "-funwind-tables",
            "-nostdinc",
            "-isystem",
            "/usr/lib/gcc-cross/arm-linux-gnueabihf/11/include",
            "-DCFG_TEE_TA_LOG_LEVEL=4",
            "-I./include",
            "-I./.",
            "-DARM32=1",
            "-D__ILP32__=1",
            "-DMBEDTLS_SELF_TEST",
            "-DTRACE_LEVEL=4",
            "-I.",
            "-DCFG_TA_MBEDTLS_SELF_TEST=1",
            "-DCFG_TA_MBEDTLS=1",
            "-DCFG_ARM32_ta_arm32=1",
            "-DCFG_TA_DYNLINK=1",
            "-DCFG_TA_MBEDTLS_MPI=1",
            "-DCFG_SYSTEM_PTA=1",
            "-DCFG_TA_FLOAT_SUPPORT=1",
            "-D__FILE_ID__=entry_c",
            "-c",
            "-o",
            "entry.o",
            "entry.c"
        ],
        "directory": ta_dir,
        "file": os.path.join(ta_dir, "entry.c"),
        "output": os.path.join(ta_dir, "entry.o"),
    }]


# ---------------------------------------------------------------------------
# UUID helpers
# ---------------------------------------------------------------------------

def generate_uuid_for_variant(variant_id: str) -> str:
    """Generate a deterministic UUID for a variant."""
    return str(uuid.uuid5(RQ3_UUID_NAMESPACE, variant_id))


def _uuid_to_hex_fields(uuid_str: str) -> str:
    """Convert UUID string to C struct initializer fields.

    e.g., "8aaaf200-2450-11e4-abe2-0002a5d5c51b"
       -> "0x8aaaf200, 0x2450, 0x11e4, \\n\\t\\t{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}"
    """
    parts = uuid_str.split("-")
    # parts: [8aaaf200, 2450, 11e4, abe2, 0002a5d5c51b]
    time_low = f"0x{parts[0]}"
    time_mid = f"0x{parts[1]}"
    time_hi = f"0x{parts[2]}"
    # Clock seq + node = parts[3] + parts[4]
    clock_node = parts[3] + parts[4]
    bytes_list = [f"0x{clock_node[i:i+2]}" for i in range(0, len(clock_node), 2)]
    return f"{time_low}, {time_mid}, {time_hi}, \\\n\t\t{{ {', '.join(bytes_list)}}}"


# ---------------------------------------------------------------------------
# entry.c assembly
# ---------------------------------------------------------------------------

def assemble_entry_c(body: str, pad_lines: int = 0) -> str:
    """Assemble a complete entry.c from boilerplate + PAD + body + invoke.

    Args:
        body: The variant-specific C function code (cmd_process + helpers)
        pad_lines: Number of blank lines to insert for line number alignment

    Returns:
        Complete entry.c source code
    """
    pad = "\n" * pad_lines if pad_lines > 0 else ""

    parts = [
        COPYRIGHT_HEADER,
        INCLUDES,
        ENTRY_POINTS_STUB,
        ENC_DEC_STUBS,
        pad,
        body,
        "",
        INVOKE_TEMPLATE,
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Scaffold writing (embedded, no external dependency)
# ---------------------------------------------------------------------------

def write_scaffold(dst_dir: Path, uuid_str: str) -> None:
    """Write the complete OP-TEE TA project scaffold to dst_dir.

    All files are generated from embedded templates derived from
    the official OP-TEE optee_examples/hello_world (BSD-2-Clause).

    Args:
        dst_dir: Target project directory
        uuid_str: UUID for this variant
    """
    dst_dir.mkdir(parents=True, exist_ok=True)

    uuid_no_dash = uuid_str.replace("-", "")
    uuid_hex_fields = _uuid_to_hex_fields(uuid_str)

    # Top-level Makefile
    (dst_dir / "Makefile").write_text(SCAFFOLD_ROOT_MAKEFILE)

    # host/
    host_dir = dst_dir / "host"
    host_dir.mkdir(parents=True, exist_ok=True)
    (host_dir / "Makefile").write_text(SCAFFOLD_HOST_MAKEFILE)
    (host_dir / "main.c").write_text(SCAFFOLD_HOST_MAIN_C)

    # ta/
    ta_dir = dst_dir / "ta"
    ta_dir.mkdir(parents=True, exist_ok=True)
    (ta_dir / "Makefile").write_text(
        SCAFFOLD_TA_MAKEFILE_TEMPLATE.format(ta_uuid_no_dash=uuid_no_dash)
    )
    (ta_dir / "sub.mk").write_text(SCAFFOLD_TA_SUB_MK)
    (ta_dir / "user_ta_header_defines.h").write_text(SCAFFOLD_USER_TA_HEADER_DEFINES)

    # ta/include/
    include_dir = ta_dir / "include"
    include_dir.mkdir(parents=True, exist_ok=True)
    (include_dir / "hello_world_ta.h").write_text(
        SCAFFOLD_HELLO_WORLD_TA_H_TEMPLATE.format(uuid_hex_fields=uuid_hex_fields)
    )

    # compile_commands.json
    ta_abs = str(ta_dir.resolve())
    cc_data = _build_compile_commands(ta_abs)
    (ta_dir / "compile_commands.json").write_text(
        json.dumps(cc_data, indent=2, ensure_ascii=False)
    )


def write_entry_c(dst_dir: Path, source_code: str) -> None:
    """Write (or overwrite) ta/entry.c in the project directory."""
    entry_path = dst_dir / "ta" / "entry.c"
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    entry_path.write_text(source_code)


# ---------------------------------------------------------------------------
# High-level project writer
# ---------------------------------------------------------------------------

def write_variant_project(
    output_dir: Path,
    variant_id: str,
    unsafe_source: str,
    safe_source: str,
) -> tuple[Path, Path]:
    """Write a complete variant project (unsafe + safe).

    Args:
        output_dir: Root output directory (e.g., TA_Dataset/)
        variant_id: e.g., "v001"
        unsafe_source: Complete entry.c for unsafe version
        safe_source: Complete entry.c for safe version

    Returns:
        Tuple of (unsafe_dir, safe_dir)
    """
    seq = int(variant_id.replace("v", ""))
    variant_dir_name = f"variant_{seq:03d}"
    variant_dir = output_dir / variant_dir_name

    uuid_str = generate_uuid_for_variant(variant_id)

    unsafe_dir = variant_dir / "unsafe"
    safe_dir = variant_dir / "safe"

    for subdir, source in [(unsafe_dir, unsafe_source), (safe_dir, safe_source)]:
        write_scaffold(subdir, uuid_str)
        write_entry_c(subdir, source)

    return unsafe_dir, safe_dir


# ---------------------------------------------------------------------------
# DUS-TOCTOU behavioral oracle
# ---------------------------------------------------------------------------

TOCTOU_ORACLE_C = """\
// SPDX-License-Identifier: BSD-2-Clause
/*
 * TOCTOU behavioral oracle — demonstrates that TEE_Wait creates a
 * window in which the Normal World can overwrite shared memory.
 *
 * Expected behavior:
 *   unsafe TA: validates "PASS", NW overwrites with "EVIL" during TEE_Wait,
 *              TA re-reads and uses "EVIL" → TOCTOU vulnerability
 *   safe TA:   copies shm to local before TEE_Wait, uses local copy →
 *              NW overwrite has no effect
 *
 * Build: link against libteec and libpthread
 *   $(CC) -o toctou_test toctou_test.c -lteec -lpthread
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <tee_client_api.h>
#include <hello_world_ta.h>

#define SHM_SIZE 256

/* Shared state between main thread and attacker thread */
static volatile int ready = 0;
static TEEC_SharedMemory shm;
static TEEC_Context ctx;

static void *attacker_thread(void *arg)
{
\t(void)arg;
\t/* Wait until the TA command has been invoked */
\twhile (!ready)
\t\tusleep(1000);

\t/*
\t * Overwrite shared memory while TA is in TEE_Wait.
\t * The TA validated "PASS" but now sees "EVIL".
\t */
\tusleep(50000); /* 50ms — within typical TEE_Wait(100ms) window */
\tmemcpy(shm.buffer, "EVIL", 5);
\tfprintf(stderr, "[attacker] Overwrote shm with 'EVIL'\\n");
\treturn NULL;
}

int main(void)
{
\tTEEC_Result res;
\tTEEC_Session sess;
\tTEEC_Operation op;
\tTEEC_UUID uuid = TA_HELLO_WORLD_UUID;
\tuint32_t err_origin;
\tpthread_t tid;

\tres = TEEC_InitializeContext(NULL, &ctx);
\tif (res != TEEC_SUCCESS)
\t\terrx(1, "InitializeContext: 0x%x", res);

\tres = TEEC_OpenSession(&ctx, &sess, &uuid,
\t\t\t       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
\tif (res != TEEC_SUCCESS)
\t\terrx(1, "OpenSession: 0x%x (origin 0x%x)", res, err_origin);

\t/* Register shared memory */
\tshm.size = SHM_SIZE;
\tshm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
\tres = TEEC_AllocateSharedMemory(&ctx, &shm);
\tif (res != TEEC_SUCCESS)
\t\terrx(1, "AllocateSharedMemory: 0x%x", res);

\t/* Write initial valid value */
\tmemset(shm.buffer, 0, SHM_SIZE);
\tmemcpy(shm.buffer, "PASS", 5);

\t/* Start attacker thread */
\tpthread_create(&tid, NULL, attacker_thread, NULL);

\t/* Invoke TA command */
\tmemset(&op, 0, sizeof(op));
\top.paramTypes = TEEC_PARAM_TYPES(
\t\tTEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
\top.params[0].memref.parent = &shm;
\top.params[0].memref.offset = 0;
\top.params[0].memref.size = SHM_SIZE;

\tready = 1; /* Signal attacker */
\tprintf("[host] Invoking TA...\\n");
\tres = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_VARIANT, &op,
\t\t\t\t &err_origin);

\tpthread_join(tid, NULL);

\tif (res == TEEC_SUCCESS)
\t\tprintf("[host] TA returned SUCCESS — used value from shm after wait\\n");
\telse
\t\tprintf("[host] TA returned 0x%x — rejected modified shm\\n", res);

\t/*
\t * Interpretation:
\t *   unsafe: returns SUCCESS (re-read "EVIL" from shm, TOCTOU exploited)
\t *   safe:   returns SUCCESS with local copy of "PASS" (NW overwrite ignored)
\t */

\tTEEC_ReleaseSharedMemory(&shm);
\tTEEC_CloseSession(&sess);
\tTEEC_FinalizeContext(&ctx);

\treturn 0;
}
"""


def write_toctou_oracle(unsafe_dir: Path, safe_dir: Path) -> None:
    """Write TOCTOU behavioral oracle test for DUS TEE_Wait variants."""
    for d in (unsafe_dir, safe_dir):
        host_dir = d / "host"
        host_dir.mkdir(parents=True, exist_ok=True)
        (host_dir / "toctou_test.c").write_text(TOCTOU_ORACLE_C)
