/**
 * @file cmd_deobfuscator.h
 * @brief C ABI Interface for cmd-ast-deobfuscator native acceleration engine.
 *
 * Provides high-speed C/Rust FFI bindings, AST parsing, constant folding,
 * dead-code elimination, quote normalization, and IOC extraction for
 * Windows cmd.exe batch scripts.
 */

#ifndef CMD_DEOBFUSCATOR_H
#define CMD_DEOBFUSCATOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Status Codes --- */
typedef enum cmd_ffi_status {
    CMD_FFI_OK = 0,
    CMD_FFI_ERR_NULL_POINTER = -1,
    CMD_FFI_ERR_INVALID_UTF8 = -2,
    CMD_FFI_ERR_BUFFER_OVERFLOW = -3,
    CMD_FFI_ERR_EXECUTION_FAILED = -4,
    CMD_FFI_ERR_INVALID_STATE = -5,
    CMD_FFI_ERR_TIMEOUT = -6
} cmd_ffi_status_t;

/* --- Transformation & Optimization Flags --- */
#define CMD_FFI_FLAG_NONE              0x00000000U
#define CMD_FFI_FLAG_STRIP_CARETS      0x00000001U
#define CMD_FFI_FLAG_FOLD_CONSTANTS    0x00000002U
#define CMD_FFI_FLAG_DCE               0x00000004U
#define CMD_FFI_FLAG_NORMALIZE_QUOTES  0x00000008U
#define CMD_FFI_FLAG_EXTRACT_IOCS      0x00000010U
#define CMD_FFI_FLAG_FAST_PATH         0x00000020U
#define CMD_FFI_FLAG_DEFANG_IOCS       0x00000040U
#define CMD_FFI_FLAG_ALL_OPTIMIZATIONS 0x0000003FU

/* --- Opaque Types --- */
typedef struct cmd_ffi_context cmd_ffi_context_t;
typedef struct cmd_ffi_result cmd_ffi_result_t;

/* --- Configuration Options --- */
typedef struct cmd_ffi_options {
    uint32_t flags;
    uint32_t max_passes;
    uint32_t timeout_ms;
    uint32_t max_unroll_depth;
} cmd_ffi_options_t;

/* --- Performance & Execution Telemetry Metrics --- */
typedef struct cmd_ffi_metrics {
    uint64_t elapsed_ns;
    uint32_t ast_nodes_initial;
    uint32_t ast_nodes_final;
    uint32_t passes_executed;
    uint32_t iocs_extracted;
    double entropy_initial;
    double entropy_final;
} cmd_ffi_metrics_t;

/* --- Version & Initialization --- */

/**
 * @brief Returns the version string of the native engine (e.g. "0.19.0").
 */
const char* cmd_ffi_version(void);

/**
 * @brief Creates a new deobfuscator context.
 *
 * @param options Pointer to configuration options (can be NULL for defaults).
 * @param out_ctx Pointer to receive the allocated context pointer.
 * @return CMD_FFI_OK on success, or error code.
 */
cmd_ffi_status_t cmd_ffi_context_create(
    const cmd_ffi_options_t* options,
    cmd_ffi_context_t** out_ctx
);

/**
 * @brief Destroys a deobfuscator context and frees its internal resources.
 *
 * @param ctx Pointer to the context to destroy.
 * @return CMD_FFI_OK on success, or error code.
 */
cmd_ffi_status_t cmd_ffi_context_destroy(cmd_ffi_context_t* ctx);

/* --- Core Deobfuscation & Analysis APIs --- */

/**
 * @brief Deobfuscates batch script input text using the native engine.
 *
 * @param ctx Active deobfuscator context (can be NULL for default context).
 * @param input Pointer to UTF-8 encoded batch script string.
 * @param len Byte length of input string (if 0 and input is null-terminated, strlen is used).
 * @param flags Bitmask of CMD_FFI_FLAG_* options (overrides context defaults if nonzero).
 * @param out_result Pointer to receive the allocated result structure.
 * @return CMD_FFI_OK on success, or error code.
 */
cmd_ffi_status_t cmd_ffi_deobfuscate(
    cmd_ffi_context_t* ctx,
    const char* input,
    size_t len,
    uint32_t flags,
    cmd_ffi_result_t** out_result
);

/**
 * @brief Extracts malware Indicators of Compromise (IOCs) from batch script input.
 *
 * @param ctx Active deobfuscator context (can be NULL for default context).
 * @param input Pointer to UTF-8 encoded batch script string.
 * @param len Byte length of input string.
 * @param flags Bitmask of flags (e.g. CMD_FFI_FLAG_DEFANG_IOCS).
 * @param out_result Pointer to receive result containing JSON-formatted IOC list.
 * @return CMD_FFI_OK on success, or error code.
 */
cmd_ffi_status_t cmd_ffi_extract_iocs(
    cmd_ffi_context_t* ctx,
    const char* input,
    size_t len,
    uint32_t flags,
    cmd_ffi_result_t** out_result
);

/**
 * @brief Parses batch script input into an AST and serializes JSON tree structure.
 *
 * @param ctx Active deobfuscator context (can be NULL for default context).
 * @param input Pointer to UTF-8 encoded batch script string.
 * @param len Byte length of input string.
 * @param flags Bitmask of options.
 * @param out_result Pointer to receive result containing serialized AST JSON.
 * @return CMD_FFI_OK on success, or error code.
 */
cmd_ffi_status_t cmd_ffi_parse_ast(
    cmd_ffi_context_t* ctx,
    const char* input,
    size_t len,
    uint32_t flags,
    cmd_ffi_result_t** out_result
);

/* --- Result Accessors & Cleanup --- */

/**
 * @brief Retrieves the output text buffer from a result handle.
 *
 * The returned pointer is valid until cmd_ffi_result_free is called.
 */
const char* cmd_ffi_result_get_text(const cmd_ffi_result_t* result);

/**
 * @brief Retrieves the byte length of the output text.
 */
size_t cmd_ffi_result_get_length(const cmd_ffi_result_t* result);

/**
 * @brief Retrieves the execution status code of the result.
 */
cmd_ffi_status_t cmd_ffi_result_get_status(const cmd_ffi_result_t* result);

/**
 * @brief Retrieves the error message string, or NULL if status is CMD_FFI_OK.
 */
const char* cmd_ffi_result_get_error(const cmd_ffi_result_t* result);

/**
 * @brief Copies execution metrics from result into user-provided out_metrics structure.
 */
cmd_ffi_status_t cmd_ffi_result_get_metrics(
    const cmd_ffi_result_t* result,
    cmd_ffi_metrics_t* out_metrics
);

/**
 * @brief Frees result handle and securely wipes internal output buffers.
 */
void cmd_ffi_result_free(cmd_ffi_result_t* result);

/* --- Memory Security & Zeroization --- */

/**
 * @brief Securely wipes memory region using volatile store fence to prevent compiler dead-store elimination.
 *
 * @param ptr Pointer to memory buffer to wipe.
 * @param len Size in bytes to wipe with zeros.
 */
void cmd_ffi_zeroize(void* ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CMD_DEOBFUSCATOR_H */
