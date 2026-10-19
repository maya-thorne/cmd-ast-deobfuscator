//! C ABI FFI Layer for cmd-ast-deobfuscator.
//!
//! Exposes extern "C" functions compatible with include/cmd_deobfuscator.h.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::{zeroize_bytes, CmdDeobfuscator, DeobfuscateOptions, StatusCode};

/// C-compatible options struct matching cmd_ffi_options_t.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmdFfiOptions {
    pub flags: u32,
    pub max_passes: u32,
    pub timeout_ms: u32,
    pub max_unroll_depth: u32,
}

/// C-compatible metrics struct matching cmd_ffi_metrics_t.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CmdFfiMetrics {
    pub elapsed_ns: u64,
    pub ast_nodes_initial: u32,
    pub ast_nodes_final: u32,
    pub passes_executed: u32,
    pub iocs_extracted: u32,
    pub entropy_initial: f64,
    pub entropy_final: f64,
}

/// Internal wrapper for FFI context.
pub struct CmdFfiContext {
    pub deobfuscator: CmdDeobfuscator,
}

/// Internal wrapper for FFI result handle.
pub struct CmdFfiResult {
    pub text_c: CString,
    pub text_len: usize,
    pub status: i32,
    pub error_c: Option<CString>,
    pub metrics: CmdFfiMetrics,
}

#[no_mangle]
pub extern "C" fn cmd_ffi_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.22.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_context_create(
    options: *const CmdFfiOptions,
    out_ctx: *mut *mut CmdFfiContext,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if out_ctx.is_null() {
            return StatusCode::ErrNullPointer as i32;
        }

        let opts = if options.is_null() {
            DeobfuscateOptions::default()
        } else {
            let opt = &*options;
            DeobfuscateOptions {
                flags: opt.flags,
                max_passes: opt.max_passes,
                timeout_ms: opt.timeout_ms,
                max_unroll_depth: opt.max_unroll_depth,
            }
        };

        let ctx = Box::new(CmdFfiContext {
            deobfuscator: CmdDeobfuscator::new(opts),
        });

        *out_ctx = Box::into_raw(ctx);
        StatusCode::Ok as i32
    }));

    outcome.unwrap_or(StatusCode::ErrExecutionFailed as i32)
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_context_destroy(ctx: *mut CmdFfiContext) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if ctx.is_null() {
            return StatusCode::ErrNullPointer as i32;
        }
        drop(Box::from_raw(ctx));
        StatusCode::Ok as i32
    }));

    outcome.unwrap_or(StatusCode::ErrExecutionFailed as i32)
}

unsafe fn parse_c_input<'a>(input: *const c_char, len: usize) -> Result<&'a str, i32> {
    if input.is_null() {
        return Err(StatusCode::ErrNullPointer as i32);
    }
    if len > 0 {
        let slice = std::slice::from_raw_parts(input as *const u8, len);
        std::str::from_utf8(slice).map_err(|_| StatusCode::ErrInvalidUtf8 as i32)
    } else {
        CStr::from_ptr(input)
            .to_str()
            .map_err(|_| StatusCode::ErrInvalidUtf8 as i32)
    }
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_deobfuscate(
    ctx: *mut CmdFfiContext,
    input: *const c_char,
    len: usize,
    flags: u32,
    out_result: *mut *mut CmdFfiResult,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if out_result.is_null() {
            return StatusCode::ErrNullPointer as i32;
        }

        let input_str = match parse_c_input(input, len) {
            Ok(s) => s,
            Err(err) => return err,
        };

        let deob = if !ctx.is_null() {
            &(*ctx).deobfuscator
        } else {
            static DEFAULT_DEOB: std::sync::OnceLock<CmdDeobfuscator> = std::sync::OnceLock::new();
            DEFAULT_DEOB.get_or_init(|| CmdDeobfuscator::new(DeobfuscateOptions::default()))
        };

        let res = deob.deobfuscate(input_str, flags);
        let text_len = res.text.len();
        let text_c = match CString::new(res.text) {
            Ok(c) => c,
            Err(_) => return StatusCode::ErrExecutionFailed as i32,
        };

        let error_c = res.error.and_then(|e| CString::new(e).ok());

        let result = Box::new(CmdFfiResult {
            text_c,
            text_len,
            status: res.status as i32,
            error_c,
            metrics: CmdFfiMetrics {
                elapsed_ns: res.metrics.elapsed_ns,
                ast_nodes_initial: res.metrics.ast_nodes_initial,
                ast_nodes_final: res.metrics.ast_nodes_final,
                passes_executed: res.metrics.passes_executed,
                iocs_extracted: res.metrics.iocs_extracted,
                entropy_initial: res.metrics.entropy_initial,
                entropy_final: res.metrics.entropy_final,
            },
        });

        *out_result = Box::into_raw(result);
        StatusCode::Ok as i32
    }));

    outcome.unwrap_or(StatusCode::ErrExecutionFailed as i32)
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_extract_iocs(
    ctx: *mut CmdFfiContext,
    input: *const c_char,
    len: usize,
    flags: u32,
    out_result: *mut *mut CmdFfiResult,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if out_result.is_null() {
            return StatusCode::ErrNullPointer as i32;
        }

        let input_str = match parse_c_input(input, len) {
            Ok(s) => s,
            Err(err) => return err,
        };

        let deob = if !ctx.is_null() {
            &(*ctx).deobfuscator
        } else {
            static DEFAULT_DEOB: std::sync::OnceLock<CmdDeobfuscator> = std::sync::OnceLock::new();
            DEFAULT_DEOB.get_or_init(|| CmdDeobfuscator::new(DeobfuscateOptions::default()))
        };

        let res = deob.extract_iocs(input_str, flags);
        let text_len = res.text.len();
        let text_c = match CString::new(res.text) {
            Ok(c) => c,
            Err(_) => return StatusCode::ErrExecutionFailed as i32,
        };

        let result = Box::new(CmdFfiResult {
            text_c,
            text_len,
            status: res.status as i32,
            error_c: None,
            metrics: CmdFfiMetrics {
                elapsed_ns: res.metrics.elapsed_ns,
                ast_nodes_initial: res.metrics.ast_nodes_initial,
                ast_nodes_final: res.metrics.ast_nodes_final,
                passes_executed: res.metrics.passes_executed,
                iocs_extracted: res.metrics.iocs_extracted,
                entropy_initial: res.metrics.entropy_initial,
                entropy_final: res.metrics.entropy_final,
            },
        });

        *out_result = Box::into_raw(result);
        StatusCode::Ok as i32
    }));

    outcome.unwrap_or(StatusCode::ErrExecutionFailed as i32)
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_parse_ast(
    ctx: *mut CmdFfiContext,
    input: *const c_char,
    len: usize,
    flags: u32,
    out_result: *mut *mut CmdFfiResult,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if out_result.is_null() {
            return StatusCode::ErrNullPointer as i32;
        }

        let input_str = match parse_c_input(input, len) {
            Ok(s) => s,
            Err(err) => return err,
        };

        let deob = if !ctx.is_null() {
            &(*ctx).deobfuscator
        } else {
            static DEFAULT_DEOB: std::sync::OnceLock<CmdDeobfuscator> = std::sync::OnceLock::new();
            DEFAULT_DEOB.get_or_init(|| CmdDeobfuscator::new(DeobfuscateOptions::default()))
        };

        let res = deob.parse_ast(input_str, flags);
        let text_len = res.text.len();
        let text_c = match CString::new(res.text) {
            Ok(c) => c,
            Err(_) => return StatusCode::ErrExecutionFailed as i32,
        };

        let result = Box::new(CmdFfiResult {
            text_c,
            text_len,
            status: res.status as i32,
            error_c: None,
            metrics: CmdFfiMetrics {
                elapsed_ns: res.metrics.elapsed_ns,
                ast_nodes_initial: res.metrics.ast_nodes_initial,
                ast_nodes_final: res.metrics.ast_nodes_final,
                passes_executed: res.metrics.passes_executed,
                iocs_extracted: res.metrics.iocs_extracted,
                entropy_initial: res.metrics.entropy_initial,
                entropy_final: res.metrics.entropy_final,
            },
        });

        *out_result = Box::into_raw(result);
        StatusCode::Ok as i32
    }));

    outcome.unwrap_or(StatusCode::ErrExecutionFailed as i32)
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_result_get_text(result: *const CmdFfiResult) -> *const c_char {
    if result.is_null() {
        return ptr::null();
    }
    (*result).text_c.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_result_get_length(result: *const CmdFfiResult) -> usize {
    if result.is_null() {
        return 0;
    }
    (*result).text_len
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_result_get_status(result: *const CmdFfiResult) -> i32 {
    if result.is_null() {
        return StatusCode::ErrNullPointer as i32;
    }
    (*result).status
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_result_get_error(result: *const CmdFfiResult) -> *const c_char {
    if result.is_null() {
        return ptr::null();
    }
    match &(*result).error_c {
        Some(e) => e.as_ptr(),
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_result_get_metrics(
    result: *const CmdFfiResult,
    out_metrics: *mut CmdFfiMetrics,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if result.is_null() || out_metrics.is_null() {
            return StatusCode::ErrNullPointer as i32;
        }
        *out_metrics = (*result).metrics;
        StatusCode::Ok as i32
    }));

    outcome.unwrap_or(StatusCode::ErrExecutionFailed as i32)
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_result_free(result: *mut CmdFfiResult) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !result.is_null() {
            let boxed = Box::from_raw(result);
            let bytes = boxed.text_c.into_bytes_with_nul();
            let mut vec = bytes;
            zeroize_bytes(&mut vec);
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn cmd_ffi_zeroize(ptr: *mut u8, len: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !ptr.is_null() && len > 0 {
            let slice = std::slice::from_raw_parts_mut(ptr, len);
            zeroize_bytes(slice);
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VERSION;

    #[test]
    fn test_c_ffi_version() {
        unsafe {
            let ver = cmd_ffi_version();
            let cstr = CStr::from_ptr(ver);
            assert_eq!(cstr.to_str().unwrap(), VERSION);
        }
    }

    #[test]
    fn test_c_ffi_lifecycle() {
        unsafe {
            let mut ctx: *mut CmdFfiContext = ptr::null_mut();
            let opts = CmdFfiOptions {
                flags: 0x3F,
                max_passes: 5,
                timeout_ms: 1000,
                max_unroll_depth: 50,
            };
            let st = cmd_ffi_context_create(&opts, &mut ctx);
            assert_eq!(st, StatusCode::Ok as i32);
            assert!(!ctx.is_null());

            let input = CString::new("c^m^d.e^x^e /c echo 1").unwrap();
            let mut res: *mut CmdFfiResult = ptr::null_mut();

            let st_deob = cmd_ffi_deobfuscate(ctx, input.as_ptr(), 0, 0, &mut res);
            assert_eq!(st_deob, StatusCode::Ok as i32);
            assert!(!res.is_null());

            let text_ptr = cmd_ffi_result_get_text(res);
            assert!(!text_ptr.is_null());
            let out_text = CStr::from_ptr(text_ptr).to_str().unwrap();
            assert!(out_text.contains("cmd.exe"));

            let len = cmd_ffi_result_get_length(res);
            assert_eq!(len, out_text.len());

            let mut metrics = CmdFfiMetrics::default();
            let st_met = cmd_ffi_result_get_metrics(res, &mut metrics);
            assert_eq!(st_met, StatusCode::Ok as i32);

            cmd_ffi_result_free(res);
            cmd_ffi_context_destroy(ctx);
        }
    }

    #[test]
    fn test_c_ffi_zeroize() {
        unsafe {
            let mut buf = [0x55u8; 16];
            cmd_ffi_zeroize(buf.as_mut_ptr(), buf.len());
            assert!(buf.iter().all(|&b| b == 0));
        }
    }
}
