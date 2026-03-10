// Scanner module — reads process memory via Mach APIs and searches for secrets

use crate::mach_ffi;
use crate::patterns::{self, PatternType, SecretPattern, Severity, DataCharset};
use std::process::Command;

const MAX_REGION_SIZE: u64 = 256 * 1024 * 1024; // Skip regions > 256MB
const READ_CHUNK_SIZE: usize = 4 * 1024 * 1024;  // Read 4MB at a time

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub pattern_name: String,
    pub description: String,
    pub severity: Severity,
    pub address: u64,
    pub region_prot: String,
    pub preview: String,        // redacted preview of the finding
    pub raw_length: usize,      // length of the raw match
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
    pub secrets: Vec<SecretFinding>,
}

/// Find all known "secure" applications currently running
pub fn find_target_processes() -> Vec<ProcessInfo> {
    let known = patterns::known_target_processes();
    let mut found = Vec::new();

    if let Ok(output) = Command::new("ps").args(["-eo", "pid,comm"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
            if parts.len() < 2 { continue; }
            let pid: i32 = match parts[0].trim().parse() { Ok(p) => p, Err(_) => continue };
            let comm = parts[1].trim();

            for (target_name, _app_type) in &known {
                if comm.to_lowercase().contains(&target_name.to_lowercase()) {
                    found.push(ProcessInfo {
                        pid,
                        name: comm.to_string(),
                    });
                    break;
                }
            }
        }
    }
    found
}

/// Find a process by name
pub fn find_process_by_name(name: &str) -> Option<ProcessInfo> {
    if let Ok(output) = Command::new("ps").args(["-eo", "pid,comm"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
            if parts.len() < 2 { continue; }
            let pid: i32 = match parts[0].trim().parse() { Ok(p) => p, Err(_) => continue };
            let comm = parts[1].trim();
            if comm.to_lowercase().contains(&name.to_lowercase()) {
                return Some(ProcessInfo { pid, name: comm.to_string() });
            }
        }
    }
    None
}

/// Get process name from PID
pub fn get_process_name(pid: i32) -> Option<String> {
    if let Ok(output) = Command::new("ps").args(["-p", &pid.to_string(), "-o", "comm="]).output() {
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !name.is_empty() { return Some(name); }
    }
    None
}

/// Main scan function: attach to process, read memory, search for secrets
pub fn scan_process(pid: i32, app_type: Option<&str>, verbose: bool) -> ScanResult {
    let mut result = ScanResult {
        regions_scanned: 0,
        bytes_scanned: 0,
        secrets: Vec::new(),
    };

    // Get task port
    let task = match mach_ffi::get_task_for_pid(pid) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("    [!] {}", e);
            return result;
        }
    };

    // Get patterns for this app
    let pats = patterns::get_patterns(app_type);
    if verbose {
        eprintln!("    [*] Loaded {} patterns (app_type: {:?})", pats.len(), app_type);
    }

    // Enumerate memory regions
    let regions = mach_ffi::enumerate_regions(task);
    eprintln!("    [*] Found {} memory regions", regions.len());

    // Scan each readable region
    for region in &regions {
        if !region.is_readable() { continue; }
        if region.shared { continue; }  // skip shared regions (dyld cache etc)
        if region.size > MAX_REGION_SIZE { continue; }
        if region.size == 0 { continue; }

        // Focus on writable regions (heap, stack, data segments)
        // Keys and secrets are in writable memory
        if !region.is_writable() { continue; }

        result.regions_scanned += 1;

        // Read in chunks
        let mut offset: u64 = 0;
        while offset < region.size {
            let chunk_size = std::cmp::min(READ_CHUNK_SIZE as u64, region.size - offset) as usize;
            let addr = region.address + offset;

            if let Some(data) = mach_ffi::read_memory(task, addr, chunk_size) {
                result.bytes_scanned += data.len() as u64;

                // Search for each pattern
                for pat in &pats {
                    let matches = search_pattern(&data, pat, addr);
                    for m in matches {
                        // Deduplicate
                        if !result.secrets.iter().any(|s|
                            s.address == m.address && s.pattern_name == m.pattern_name
                        ) {
                            if verbose {
                                eprintln!("    [+] {} at 0x{:016x} ({})",
                                    m.pattern_name, m.address, m.severity.as_str());
                            }
                            result.secrets.push(m);
                        }
                    }
                }
            }
            offset += chunk_size as u64;
        }
    }

    result
}

/// Search for a single pattern in a memory chunk
fn search_pattern(data: &[u8], pattern: &SecretPattern, base_addr: u64) -> Vec<SecretFinding> {
    let mut findings = Vec::new();

    match &pattern.pattern_type {
        PatternType::Bytes(needle) => {
            for pos in find_all(data, needle) {
                findings.push(make_finding(pattern, base_addr + pos as u64, data, pos, needle.len()));
            }
        }

        PatternType::PrefixThenData { prefix, min_data_len, max_data_len, data_charset } => {
            for pos in find_all(data, prefix) {
                let after = pos + prefix.len();
                if after + *min_data_len > data.len() { continue; }

                let end = std::cmp::min(after + *max_data_len, data.len());
                let candidate = &data[after..end];

                let valid_len = match data_charset {
                    DataCharset::Hex => count_hex_chars(candidate),
                    DataCharset::Base64 => count_base64_chars(candidate),
                    DataCharset::UpperAlphaNum => count_upper_alphanum_chars(candidate),
                    DataCharset::Any => candidate.len(),
                };

                if valid_len >= *min_data_len {
                    let total_len = prefix.len() + valid_len;
                    findings.push(make_finding(pattern, base_addr + pos as u64, data, pos, total_len));
                }
            }
        }

        PatternType::HighEntropy { min_len, max_len, min_entropy } => {
            // Slide a window across writable memory looking for high-entropy blocks
            // Only check at aligned boundaries to avoid noise
            let step = *min_len;
            if data.len() < *max_len { return findings; }

            let mut pos = 0;
            while pos + *max_len <= data.len() {
                let block = &data[pos..pos + *max_len];

                // Quick pre-filter: skip if too many zeros or too many repeated bytes
                let zeros = block.iter().filter(|&&b| b == 0).count();
                if zeros > block.len() / 4 {
                    pos += step;
                    continue;
                }

                let entropy = patterns::shannon_entropy(block);
                if entropy >= *min_entropy {
                    // Additional check: is this preceded by a key-like context?
                    // Look backwards for markers like "key", "Key", "secret", etc.
                    let context_start = if pos >= 64 { pos - 64 } else { 0 };
                    let context = &data[context_start..pos];

                    if has_key_context(context) {
                        findings.push(make_finding(
                            pattern,
                            base_addr + pos as u64,
                            data,
                            pos,
                            *max_len,
                        ));
                    }
                }
                pos += step;
            }
        }

        PatternType::AsciiShape { prefix, min_len, max_len } => {
            let prefix_bytes = prefix.as_bytes();
            for pos in find_all(data, prefix_bytes) {
                let end = std::cmp::min(pos + *max_len, data.len());
                let candidate = &data[pos..end];

                // Find end of printable ASCII
                let ascii_len = candidate.iter()
                    .take_while(|&&b| b >= 0x20 && b < 0x7f)
                    .count();

                if ascii_len >= *min_len {
                    findings.push(make_finding(pattern, base_addr + pos as u64, data, pos, ascii_len));
                }
            }
        }
    }

    findings
}

/// Create a finding with redacted preview
fn make_finding(
    pattern: &SecretPattern,
    address: u64,
    data: &[u8],
    offset: usize,
    length: usize,
) -> SecretFinding {
    let end = std::cmp::min(offset + length, data.len());
    let raw = &data[offset..end];

    // Create redacted preview: show first 8 and last 4 bytes, mask the rest
    let preview = if raw.len() <= 16 {
        format_bytes_redacted(raw, 4, 4)
    } else {
        format_bytes_redacted(raw, 8, 4)
    };

    SecretFinding {
        pattern_name: pattern.name.to_string(),
        description: pattern.description.to_string(),
        severity: pattern.severity,
        address,
        region_prot: String::from("rw-"),
        preview,
        raw_length: length,
    }
}

/// Format bytes with redaction: show first N and last M, mask middle
fn format_bytes_redacted(data: &[u8], show_first: usize, show_last: usize) -> String {
    if data.len() <= show_first + show_last {
        // Try to show as ASCII if printable, else hex
        if data.iter().all(|&b| b >= 0x20 && b < 0x7f) {
            let s = String::from_utf8_lossy(data);
            if s.len() > show_first + 2 {
                return format!("{}...{} ({} bytes)",
                    &s[..show_first],
                    &s[s.len()-show_last..],
                    data.len()
                );
            }
            return format!("\"{}\"", s);
        }
        return hex_preview(data, 16);
    }

    if data.iter().take(show_first).all(|&b| b >= 0x20 && b < 0x7f) {
        let s = String::from_utf8_lossy(&data[..show_first]);
        return format!("\"{}\"...[{} bytes redacted] ({} total)",
            s, data.len() - show_first - show_last, data.len());
    }

    let first: String = data[..show_first].iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    let last: String = data[data.len()-show_last..].iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");

    format!("{}...[redacted]...{} ({} bytes)", first, last, data.len())
}

fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let show = std::cmp::min(data.len(), max_bytes);
    let hex: String = data[..show].iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    if data.len() > max_bytes {
        format!("{}... ({} bytes)", hex, data.len())
    } else {
        hex
    }
}

/// Find all occurrences of needle in haystack
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    let mut positions = Vec::new();
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        if let Some(pos) = haystack[start..].windows(needle.len())
            .position(|w| w == needle)
        {
            positions.push(start + pos);
            start = start + pos + 1;
        } else {
            break;
        }
    }
    positions
}

fn count_hex_chars(data: &[u8]) -> usize {
    data.iter()
        .take_while(|&&b| b.is_ascii_hexdigit())
        .count()
}

fn count_base64_chars(data: &[u8]) -> usize {
    data.iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        .count()
}

fn count_upper_alphanum_chars(data: &[u8]) -> usize {
    data.iter()
        .take_while(|&&b| b.is_ascii_uppercase() || b.is_ascii_digit())
        .count()
}

/// Check if a context region contains key-related keywords
fn has_key_context(context: &[u8]) -> bool {
    let s = String::from_utf8_lossy(context).to_lowercase();
    let markers = [
        "key", "secret", "password", "passwd", "token",
        "cipher", "crypt", "aes", "hmac", "auth",
        "private", "master", "session", "salt", "iv",
        "nonce", "derivedkey", "enckey", "deckey",
    ];
    markers.iter().any(|m| s.contains(m))
}
