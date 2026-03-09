// Report generation — terminal output, markdown, and JSON reports

use crate::patterns::Severity;
use crate::scanner::SecretFinding;
use std::io::Write;

#[derive(Debug, Clone)]
pub struct AppReport {
    pub app_name: String,
    pub pid: i32,
    pub scan_duration_ms: u64,
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
    pub secrets: Vec<SecretFinding>,
}

/// Print findings to terminal with colors
pub fn print_findings(report: &AppReport) {
    let reset = "\x1b[0m";
    let dim = "\x1b[2m";

    eprintln!();
    eprintln!("    ┌─ {} (PID {}) ─────────────────────────────────", report.app_name, report.pid);
    eprintln!("    │ Regions: {}  Bytes: {}  Time: {}ms",
        report.regions_scanned,
        format_bytes(report.bytes_scanned),
        report.scan_duration_ms
    );

    if report.secrets.is_empty() {
        eprintln!("    │ {}No secrets found{}", dim, reset);
    } else {
        eprintln!("    │ \x1b[91m{} secret(s) found!{}", report.secrets.len(), reset);
        for s in &report.secrets {
            let color = s.severity.color_code();
            eprintln!("    │");
            eprintln!("    │  {}[{}]{} {}",
                color, s.severity.as_str(), reset, s.pattern_name);
            eprintln!("    │    Address:  0x{:016x}", s.address);
            eprintln!("    │    Size:     {} bytes", s.raw_length);
            eprintln!("    │    Preview:  {}", s.preview);
            eprintln!("    │    {}{}{}", dim, s.description, reset);
        }
    }
    eprintln!("    └───────────────────────────────────────────────────");
}

/// Write reports to files
pub fn write_report(reports: &[AppReport], output_dir: &str, json: bool) -> String {
    let md_path = format!("{}/scan_report.md", output_dir);
    let mut md = std::fs::File::create(&md_path).expect("Failed to create report");

    writeln!(md, "# MEGALODON P2 — Process Memory Secret Scan Report\n").unwrap();
    writeln!(md, "**Platform:** macOS Apple Silicon").unwrap();
    writeln!(md, "**Date:** {}\n", chrono_now()).unwrap();

    // Summary table
    writeln!(md, "## Summary\n").unwrap();
    writeln!(md, "| Application | PID | Regions | Bytes Scanned | Secrets | Duration |").unwrap();
    writeln!(md, "|---|---|---|---|---|---|").unwrap();
    for r in reports {
        writeln!(md, "| {} | {} | {} | {} | {} | {}ms |",
            r.app_name, r.pid, r.regions_scanned,
            format_bytes(r.bytes_scanned),
            r.secrets.len(), r.scan_duration_ms
        ).unwrap();
    }

    // Findings per app
    for r in reports {
        writeln!(md, "\n## {} (PID {})\n", r.app_name, r.pid).unwrap();
        if r.secrets.is_empty() {
            writeln!(md, "No secrets found in process memory.\n").unwrap();
        } else {
            writeln!(md, "**{} secret(s) found:**\n", r.secrets.len()).unwrap();
            writeln!(md, "| # | Severity | Finding | Address | Size |").unwrap();
            writeln!(md, "|---|---|---|---|---|").unwrap();
            for (i, s) in r.secrets.iter().enumerate() {
                writeln!(md, "| {} | {} | {} | 0x{:016x} | {} bytes |",
                    i + 1, s.severity.as_str(), s.pattern_name, s.address, s.raw_length
                ).unwrap();
            }
            writeln!(md, "\n*Note: Secret content is redacted. Raw values are not stored in reports.*\n").unwrap();
        }
    }

    // Verdict
    let total_secrets: usize = reports.iter().map(|r| r.secrets.len()).sum();
    let critical: usize = reports.iter()
        .flat_map(|r| &r.secrets)
        .filter(|s| s.severity == Severity::Critical)
        .count();

    writeln!(md, "\n## Verdict\n").unwrap();
    if total_secrets == 0 {
        writeln!(md, "No secrets found in process memory. Applications appear to handle secret cleanup correctly.").unwrap();
    } else {
        writeln!(md, "**{} secret(s) found ({} critical).** Applications are leaving sensitive material in process memory.", total_secrets, critical).unwrap();
        writeln!(md, "\nThis indicates that the tested applications do not properly zeroize secret material after use.").unwrap();
        writeln!(md, "On a system with local access (stolen laptop, evil-maid, compromised account), these secrets can be extracted.").unwrap();
    }

    // JSON output
    if json {
        let json_path = format!("{}/scan_report.json", output_dir);
        let mut jf = std::fs::File::create(&json_path).expect("Failed to create JSON report");
        writeln!(jf, "{{").unwrap();
        writeln!(jf, "  \"platform\": \"macOS Apple Silicon\",").unwrap();
        writeln!(jf, "  \"date\": \"{}\",", chrono_now()).unwrap();
        writeln!(jf, "  \"applications\": [").unwrap();
        for (idx, r) in reports.iter().enumerate() {
            writeln!(jf, "    {{").unwrap();
            writeln!(jf, "      \"name\": \"{}\",", r.app_name).unwrap();
            writeln!(jf, "      \"pid\": {},", r.pid).unwrap();
            writeln!(jf, "      \"regions_scanned\": {},", r.regions_scanned).unwrap();
            writeln!(jf, "      \"bytes_scanned\": {},", r.bytes_scanned).unwrap();
            writeln!(jf, "      \"scan_duration_ms\": {},", r.scan_duration_ms).unwrap();
            writeln!(jf, "      \"findings\": [").unwrap();
            for (si, s) in r.secrets.iter().enumerate() {
                writeln!(jf, "        {{").unwrap();
                writeln!(jf, "          \"name\": \"{}\",", s.pattern_name).unwrap();
                writeln!(jf, "          \"severity\": \"{}\",", s.severity.as_str()).unwrap();
                writeln!(jf, "          \"address\": \"0x{:016x}\",", s.address).unwrap();
                writeln!(jf, "          \"size\": {},", s.raw_length).unwrap();
                writeln!(jf, "          \"description\": \"{}\"", s.description).unwrap();
                if si < r.secrets.len() - 1 {
                    writeln!(jf, "        }},").unwrap();
                } else {
                    writeln!(jf, "        }}").unwrap();
                }
            }
            writeln!(jf, "      ]").unwrap();
            if idx < reports.len() - 1 {
                writeln!(jf, "    }},").unwrap();
            } else {
                writeln!(jf, "    }}").unwrap();
            }
        }
        writeln!(jf, "  ]").unwrap();
        writeln!(jf, "}}").unwrap();
    }

    // CSV for analysis
    let csv_path = format!("{}/findings.csv", output_dir);
    let mut csv = std::fs::File::create(&csv_path).expect("Failed to create CSV");
    writeln!(csv, "app,pid,severity,finding,address,size_bytes").unwrap();
    for r in reports {
        for s in &r.secrets {
            writeln!(csv, "{},{},{},{},0x{:016x},{}",
                r.app_name, r.pid, s.severity.as_str(), s.pattern_name, s.address, s.raw_length
            ).unwrap();
        }
    }

    md_path
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn chrono_now() -> String {
    // Simple timestamp without external dependency
    use std::process::Command;
    if let Ok(output) = Command::new("date").arg("+%Y-%m-%d %H:%M:%S").output() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        String::from("unknown")
    }
}
