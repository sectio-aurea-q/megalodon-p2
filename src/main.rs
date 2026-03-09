// MEGALODON P2 — Process Memory Secret Scanner for Apple Silicon
// =============================================================
// Scans process memory of "secure" applications for residual secrets:
// encryption keys, plaintext passwords, session tokens, private keys.
//
// Requires: macOS, root privileges, SIP disabled (for task_for_pid)
// Usage: sudo ./meg-scan --pid <PID> [--app signal|1password|bitwarden|telegram|protonmail|gpg]
//        sudo ./meg-scan --name "Signal"
//        sudo ./meg-scan --all

mod mach_ffi;
mod scanner;
mod patterns;
mod report;

use std::env;
use std::process;
use std::time::Instant;

fn print_banner() {
    eprintln!("╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  MEGALODON P2 — Process Memory Secret Scanner               ║");
    eprintln!("║  Target: Apple Silicon (M1/M2/M3/M4)                        ║");
    eprintln!("║  sectio-aurea-q · meg.depth@proton.me                       ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    eprintln!();
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  sudo meg-scan --pid <PID>              Scan specific process by PID");
    eprintln!("  sudo meg-scan --name <process_name>    Scan process by name");
    eprintln!("  sudo meg-scan --all                    Scan all known secure apps");
    eprintln!("  sudo meg-scan --list                   List running target processes");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --app <name>     Hint which app (signal|1password|bitwarden|telegram|gpg)");
    eprintln!("  --output <dir>   Output directory for reports (default: ./results)");
    eprintln!("  --json           Output JSON report");
    eprintln!("  --verbose        Verbose output");
}

fn main() {
    print_banner();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    // Check root
    if !am_i_root() {
        eprintln!("[!] This tool requires root privileges.");
        eprintln!("    Run with: sudo {}", args[0]);
        process::exit(1);
    }

    let mut pid: Option<i32> = None;
    let mut proc_name: Option<String> = None;
    let mut scan_all = false;
    let mut list_only = false;
    let mut app_hint: Option<String> = None;
    let mut output_dir = String::from("./results");
    let mut json_output = false;
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--pid" => {
                i += 1;
                if i < args.len() {
                    pid = args[i].parse().ok();
                }
            }
            "--name" => {
                i += 1;
                if i < args.len() {
                    proc_name = Some(args[i].clone());
                }
            }
            "--all" => scan_all = true,
            "--list" => list_only = true,
            "--app" => {
                i += 1;
                if i < args.len() {
                    app_hint = Some(args[i].to_lowercase());
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output_dir = args[i].clone();
                }
            }
            "--json" => json_output = true,
            "--verbose" => verbose = true,
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => {
                eprintln!("[!] Unknown argument: {}", args[i]);
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    // Create output directory
    let _ = std::fs::create_dir_all(&output_dir);

    // List known target processes
    let targets = scanner::find_target_processes();

    if list_only {
        eprintln!("[*] Known secure applications currently running:\n");
        if targets.is_empty() {
            eprintln!("    (none found)");
        } else {
            for t in &targets {
                eprintln!("    PID {:>6}  {}", t.pid, t.name);
            }
        }
        process::exit(0);
    }

    // Determine what to scan
    let mut scan_targets: Vec<scanner::ProcessInfo> = Vec::new();

    if scan_all {
        scan_targets = targets;
        if scan_targets.is_empty() {
            eprintln!("[!] No known secure applications found running.");
            eprintln!("    Start Signal, 1Password, Bitwarden, Telegram, etc. and retry.");
            process::exit(1);
        }
    } else if let Some(p) = pid {
        let name = proc_name.unwrap_or_else(|| {
            scanner::get_process_name(p).unwrap_or_else(|| format!("pid_{}", p))
        });
        scan_targets.push(scanner::ProcessInfo { pid: p, name });
    } else if let Some(ref name) = proc_name {
        match scanner::find_process_by_name(name) {
            Some(info) => scan_targets.push(info),
            None => {
                eprintln!("[!] Process '{}' not found.", name);
                process::exit(1);
            }
        }
    } else {
        eprintln!("[!] Specify --pid, --name, or --all");
        print_usage();
        process::exit(1);
    }

    // Scan each target
    let mut all_findings: Vec<report::AppReport> = Vec::new();

    for target in &scan_targets {
        eprintln!("[*] Scanning: {} (PID {})", target.name, target.pid);
        let start = Instant::now();

        let app_type = app_hint.as_deref()
            .or_else(|| patterns::detect_app_type(&target.name));

        let findings = scanner::scan_process(target.pid, app_type, verbose);
        let elapsed = start.elapsed();

        let app_report = report::AppReport {
            app_name: target.name.clone(),
            pid: target.pid,
            scan_duration_ms: elapsed.as_millis() as u64,
            regions_scanned: findings.regions_scanned,
            bytes_scanned: findings.bytes_scanned,
            secrets: findings.secrets.clone(),
        };

        report::print_findings(&app_report);
        all_findings.push(app_report);
    }

    // Generate reports
    let report_path = report::write_report(&all_findings, &output_dir, json_output);
    eprintln!("\n[*] Report saved to: {}", report_path);

    // Summary
    let total_secrets: usize = all_findings.iter().map(|r| r.secrets.len()).sum();
    eprintln!("\n╔═══════════════════════════════════════════════════════════════╗");
    if total_secrets > 0 {
        eprintln!("║  RESULT: {} secret(s) found in {} application(s)            ║",
            total_secrets, all_findings.len());
        eprintln!("║  VERDICT: SECRETS EXPOSED IN PROCESS MEMORY                ║");
    } else {
        eprintln!("║  RESULT: No secrets found in {} application(s)              ║",
            all_findings.len());
        eprintln!("║  VERDICT: Memory appears clean                             ║");
    }
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
}

fn am_i_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
