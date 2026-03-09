# MEGALODON P2 — Process Memory Secret Scanner for Apple Silicon

Systematischer Scan von Prozessspeicher "sicherer" Anwendungen auf Apple Silicon (M1/M2/M3/M4) Macs. Findet Encryption Keys, Passwörter, Session Tokens und Private Keys die nach Gebrauch nicht aus dem RAM gelöscht wurden.

## Motivation

Die gesamte Memory-Forensik-Community hat Apple Silicon als Black Box aufgegeben:
- Volatility: kein Apple Silicon Support
- OSXPmem: Intel only, archiviert seit 2017
- DMA-Attacks: unmöglich auf Apple Silicon

Dieses Tool nutzt Apples eigene Developer-APIs (`task_for_pid`, `mach_vm_read`) um den Prozessspeicher direkt zu lesen. Kein Kernel-Exploit nötig — nur Root-Zugang und SIP disabled.

## Getestete Anwendungen

| App | Typ | Was wir suchen |
|-----|-----|----------------|
| Signal Desktop | Messenger | SQLCipher DB Key, Identity Keys, Plaintext Messages |
| 1Password | Password Manager | Master Password, Vault Keys, Account Key |
| Bitwarden | Password Manager | Master Encryption Key, Access Tokens |
| Telegram | Messenger | Auth Key, Session Data |
| GPG Agent | Encryption | Private Key Material, Passphrases |
| SSH Agent | Authentication | Private Key Bytes |

## Voraussetzungen

- macOS auf Apple Silicon (M1/M2/M3/M4)
- Rust toolchain (`rustup`)
- Root-Zugang
- SIP disabled (`csrutil disable` im Recovery Mode)

## Build

```bash
cargo build --release
```

## Usage

```bash
# Alle bekannten sicheren Apps scannen
sudo ./target/release/meg-scan --all

# Spezifische App scannen
sudo ./target/release/meg-scan --name "Signal"
sudo ./target/release/meg-scan --pid 12345 --app signal

# Laufende Ziel-Prozesse auflisten
sudo ./target/release/meg-scan --list

# JSON-Report generieren
sudo ./target/release/meg-scan --all --json --output ./results
```

## Output

- `results/scan_report.md` — Markdown-Report mit Findings
- `results/scan_report.json` — Maschinenlesbarer JSON-Report
- `results/findings.csv` — CSV für weitere Analyse

## Threat Model

**Angreifer:** Lokaler Zugriff mit Root-Rechten (gestohlener Laptop, Evil-Maid, kompromittierter Account, Malware mit Privilege Escalation).

**Annahme:** SIP ist disabled. Dies ist ein realistisches Szenario für Entwickler-Maschinen und in Umgebungen wo MDM oder Security-Tools SIP-Exceptions konfigurieren.

**Ziel:** Nachweis dass "sichere" Anwendungen sensitives Material im Prozessspeicher belassen, auch nachdem es nicht mehr benötigt wird. Korrekte Implementierung würde Secrets nach Gebrauch mit Nullen überschreiben (`memset_s`, `SecureZeroMemory`).

## Responsible Disclosure

Findings werden den betroffenen Entwicklern über ihre Bug-Bounty-Programme gemeldet bevor sie veröffentlicht werden.

## Kontext

Teil der **MEGALODON**-Forschungsreihe:
- **P1**: Timing Oracle on CRYSTALS-Kyber (Timing Side-Channel in PQC)
- **P2**: Process Memory Secret Scanner for Apple Silicon (dieses Repo)
- **P3**: RSA zerlegen mit Fermat/Pollard-Rho/Quadratic Sieve

---

*sectio-aurea-q · meg.depth@proton.me*
