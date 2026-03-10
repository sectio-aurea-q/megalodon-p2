// Pattern definitions for detecting secrets in process memory
// Each app has specific patterns that indicate exposed secrets.

/// A pattern to search for in memory
#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub pattern_type: PatternType,
}

#[derive(Debug, Clone)]
pub enum PatternType {
    /// Exact byte sequence
    Bytes(&'static [u8]),
    /// ASCII prefix followed by hex/base64 data of expected length
    PrefixThenData {
        prefix: &'static [u8],
        min_data_len: usize,
        max_data_len: usize,
        data_charset: DataCharset,
    },
    /// High-entropy region of specific size (likely key material)
    HighEntropy {
        min_len: usize,
        max_len: usize,
        min_entropy: f64,
    },
    /// Regex-like: printable ASCII string matching a shape
    AsciiShape {
        prefix: &'static str,
        min_len: usize,
        max_len: usize,
    },
}

#[derive(Debug, Clone)]
pub enum DataCharset {
    Hex,
    Base64,
    UpperAlphaNum,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Critical,  // encryption key, private key, master password
    High,      // session token, auth cookie, API key
    Medium,    // plaintext message, email address
    Low,       // metadata, username
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[91m",  // bright red
            Severity::High => "\x1b[93m",      // yellow
            Severity::Medium => "\x1b[96m",    // cyan
            Severity::Low => "\x1b[37m",       // white
        }
    }
}

/// Detect app type from process name
pub fn detect_app_type(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    if lower.contains("signal") { return Some("signal"); }
    if lower.contains("1password") || lower.contains("onepassword") { return Some("1password"); }
    if lower.contains("bitwarden") { return Some("bitwarden"); }
    if lower.contains("telegram") { return Some("telegram"); }
    if lower.contains("protonmail") || lower.contains("proton mail") { return Some("protonmail"); }
    if lower.contains("gpg") || lower.contains("gnupg") || lower.contains("gpg-agent") { return Some("gpg"); }
    if lower.contains("keychain") || lower.contains("securityd") { return Some("keychain"); }
    if lower.contains("ssh-agent") { return Some("ssh"); }
    if lower.contains("firefox") { return Some("firefox"); }
    if lower.contains("chrome") || lower.contains("chromium") { return Some("chrome"); }
    if lower.contains("slack") { return Some("slack"); }
    if lower.contains("discord") { return Some("discord"); }
    if lower.contains("whatsapp") { return Some("whatsapp"); }
    None
}

/// Get patterns for a specific app type
pub fn get_patterns(app_type: Option<&str>) -> Vec<SecretPattern> {
    let mut patterns = get_generic_patterns();

    if let Some(app) = app_type {
        match app {
            "signal" => patterns.extend(get_signal_patterns()),
            "1password" => patterns.extend(get_1password_patterns()),
            "bitwarden" => patterns.extend(get_bitwarden_patterns()),
            "telegram" => patterns.extend(get_telegram_patterns()),
            "gpg" => patterns.extend(get_gpg_patterns()),
            "ssh" => patterns.extend(get_ssh_patterns()),
            _ => {}
        }
    }

    patterns
}

/// Generic patterns applicable to any process
fn get_generic_patterns() -> Vec<SecretPattern> {
    vec![
        // RSA private key header
        SecretPattern {
            name: "RSA Private Key (PEM)",
            description: "RSA private key in PEM format found in memory",
            severity: Severity::Critical,
            pattern_type: PatternType::Bytes(b"-----BEGIN RSA PRIVATE KEY-----"),
        },
        // EC private key
        SecretPattern {
            name: "EC Private Key (PEM)",
            description: "Elliptic curve private key in PEM format",
            severity: Severity::Critical,
            pattern_type: PatternType::Bytes(b"-----BEGIN EC PRIVATE KEY-----"),
        },
        // Generic private key
        SecretPattern {
            name: "Private Key (PEM)",
            description: "Private key in PEM format",
            severity: Severity::Critical,
            pattern_type: PatternType::Bytes(b"-----BEGIN PRIVATE KEY-----"),
        },
        // OpenSSH private key
        SecretPattern {
            name: "OpenSSH Private Key",
            description: "OpenSSH format private key",
            severity: Severity::Critical,
            pattern_type: PatternType::Bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----"),
        },
        // Password patterns
        SecretPattern {
            name: "Password Field (JSON)",
            description: "JSON password field with value",
            severity: Severity::High,
            pattern_type: PatternType::AsciiShape {
                prefix: "\"password\":",
                min_len: 14,
                max_len: 200,
            },
        },
        SecretPattern {
            name: "Password Field (JSON alt)",
            description: "JSON passwd field with value",
            severity: Severity::High,
            pattern_type: PatternType::AsciiShape {
                prefix: "\"passwd\":",
                min_len: 12,
                max_len: 200,
            },
        },
        // Bearer tokens
        SecretPattern {
            name: "Bearer Token",
            description: "OAuth/API bearer token",
            severity: Severity::High,
            pattern_type: PatternType::AsciiShape {
                prefix: "Bearer eyJ",
                min_len: 20,
                max_len: 2048,
            },
        },
        // AWS keys — strict: AKIA + exactly 16 uppercase alphanumeric chars
        SecretPattern {
            name: "AWS Access Key",
            description: "AWS access key ID",
            severity: Severity::High,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"AKIA",
                min_data_len: 16,
                max_data_len: 16,
                data_charset: DataCharset::UpperAlphaNum,
            },
        },
        // GitHub tokens
        SecretPattern {
            name: "GitHub Token",
            description: "GitHub personal access token",
            severity: Severity::High,
            pattern_type: PatternType::AsciiShape {
                prefix: "ghp_",
                min_len: 40,
                max_len: 40,
            },
        },
        // High entropy 32-byte blocks (AES-256 keys)
        SecretPattern {
            name: "AES-256 Key Candidate",
            description: "32-byte high-entropy block (potential AES-256 key)",
            severity: Severity::Critical,
            pattern_type: PatternType::HighEntropy {
                min_len: 32,
                max_len: 32,
                min_entropy: 7.0,
            },
        },
        // High entropy 16-byte blocks (AES-128 keys)
        SecretPattern {
            name: "AES-128 Key Candidate",
            description: "16-byte high-entropy block (potential AES-128 key)",
            severity: Severity::Critical,
            pattern_type: PatternType::HighEntropy {
                min_len: 16,
                max_len: 16,
                min_entropy: 7.0,
            },
        },
    ]
}

/// Signal Desktop specific patterns
fn get_signal_patterns() -> Vec<SecretPattern> {
    vec![
        // SQLCipher key (64 hex chars) — older versions via config.json
        SecretPattern {
            name: "Signal SQLCipher Key",
            description: "Signal Desktop database encryption key in memory",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"\"key\":\"",
                min_data_len: 64,
                max_data_len: 64,
                data_charset: DataCharset::Hex,
            },
        },
        // SQLCipher key variant — sqlKey field
        SecretPattern {
            name: "Signal SQL Key",
            description: "Signal Desktop SQL encryption key",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"\"sqlKey\":\"",
                min_data_len: 64,
                max_data_len: 64,
                data_charset: DataCharset::Hex,
            },
        },
        // Encrypted key from safeStorage (newer versions)
        SecretPattern {
            name: "Signal Encrypted Key",
            description: "Signal safeStorage encrypted key material",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"\"encryptedKey\":\"",
                min_data_len: 32,
                max_data_len: 512,
                data_charset: DataCharset::Base64,
            },
        },
        // Signal storage key
        SecretPattern {
            name: "Signal Storage Key",
            description: "Signal storage service key",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"\"storageKey\":\"",
                min_data_len: 32,
                max_data_len: 128,
                data_charset: DataCharset::Base64,
            },
        },
        // Signal identity key
        SecretPattern {
            name: "Signal Identity Key",
            description: "Signal identity private key",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"identityKey",
                min_data_len: 32,
                max_data_len: 128,
                data_charset: DataCharset::Base64,
            },
        },
        // Signal profile key
        SecretPattern {
            name: "Signal Profile Key",
            description: "Signal profile encryption key",
            severity: Severity::High,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"\"profileKey\":\"",
                min_data_len: 32,
                max_data_len: 64,
                data_charset: DataCharset::Base64,
            },
        },
        // Plaintext messages
        SecretPattern {
            name: "Signal Message Body",
            description: "Plaintext Signal message in memory",
            severity: Severity::Medium,
            pattern_type: PatternType::AsciiShape {
                prefix: "\"body\":\"",
                min_len: 10,
                max_len: 4096,
            },
        },
    ]
}

/// 1Password specific patterns
fn get_1password_patterns() -> Vec<SecretPattern> {
    vec![
        // Master password
        SecretPattern {
            name: "1Password Master Password",
            description: "1Password master password or derived key in memory",
            severity: Severity::Critical,
            pattern_type: PatternType::AsciiShape {
                prefix: "masterPassword",
                min_len: 16,
                max_len: 512,
            },
        },
        // Account key (A3-xxx-xxx format)
        SecretPattern {
            name: "1Password Account Key",
            description: "1Password secret key / account key",
            severity: Severity::Critical,
            pattern_type: PatternType::AsciiShape {
                prefix: "A3-",
                min_len: 34,
                max_len: 34,
            },
        },
        // Vault key
        SecretPattern {
            name: "1Password Vault Key",
            description: "1Password vault encryption key",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"vaultKey",
                min_data_len: 32,
                max_data_len: 64,
                data_charset: DataCharset::Any,
            },
        },
    ]
}

/// Bitwarden specific patterns
fn get_bitwarden_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Bitwarden Master Key",
            description: "Bitwarden master encryption key",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"\"encKey\":\"",
                min_data_len: 64,
                max_data_len: 512,
                data_charset: DataCharset::Base64,
            },
        },
        SecretPattern {
            name: "Bitwarden Access Token",
            description: "Bitwarden API access token",
            severity: Severity::High,
            pattern_type: PatternType::AsciiShape {
                prefix: "\"accessToken\":\"",
                min_len: 20,
                max_len: 1024,
            },
        },
    ]
}

/// Telegram specific patterns
fn get_telegram_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Telegram Auth Key",
            description: "Telegram authorization key in memory",
            severity: Severity::Critical,
            pattern_type: PatternType::PrefixThenData {
                prefix: b"auth_key",
                min_data_len: 256,
                max_data_len: 256,
                data_charset: DataCharset::Any,
            },
        },
    ]
}

/// GPG specific patterns
fn get_gpg_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "GPG Secret Key Packet",
            description: "GPG/PGP secret key material in memory",
            severity: Severity::Critical,
            // Secret key packet tag: 0xC5 or 0x95
            pattern_type: PatternType::Bytes(&[0xC5]),
        },
        SecretPattern {
            name: "GPG Passphrase",
            description: "GPG passphrase cache in gpg-agent memory",
            severity: Severity::Critical,
            pattern_type: PatternType::AsciiShape {
                prefix: "passphrase",
                min_len: 12,
                max_len: 256,
            },
        },
    ]
}

/// SSH specific patterns
fn get_ssh_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "SSH Private Key Material",
            description: "SSH private key bytes in ssh-agent memory",
            severity: Severity::Critical,
            pattern_type: PatternType::Bytes(b"openssh-key-v1\x00"),
        },
    ]
}

/// Known process names to look for
pub fn known_target_processes() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Signal", "signal"),
        ("Signal Helper", "signal"),
        ("1Password", "1password"),
        ("1Password 7", "1password"),
        ("Bitwarden", "bitwarden"),
        ("Bitwarden Helper", "bitwarden"),
        ("Telegram", "telegram"),
        ("ProtonMail Bridge", "protonmail"),
        ("gpg-agent", "gpg"),
        ("ssh-agent", "ssh"),
        ("Firefox", "firefox"),
        ("Google Chrome", "chrome"),
        ("Slack", "slack"),
        ("Discord", "discord"),
        ("WhatsApp", "whatsapp"),
        ("securityd", "keychain"),
    ]
}

/// Calculate Shannon entropy of a byte slice
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
