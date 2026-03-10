# MEGALODON P2 — Process Memory Secret Scan Report

**Platform:** macOS Apple Silicon
**Date:** 2026-03-10 13:42:43

## Summary

| Application | PID | Regions | Bytes Scanned | Secrets | Duration |
|---|---|---|---|---|---|
| /Applications/1Password 7.app/Contents/MacOS/1Password 7 | 2946 | 260 | 4.6 GB | 3 | 85617ms |

## /Applications/1Password 7.app/Contents/MacOS/1Password 7 (PID 2946)

**3 secret(s) found:**

| # | Severity | Finding | Address | Size |
|---|---|---|---|---|
| 1 | CRITICAL | 1Password Account Key | 0x000000011d64f755 | 34 bytes |
| 2 | CRITICAL | 1Password Account Key | 0x000000011d843f1a | 34 bytes |
| 3 | CRITICAL | RSA Private Key (PEM) | 0x0000000c2a611c30 | 31 bytes |

*Note: Secret content is redacted. Raw values are not stored in reports.*


## Verdict

**3 secret(s) found (3 critical).** Applications are leaving sensitive material in process memory.

This indicates that the tested applications do not properly zeroize secret material after use.
On a system with local access (stolen laptop, evil-maid, compromised account), these secrets can be extracted.
