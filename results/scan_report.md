# MEGALODON P2 — Process Memory Secret Scan Report

**Platform:** macOS Apple Silicon
**Date:** 2026-03-10 12:23:53

## Summary

| Application | PID | Regions | Bytes Scanned | Secrets | Duration |
|---|---|---|---|---|---|
| /Applications/Telegram.app/Contents/MacOS/Telegram | 2831 | 412 | 642.6 MB | 1 | 12796ms |

## /Applications/Telegram.app/Contents/MacOS/Telegram (PID 2831)

**1 secret(s) found:**

| # | Severity | Finding | Address | Size |
|---|---|---|---|---|
| 1 | CRITICAL | RSA Private Key (PEM) | 0x00000009277f5c30 | 31 bytes |

*Note: Secret content is redacted. Raw values are not stored in reports.*


## Verdict

**1 secret(s) found (1 critical).** Applications are leaving sensitive material in process memory.

This indicates that the tested applications do not properly zeroize secret material after use.
On a system with local access (stolen laptop, evil-maid, compromised account), these secrets can be extracted.
