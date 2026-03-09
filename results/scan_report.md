# MEGALODON P2 — Process Memory Secret Scan Report

**Platform:** macOS Apple Silicon
**Date:** 2026-03-09 22:11:13

## Summary

| Application | PID | Regions | Bytes Scanned | Secrets | Duration |
|---|---|---|---|---|---|
| /Applications/Tor Browser.app/Contents/MacOS/firefox | 640 | 517 | 622.2 MB | 1 | 8980ms |

## /Applications/Tor Browser.app/Contents/MacOS/firefox (PID 640)

**1 secret(s) found:**

| # | Severity | Finding | Address | Size |
|---|---|---|---|---|
| 1 | CRITICAL | RSA Private Key (PEM) | 0x0000000105fb5430 | 31 bytes |

*Note: Secret content is redacted. Raw values are not stored in reports.*


## Verdict

**1 secret(s) found (1 critical).** Applications are leaving sensitive material in process memory.

This indicates that the tested applications do not properly zeroize secret material after use.
On a system with local access (stolen laptop, evil-maid, compromised account), these secrets can be extracted.
