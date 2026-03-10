# MEGALODON P2 — Process Memory Secret Scan Report

**Platform:** macOS Apple Silicon
**Date:** 2026-03-10 18:09:43

## Summary

| Application | PID | Regions | Bytes Scanned | Secrets | Duration |
|---|---|---|---|---|---|
| /Applications/Signal.app/Contents/MacOS/Signal | 649 | 1404 | 1.1 GB | 24 | 34823ms |

## /Applications/Signal.app/Contents/MacOS/Signal (PID 649)

**24 secret(s) found:**

| # | Severity | Finding | Address | Size |
|---|---|---|---|---|
| 1 | HIGH | Password Field (JSON) | 0x0000013c02da678c | 83 bytes |
| 2 | CRITICAL | Signal SQLCipher PRAGMA | 0x0000013c04494aa0 | 138 bytes |
| 3 | CRITICAL | Signal SQLCipher PRAGMA | 0x0000013c044952e0 | 138 bytes |
| 4 | CRITICAL | Signal SQLCipher PRAGMA | 0x0000013c044959a0 | 138 bytes |
| 5 | CRITICAL | Signal SQLCipher PRAGMA | 0x0000013c04495fa0 | 138 bytes |
| 6 | CRITICAL | Signal SQLCipher Hex Key | 0x0000013c04494aae | 66 bytes |
| 7 | CRITICAL | Signal SQLCipher Hex Key | 0x0000013c044952ee | 66 bytes |
| 8 | CRITICAL | Signal SQLCipher Hex Key | 0x0000013c044959ae | 66 bytes |
| 9 | CRITICAL | Signal SQLCipher Hex Key | 0x0000013c04495fae | 66 bytes |
| 10 | HIGH | Signal Profile Key | 0x0000013c04a737b6 | 58 bytes |
| 11 | HIGH | Signal Profile Key | 0x0000013c04a738ab | 58 bytes |
| 12 | HIGH | Password Field (JSON) | 0x0000013c04cfbe16 | 83 bytes |
| 13 | HIGH | Password Field (JSON) | 0x0000013c05069621 | 83 bytes |
| 14 | HIGH | Password Field (JSON) | 0x0000013c05069e74 | 83 bytes |
| 15 | CRITICAL | Signal SQLCipher PRAGMA | 0x0000174101bc4bac | 138 bytes |
| 16 | CRITICAL | Signal SQLCipher Hex Key | 0x0000174101bc4bba | 66 bytes |
| 17 | CRITICAL | Signal SQLCipher PRAGMA | 0x0000174101f45ca8 | 138 bytes |
| 18 | CRITICAL | Signal SQLCipher Hex Key | 0x0000174101f45cb6 | 66 bytes |
| 19 | CRITICAL | Signal SQLCipher PRAGMA | 0x00001741030b3cac | 138 bytes |
| 20 | CRITICAL | Signal SQLCipher Hex Key | 0x00001741030b3cba | 66 bytes |
| 21 | CRITICAL | Signal SQLCipher PRAGMA | 0x000017410b0ff3f4 | 138 bytes |
| 22 | CRITICAL | Signal SQLCipher Hex Key | 0x000017410b0ff402 | 66 bytes |
| 23 | HIGH | Password Field (JSON) | 0x000017410be5d43a | 200 bytes |
| 24 | HIGH | Password Field (JSON) | 0x0000174400542aba | 200 bytes |

*Note: Secret content is redacted. Raw values are not stored in reports.*


## Verdict

**24 secret(s) found (16 critical).** Applications are leaving sensitive material in process memory.

This indicates that the tested applications do not properly zeroize secret material after use.
On a system with local access (stolen laptop, evil-maid, compromised account), these secrets can be extracted.
