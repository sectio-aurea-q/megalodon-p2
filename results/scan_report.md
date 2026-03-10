# MEGALODON P2 — Process Memory Secret Scan Report

**Platform:** macOS Apple Silicon
**Date:** 2026-03-10 08:52:00

## Summary

| Application | PID | Regions | Bytes Scanned | Secrets | Duration |
|---|---|---|---|---|---|
| /Applications/Signal.app/Contents/MacOS/Signal | 1789 | 2076 | 1.2 GB | 32 | 30467ms |

## /Applications/Signal.app/Contents/MacOS/Signal (PID 1789)

**32 secret(s) found:**

| # | Severity | Finding | Address | Size |
|---|---|---|---|---|
| 1 | HIGH | Signal Profile Key | 0x0000011c004baab0 | 58 bytes |
| 2 | HIGH | Signal Profile Key | 0x0000011c004baba5 | 58 bytes |
| 3 | CRITICAL | RSA Private Key (PEM) | 0x0000011c008d7930 | 31 bytes |
| 4 | HIGH | Signal Profile Key | 0x0000011c02da4900 | 58 bytes |
| 5 | HIGH | Signal Profile Key | 0x0000011c02da49f4 | 58 bytes |
| 6 | HIGH | Signal Profile Key | 0x0000011c02dc427c | 58 bytes |
| 7 | HIGH | Signal Profile Key | 0x0000011c02dc438b | 58 bytes |
| 8 | HIGH | Signal Profile Key | 0x0000011c04a3aeb7 | 58 bytes |
| 9 | HIGH | Signal Profile Key | 0x0000011c04a3afac | 58 bytes |
| 10 | HIGH | Signal Profile Key | 0x0000011c055549fc | 58 bytes |
| 11 | HIGH | Signal Profile Key | 0x0000011c05554af1 | 58 bytes |
| 12 | HIGH | Signal Profile Key | 0x0000011c05cf26f6 | 58 bytes |
| 13 | HIGH | Signal Profile Key | 0x0000011c05cf27eb | 58 bytes |
| 14 | HIGH | Password Field (JSON) | 0x0000011c05e8ba21 | 83 bytes |
| 15 | HIGH | Password Field (JSON) | 0x0000135c03404cce | 83 bytes |
| 16 | HIGH | Password Field (JSON) | 0x0000135c03417ff2 | 83 bytes |
| 17 | HIGH | Password Field (JSON) | 0x0000135c0342679a | 83 bytes |
| 18 | HIGH | Signal Profile Key | 0x0000135c07d01525 | 58 bytes |
| 19 | HIGH | Signal Profile Key | 0x0000135c07d16cf8 | 58 bytes |
| 20 | HIGH | Signal Profile Key | 0x0000135c07d16dec | 58 bytes |
| 21 | HIGH | Signal Profile Key | 0x0000135c07d33a80 | 58 bytes |
| 22 | HIGH | Signal Profile Key | 0x0000135c07d33b8f | 58 bytes |
| 23 | HIGH | Password Field (JSON) | 0x0000135c07e4a95a | 83 bytes |
| 24 | HIGH | Signal Profile Key | 0x0000135c07e7f10c | 58 bytes |
| 25 | HIGH | Signal Profile Key | 0x0000135c07e7f21c | 58 bytes |
| 26 | HIGH | Password Field (JSON) | 0x0000135c07ed064a | 83 bytes |
| 27 | HIGH | Password Field (JSON) | 0x0000135c07ef5f02 | 83 bytes |
| 28 | HIGH | Signal Profile Key | 0x0000135c07ed75a8 | 58 bytes |
| 29 | HIGH | Signal Profile Key | 0x0000135c07ed76b8 | 58 bytes |
| 30 | HIGH | Signal Profile Key | 0x0000135c0946ac08 | 58 bytes |
| 31 | HIGH | Signal Profile Key | 0x0000135c0946acfd | 58 bytes |
| 32 | HIGH | Password Field (JSON) | 0x0000135c0bc095ca | 200 bytes |

*Note: Secret content is redacted. Raw values are not stored in reports.*


## Verdict

**32 secret(s) found (1 critical).** Applications are leaving sensitive material in process memory.

This indicates that the tested applications do not properly zeroize secret material after use.
On a system with local access (stolen laptop, evil-maid, compromised account), these secrets can be extracted.
