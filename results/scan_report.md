# MEGALODON P2 — Process Memory Secret Scan Report

**Platform:** macOS Apple Silicon
**Date:** 2026-03-10 13:29:31

## Summary

| Application | PID | Regions | Bytes Scanned | Secrets | Duration |
|---|---|---|---|---|---|
| /System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari | 624 | 1559 | 4.6 GB | 7 | 62320ms |

## /System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari (PID 624)

**7 secret(s) found:**

| # | Severity | Finding | Address | Size |
|---|---|---|---|---|
| 1 | HIGH | Bearer Token | 0x000000012b27cb28 | 216 bytes |
| 2 | HIGH | AWS Access Key | 0x000000012da14681 | 20 bytes |
| 3 | HIGH | AWS Access Key | 0x000000012da148dc | 20 bytes |
| 4 | HIGH | AWS Access Key | 0x0000000133c30681 | 20 bytes |
| 5 | HIGH | AWS Access Key | 0x0000000133c308dc | 20 bytes |
| 6 | CRITICAL | RSA Private Key (PEM) | 0x000000087232aa30 | 31 bytes |
| 7 | HIGH | Bearer Token | 0x0000000c81128286 | 392 bytes |

*Note: Secret content is redacted. Raw values are not stored in reports.*


## Verdict

**7 secret(s) found (1 critical).** Applications are leaving sensitive material in process memory.

This indicates that the tested applications do not properly zeroize secret material after use.
On a system with local access (stolen laptop, evil-maid, compromised account), these secrets can be extracted.
