# Stage 1 test record: sealed intake

Date: 2026-11-26. Tool version: 0.1.0. Python 3.14.5 on Windows 11.

## Source plan

No plan file. The journeys below came from the Stage 1 scope: hash, time stamp, locked log, quality warnings, PDF tamper check.

## User journeys

1. As an examiner, I want to put files into a case, so that I can prove later that they did not change.
2. As an examiner, I want a trusted time stamp, so that the time does not depend on my own clock.
3. As an examiner, I want warnings about weak scans and too few known samples, before I start to compare.
4. As an examiner, I want to see signs of PDF changes, each with its limits, so that I do not overstate them.
5. As the other side's expert, I want to check the case with a tool that I can read, with no install.

## RED and GREEN

| Step | Command | Result |
|---|---|---|
| RED | `.venv\Scripts\python.exe -m pytest` (tests written, no code yet) | `8 errors during collection`: `ImportError: cannot import name 'tsa' from 'forensic_hand'` and the same for the other modules. The cause was the missing code, as intended. |
| GREEN | same command, after the code was written | `129 passed, 1 skipped` (the skipped test needs the network) |
| Final | `$env:FHAND_NETWORK = "1"; .venv\Scripts\python.exe -m pytest --cov=forensic_hand` | `137 passed`, coverage 89% |
| Lint | `uvx ruff check src tests` | `All checks passed!` |

The project is not a git repository, so there are no checkpoint commits.

## What the tests guarantee

| # | Guarantee | Test file | Type |
|---|---|---|---|
| 1 | An edited, deleted or moved ledger line is detected. The hash covers the exact bytes of the line. | `tests/test_ledger.py` | unit |
| 2 | A stored file has identical bytes, is read-only, and the source is not touched. Bad input records nothing. | `tests/test_case.py` | unit |
| 3 | A correction is a new event. The old value stays in the ledger. | `tests/test_case.py` | unit |
| 4 | The ledger holds the file name, not the folder path. | `tests/test_case.py` | unit |
| 5 | Duplicate files, too few known samples, missing dates and distant dates are flagged. | `tests/test_case.py` | unit |
| 6 | Blur, low DPI, heavy JPEG compression, pure black-and-white and tiny pictures are flagged. A blank page is not called blurred. A broken file does not crash. | `tests/test_quality.py` | unit |
| 7 | Saves after the first write, bytes after a digital signature, a picture on top of a scan, typed text on a scan, annotations and trailing data are flagged. A linearized file is not a false alarm. | `tests/test_pdf_audit.py` | unit |
| 8 | Each finding states what it does not prove. | `tests/test_quality.py`, `tests/test_pdf_audit.py` | unit |
| 9 | The time stamp request is valid for an independent library (asn1crypto) and holds only the hash. A reply made by that library is parsed correctly. | `tests/test_tsa.py` | unit |
| 10 | A time stamp for other data, with a wrong random number, or refused by the server is not recorded. | `tests/test_seal_verify.py` | unit |
| 11 | One changed evidence bit, a missing file, a planted file, an edited seal and a cut ledger are all detected. | `tests/test_seal_verify.py` | integration |
| 12 | A broken or missing OpenSSL gives a note, never a false "bad time stamp". | `tests/test_seal_verify.py` | integration |
| 13 | The report escapes hostile text from file metadata and loads nothing from the network. | `tests/test_report.py` | unit |
| 14 | `intake` does not use the network unless `--timestamp` is given. | `tests/test_cli.py` | integration |
| 15 | An exported bundle verifies with Python run as `-I -S` (standard library only). A tampered bundle fails. | `tests/test_cli.py` | end to end |
| 16 | A real public time stamp server accepts the request, and OpenSSL accepts the signature of its reply. | `tests/test_tsa.py`, `tests/test_seal_verify.py` (network) | external |

## Proof outside the test files

The unit tests use files made by the test code. Those do not count as proof on real files.
These runs used other programs:

| What | How | Result |
|---|---|---|
| Real time stamp | DigiCert public server, 2026-11-26 | Granted. Token for the seal hash. |
| Signature of the token | OpenSSL 3.6.1 with roots from the Windows trust store, and OpenSSL 3.5.6 with the Mozilla root bundle | `Verification: OK` on both |
| Token fields | `openssl ts -reply -text` | Same time, hash and random number as our parser |
| File hashes | `sha256sum` on all 11 stored files | All 11 match |
| PDF from Microsoft Edge (print to PDF) | `fhand intake` | Clean letter: no notes. Scan with a pasted picture: `PDF-IMAGE-OVERLAY`. |
| PDF signed by pyHanko | `fhand intake` | Signed once and twice: no warning. Changed after signing: `PDF-SIG-AFTER` (916 bytes). |
| Scans and photo written by Pillow | `fhand intake` | 100 DPI: warning. 300 DPI blurred: warning. JPEG quality 35: warning. Clean files: no notes. |
| One bit changed in a copy of the case | `python -I -S verify_case.py` | Exit code 1, names item K1 |

## Faults that only the real runs found

1. An OpenSSL install with a missing configuration file made the checker report a bad time stamp. Fixed: the checker gives OpenSSL an empty configuration, and a tool failure is now a note. Tests added.
2. An A4 page at 150 DPI computed to 149.9 DPI and got a "too low" warning. Fixed: the value is rounded before the comparison. Test added.
3. The text of a PDF reader warning held a memory address, so two runs gave different text. Fixed. Test added.

## Known gaps

- **No real case file was tested.** No scan from a real scanner, no phone photo, no PDF from a real law office.
- The screening values in `config.py` are not validated. They are a first guess.
- Only one time stamp server was tried (DigiCert).
- Tested on Windows 11 with Python 3.14 only.
- Not covered by tests: about 11% of the lines, mostly error paths for broken PDF objects and rare OpenSSL failures.
- PDF: no visual comparison of the earlier versions inside a file yet. No test of the validity of a digital signature.

## CodeRabbit review 1 (2026-11-26)

Command: `coderabbit review --base main --committed --agent` (CodeRabbit CLI 0.9.7). 12 findings, all major.
All 12 were checked against the code and were real. All 12 are fixed. Tests: `tests/test_review_fixes.py`.

| # | Finding | Fix |
|---|---|---|
| 1 | Reused PDF drawings can expand to millions of placements | Shared work limit per file; `PDF-SCREEN-INCOMPLETE` warning |
| 2 | Checker checked only the first record of a shared file | Each record is compared with the file |
| 3 | Bad field types in the ledger crashed the checker | Fields are validated; any unexpected error is a problem (fail closed) |
| 4 | Checker did not say that an older copy can still pass | Stated in the output, the docstring and the README; last seal hash is printed |
| 5 | A failed seal append left a file that blocked the next seal | New file removed when the event is surely not written; a matching left-over file is taken over; a non-matching one is refused |
| 6 | Missing OpenSSL gave `OK` and exit code 0 | New status `incomplete`, exit code 3 |
| 7 | A stored file could stay writable | Read-only before it gets its final name; repaired on reuse |
| 8 | A failed time stamp append blocked a retry | Same handling as 5; a left-over token for this seal is taken over with no new request |
| 9 | The time stamp signature was not checked before it was recorded | OpenSSL checks it first; a bad signature is refused; "not checked" is recorded as such |
| 10 | OpenSSL reopened the files that Python had checked | OpenSSL gets a private copy of the response and the checked digest |
| 11 | A duplicate seal number hid the first seal | Duplicates are problems |
| 12 | An unreadable file crashed the checker | It is a problem that names the file |

Own fault found by the new tests: a time stamp file taken over from a stopped run was not set to read-only. Fixed.

Result after the fixes: 163 passed, 2 network tests passed (real DigiCert stamp, checked by OpenSSL at intake and in
the checker), coverage 91%, ruff clean. Stress test: 21,200 broken time stamp, PDF and image inputs, 0 crashes.

## CodeRabbit review 2 (2026-11-26)

Command: `coderabbit review --committed --base-commit e9b5b75 --agent` (the fixes only). 4 findings, all real, all fixed.

| # | Finding | Fix |
|---|---|---|
| 1 | README said every recorded stamp passed a signature check | README states the "not checked" case and the INCOMPLETE result |
| 2 | Over 1,000 small pictures could hide a full-page scan | The largest picture is always kept; crowded pages give `PDF-SCREEN-INCOMPLETE` |
| 3 | A compressed drawing was fully decoded before the work limit counted | Decoded size is measured in steps (capped) before the drawing is read: 4 MB per drawing, 64 MB per file |
| 4 | Tests used `os.access` for read-only checks (wrong for admin users) | Tests and store use the file mode bits |

Result: 173 passed (including the 2 network tests), coverage 91%, ruff clean, 21,200 fuzz inputs with 0 crashes.
The Edge, pyHanko and Pillow files give the same findings as before.
