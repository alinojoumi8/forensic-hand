# forensic-hand

Sealed intake for forensic document examination. It runs on your computer. This is Stage 1.

It helps a human examiner. **It does not decide if a signature is genuine.**

## What it does

- **Seals the files.** It copies each file once, hashes it (SHA-256 and BLAKE2b), and sets the copy to read-only.
- **Keeps a locked log.** Each step is one line in `ledger.log`. Each line holds the hash of the line before it. An edit breaks the chain.
- **Gets a trusted time stamp** (only if you ask). A public time stamp authority signs the hash of the seal.
  OpenSSL checks that signature before the stamp is recorded, and a bad signature is refused.
  If OpenSSL cannot run, the stamp is recorded as "not checked", and the checker reports INCOMPLETE
  (exit code 3) until the signature is checked on a computer with OpenSSL.
- **Screens quality.** Resolution, blur, JPEG compression, number and dates of known samples.
- **Screens PDF structure.** Saves after the first write, changes after a digital signature, pictures pasted on a scan, typed text on a scan, annotations, mismatched metadata.
- **Writes a report.** One HTML file. It loads nothing from the internet.
- **Gives the other side a checker.** `verify_case.py` is one file of plain Python. It needs no install.

## What it does not do

- No verdict. No machine learning model. No score unless a calibration passed its pre-registered test on
  real, consented data (Stage 4); until then every case says "No score".
- It cannot replace an examination of the original paper. The report says this each time.
- The screening values are **not validated on real casework**. A qualified examiner decides.

## Privacy

Nothing leaves your computer unless you add `--timestamp`.
With `--timestamp`, one 32-byte hash and one random number go to the time stamp server. No file, no name, no text.

## Start a case

```powershell
.\.venv\Scripts\fhand.exe intake cases\my-case --title "My case" --questioned "C:\path\questioned.pdf" --known "C:\path\known1.png" "C:\path\known2.png"
```

Add `--timestamp` at the end for a trusted time stamp. Then open `cases\my-case\reports\report.html`.

## Workbench (Stage 2)

```powershell
.\.venv\Scripts\fhand.exe serve cases\my-case
```

Your browser opens the case. Nothing leaves your computer. You can:

- **Crop** a signature: choose Crop, drag a box, give it a name. A picture crop keeps the exact pixels of
  the file. A PDF crop is drawn by PDFium at a stated resolution (by default, the resolution of the scan).
- **Compare** 2 to 4 crops side by side at the same physical scale, or **overlay** two crops (red and blue)
  and align them by hand.
- **Measure** a line (length in mm and angle) or the angle between two lines.
- **Copy check**: look for crops that match point for point, as a digital cut and paste does.
- **Chart**: make a comparison chart for court, at the same scale, with a 10 mm bar and its method notes.
- **Notes**: write observations. A correction is a new note; the old text stays in the ledger.
- **Seal** and **Report** from the top bar.

Every action is one event in the ledger. Crops and charts are stored by their SHA-256, set to read-only, and
listed in the next seal. The checker tests them like the evidence files.

Safety: the workbench listens on 127.0.0.1 only and needs the one-time key in the address that it prints.
Do not share that address. Press Ctrl+C in its window to stop it.

## Validation (Stage 3)

A screen is only useful when its error rates are known. Stage 3 measures them.

```powershell
.\.venv\Scripts\fhand.exe synth data\synth-s1 --writers 12 --seed 1
```

```powershell
.\.venv\Scripts\fhand.exe validate data\synth-s1\manifest.json --out data\validation-s1
```

- `synth` makes labelled signatures with the Sigma-Lognormal model of pen movement: genuine
  signatures, skilled forgeries (slower, shaky, blunt ends) and digital copies, each in six
  conditions (clean, ruled line, stamp, blur, JPEG, 150 DPI).
- `validate` runs the copy check, the blur screen and the JPEG estimate on that data, and writes
  `dossier.html` and `dossier.json`: rates with 95% intervals, AUC, EER, the data hashes, the
  settings and a results hash. The same data and settings give the same results hash.
- `validate` also measures the **raw writer score** (Stage 4): 12 fixed measures of the ink (shape,
  slant, line width, line quality, loops), compared with 5 known signatures. 0 means "as close to the
  known signatures as they are to each other". It is not a likelihood ratio, and a case cannot use it.
  It needs 6 or more genuine signatures per writer: make the data with `--genuine 8 --forgeries 3`.
- Every dataset has a manifest with file hashes, a licence class and optional consent records.
  Research-only data may be used for internal benchmarks only; unknown licences are refused.
- `calibrate` turns the raw score into a **likelihood ratio (LR)**: how much more likely the score is if
  the known writer wrote the signature (Hp) than if someone else did (Hd: a skilled forger, or a random
  other writer). The LR is kept inside bounds that the amount of data supports. Licence and consent must
  allow `calibrate`. A calibration on synthetic data is a **demo**; on real data it is a **candidate**.
  No case can use either: a case needs a released calibration (see the plan, phases 3 and 4).
- `validate --calibration FILE` measures a calibration on other writers: Cllr (0 is perfect, 1 is no
  better than always saying LR 1), Cllr-min, the rates of misleading evidence with 95% intervals that
  resample whole writers, and a Tippett plot. It warns when a writer was also used to calibrate.

```powershell
.\.venv\Scripts\fhand.exe synth data\cal-set --writers 20 --genuine 8 --forgeries 3 --seed 4 --writer-prefix c
```

```powershell
.\.venv\Scripts\fhand.exe calibrate data\cal-set\manifest.json --propositions skilled-forgery --out data\cal.json
```

```powershell
.\.venv\Scripts\fhand.exe validate data\test-set\manifest.json --calibration data\cal.json --out data\lr-test
```

- **Release (the lock).** A case can use a calibration only after a release. Write the pass marks first
  (`prereg`), time stamp them (`stamp-file`), and only then run the test with `validate --purpose publish
  --calibration ... --criteria ...`. Time stamp the dossier, then run `release`. It refuses if the data was
  synthetic, if a file changed after its stamp, if the test was stamped before the pass marks, if it tested
  other data than the marks named, if a test writer was also used to calibrate, or if any mark failed.
  The stamps prove the order of the files; they cannot prove that nobody ran the test earlier. Keep the
  test data unopened until the marks are stamped. The proposed marks (Cllr 0.5 or less, misleading evidence
  for Hd 5% or less, 30 writers, 5 forgeries per writer, 2 forgers) must be confirmed with examiners.

```powershell
.\.venv\Scripts\fhand.exe prereg data\cal.json --test data\test-set\manifest.json --out data\marks.json
```

```powershell
.\.venv\Scripts\fhand.exe stamp-file data\marks.json
```

```powershell
.\.venv\Scripts\fhand.exe validate data\test-set\manifest.json --purpose publish --calibration data\cal.json --criteria data\marks.json --out data\test-run
```

```powershell
.\.venv\Scripts\fhand.exe stamp-file data\test-run\dossier.json
```

```powershell
.\.venv\Scripts\fhand.exe release --calibration data\cal.json --criteria data\marks.json --dossier data\test-run\dossier.json --out data\release.json
```

- **Synthetic results are not error rates on real casework.** The dossier says so. To collect real,
  consented data, see `docs/validation/collection-protocol.md`.

## Score in a case (Stage 4)

A case shows a likelihood ratio only with a release file. Without one, the report says **No score**,
and the workbench Score button says **Locked**.

```powershell
.\.venv\Scripts\fhand.exe score cases\my-case --release data\release.json --questioned C1 --known C2 C3 C4 C5 C6
```

- The release is checked again each time: every release check, and the signatures of its two time stamps.
- The case must be inside what the test covered, or there is no score: exactly the tested number of known
  crops (from known items), a questioned crop from a questioned item, the tested resolution range, no quality
  warning for a condition that was not tested, no stamp when stamps were not tested. Run `fhand check` first.
- The release file is kept in the case (`models/`, read-only) and listed in the next seal. The score, its
  measures, the LR, the propositions and the release facts are one ledger event.
- The checker (`verify_case.py`) tests the release's time stamps and recomputes each LR from its recorded raw
  score. It does not measure the crops again: that needs this app.
- The report shows the LR, a verbal equivalent (after the ENFSI 2015 scale; check the scale your laboratory
  uses), the propositions, the tested conditions, the test results and the limits. **The examiner decides.**

## Commands

| Command | What it does |
|---|---|
| `fhand intake CASE --title T --questioned F... --known F...` | All steps at once: new case, add, check, seal, report |
| `fhand new CASE --title T` | Make an empty case |
| `fhand add CASE F... --role questioned\|known\|other [--date 2021-05-03] [--signer NAME]` | Add files |
| `fhand date CASE K1 2021-05-03` | Set or correct a document date. The old value stays in the log |
| `fhand check CASE` | Run the screens |
| `fhand seal CASE [--timestamp]` | Seal the present state |
| `fhand stamp CASE` | Get a time stamp for the last seal |
| `fhand report CASE` | Write `reports\report.html` and `reports\report.json` |
| `fhand verify CASE` | Check that nothing changed |
| `fhand export CASE out.zip` | Pack the case for another party |
| `fhand serve CASE` | Open the workbench in your browser (this computer only) |
| `fhand synth OUT [--writers N --seed S]` | Make a labelled synthetic dataset |
| `fhand dataset verify MANIFEST` | Check every file of a dataset against its manifest |
| `fhand dataset build FOLDER --csv items.csv ...` | Make a manifest for a real collection |
| `fhand validate MANIFEST --out FOLDER [--calibration FILE]` | Measure the screens (and the LRs of a calibration) and write a validation dossier |
| `fhand calibrate MANIFEST --propositions skilled-forgery\|other-writer --out FILE` | Fit the writer score to a likelihood ratio |
| `fhand prereg CALIBRATION --test MANIFEST --out FILE [--cllr-max 0.5 ...]` | Write the pass marks before the test |
| `fhand stamp-file FILE` | Get a trusted time stamp for a file (sends one hash out) |
| `fhand release --calibration C --criteria M --dossier D --out FILE` | Release a calibration that passed every check |
| `fhand score CASE --release FILE --questioned CROP --known CROP...` | Likelihood ratio for a questioned crop |

## Check a case

```powershell
.\.venv\Scripts\fhand.exe verify cases\my-case
```

The other side does not need this app. They unpack the zip and run:

```powershell
python verify_case.py <unpacked folder>
```

The checker tests the hash chain, each evidence file, each seal, and each time stamp.
It uses OpenSSL to test the signature of the time stamp.

| Exit code | Meaning |
|---|---|
| 0 | OK |
| 1 | Problems found |
| 3 | Incomplete: no problem found, but a check could not run (for example, no OpenSSL) |

Use `--skip-tsa-signature` to check the structure only, with no OpenSSL.

## Limits you must know

- The checker cannot tell if you have the **newest** copy. An older copy, or a copy with the last events,
  seals or time stamps removed, can still pass. Send the last seal hash by a separate route
  (for example, in the covering letter), so that the other side can compare it.
- A seal with no time stamp only has the clock of this computer. That clock can be wrong.
- Dates and program names inside a PDF are plain text. Anyone can edit them. A note is a lead, not proof.
- The tool does not test if a digital signature inside a PDF is valid.
- One writer at a time: a lock file (`ledger.lock`) makes a second writer wait. It is not part of the case.
- The copy check is a screen. Its values were tuned on synthetic lines only, not on real casework.
  It removes long straight printed lines, and a stamp of another colour than the pen (it records which
  colour it kept). A stamp in the pen's own colour, or a near hue, still lowers the score: crop tightly.
- A PDF crop is a new drawing of the page. Above the resolution of the scan, it shows no new detail.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Two tests contact a real time stamp server. They are off by default. To run them:

```powershell
$env:FHAND_NETWORK = "1"; .\.venv\Scripts\python.exe -m pytest
```

## Set up on a new computer

```powershell
uv venv --python 3.14 .venv
```

```powershell
uv pip install --python .venv\Scripts\python.exe -e ".[dev]"
```

## Where things are

| File | Job |
|---|---|
| `src/forensic_hand/verify_case.py` | The checker. Standard library only. Also defines the log format |
| `src/forensic_hand/ledger.py`, `store.py`, `case.py` | Locked log, file store, case state |
| `src/forensic_hand/quality.py`, `pdf_audit.py`, `checks.py` | The screens |
| `src/forensic_hand/tsa.py`, `seal.py` | Time stamp and seal |
| `src/forensic_hand/report.py`, `export.py`, `cli.py` | Report, bundle, commands |
| `src/forensic_hand/config.py` | The screening values. Each run records them in the log |
| `src/forensic_hand/pages.py`, `work.py`, `clones.py`, `exhibit.py` | Pages, crops, notes, measurements, copy check, charts |
| `src/forensic_hand/server.py`, `web/` | The local workbench server and the browser screen |
| `src/forensic_hand/synth.py`, `datasets.py`, `validation.py`, `metrics.py` | Test data, licence and consent gates, validation |
| `src/forensic_hand/writer.py` | The measures of a signature and the raw writer score (Stage 4) |
| `src/forensic_hand/calibrate.py` | Score to likelihood ratio: fit, bounds, calibration file (Stage 4) |
| `src/forensic_hand/prereg.py`, `release.py` | Pass marks, file time stamps and the release gate (Stage 4) |

## License

Copyright (C) 2026 alinojoumi8.

forensic-hand is free software under the GNU Affero General Public License, version 3 or later
(AGPL-3.0-or-later). See `LICENSE`. In short: you may use, study, change and share it. If you share a
changed version, or offer it to others over a network, you must publish your changed source code under
the same license.

For a commercial license without these terms, contact the copyright holder.

Third-party parts keep their own licenses: Pillow (MIT-CMU), NumPy (BSD-3-Clause), pikepdf (MPL-2.0),
pypdfium2 and PDFium (Apache-2.0 / BSD-3-Clause).

This tool supports a qualified examiner. It is not a verdict tool, and it comes with no warranty
(see sections 15 and 16 of the license).

