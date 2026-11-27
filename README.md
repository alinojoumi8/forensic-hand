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

- No verdict. No match score. No machine learning model.
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
- Every dataset has a manifest with file hashes, a licence class and optional consent records.
  Research-only data may be used for internal benchmarks only; unknown licences are refused.
- **Synthetic results are not error rates on real casework.** The dossier says so. To collect real,
  consented data, see `docs/validation/collection-protocol.md`.

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
| `fhand validate MANIFEST --out FOLDER` | Measure the screens and write a validation dossier |

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
