# forensic-hand

Sealed intake for forensic document examination. It runs on your computer. This is Stage 1.

It helps a human examiner. **It does not decide if a signature is genuine.**

## What it does

- **Seals the files.** It copies each file once, hashes it (SHA-256 and BLAKE2b), and sets the copy to read-only.
- **Keeps a locked log.** Each step is one line in `ledger.log`. Each line holds the hash of the line before it. An edit breaks the chain.
- **Gets a trusted time stamp** (only if you ask). A public time stamp authority signs the hash of the seal.
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

## Check a case

```powershell
.\.venv\Scripts\fhand.exe verify cases\my-case
```

The other side does not need this app. They unpack the zip and run:

```powershell
python verify_case.py <unpacked folder>
```

The checker tests the hash chain, each evidence file, each seal, and each time stamp.
It uses OpenSSL to test the signature of the time stamp. Exit code 0 means OK. Exit code 1 means a problem.

## Limits you must know

- The log cannot show events that someone removed from the **end** after the last seal. Seal often.
- A seal with no time stamp only has the clock of this computer. That clock can be wrong.
- Dates and program names inside a PDF are plain text. Anyone can edit them. A note is a lead, not proof.
- The tool does not test if a digital signature inside a PDF is valid.
- One writer at a time. Do not run two commands on the same case at once.

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
