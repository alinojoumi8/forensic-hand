# Collecting real signature data for validation

Status: draft protocol. Check it against the current OSAC Registry and ASB documents on the
collection of known writing, and have a lawyer review the consent form before use.

Synthetic data shows how a method behaves. Only real, consented data can show error rates that
an expert may quote. This protocol is how to collect that data so that it is lawful, useful and
free of third-party licence limits.

## 1. What the data is for

Each person chooses, separately, what their samples may be used for. The tool enforces these
choices (`consent.csv`, scopes):

| Scope | Meaning |
|---|---|
| `benchmark` | Measure the tool internally. |
| `calibrate` | Set thresholds or a future likelihood-ratio model. |
| `train` | Train a future machine-learning model. |
| `publish` | Report results from this data in a public validation dossier. |

A person can withdraw at any time. Mark `withdrawn` as `yes`; the next run leaves their items out
and reports the count. Old dossiers keep the manifest hash that they used.

## 2. Who

- Writers: adults who give informed consent. Aim for a wide mix of ages, scripts, handedness and
  writing speed. Older and ill writers matter: tremor in a genuine signature must not look like forgery.
- Forgers: separate volunteers who imitate other participants' signatures (skilled forgeries).
  Give them time to practise with the genuine samples, as a real forger would.
- Never collect from people who cannot consent freely (for example, an employee asked by a manager).

## 3. What to collect per writer

| Item | Count | Notes |
|---|---|---|
| Genuine signatures, normal | 15 to 25 | Over at least 2 sessions on different days, to show natural variation. |
| Genuine signatures, other conditions | 5 each | Standing up, fast, slow, on a ruled line, in a small box. |
| Disguised signatures | 3 | The writer tries to make their own signature look different. Label `disguised`. |
| Skilled forgeries of this writer | 5 to 10 | By 2 or more forgers. Label `forgery-skilled`. |

Use more than one pen type (ballpoint, gel, felt-tip) and colour (black, blue). Record the pen in a note
column. Include sheets with real stamps (red, blue, violet, black) over some signatures: the copy check
separates inks by colour, and its hue rule was set on synthetic inks only.

## 4. Capture

- Flatbed scan at 600 DPI, 8-bit gray or 24-bit color, saved as PNG or TIFF (no JPEG).
- Also a phone photo of some sheets, to measure the photo case. Label `capture` as `photo`.
- To build copy pairs, make digital copies with a known process and label them `copy` with
  `source_item` set to the original item id.
- Keep the paper originals. A later study may need ink or indentation examination.

## 5. Privacy

- Use pseudonymous writer ids (for example `p017`). Keep the list that links ids to names in a
  separate, encrypted place, apart from the dataset.
- Signatures are personal information. Privacy law applies, such as PIPEDA in Canada or the GDPR in
  the European Union. Under the GDPR, signature data used to identify a person can be special-category
  data. Get legal advice on the lawful basis, storage, retention and transfer.
- Store the dataset encrypted. Share it only under a written agreement that keeps the consent scopes.

## 6. Build the manifest

```powershell
.\.venv\Scripts\fhand.exe dataset build D:\data\pilot --csv D:\data\pilot\items.csv --consent D:\data\pilot\consent.csv --title "Pilot collection 2027" --license-class own --license-name "Own collection under consent"
```

`items.csv` columns: `file, writer_id, kind, stratum, consent_id, capture, source_item, item_id, sample`.
For a degraded version of an item (for example the same sheet scanned at 150 DPI, `stratum` `dpi150`),
set `sample` to the `item_id` of the clean original. The validation uses this link to pair items.
`consent.csv` columns: `consent_id, scopes, date, withdrawn` (scopes separated by `;`).

Then check it and run the validation:

```powershell
.\.venv\Scripts\fhand.exe dataset verify D:\data\pilot\manifest.json
```

```powershell
.\.venv\Scripts\fhand.exe validate D:\data\pilot\manifest.json --out D:\data\pilot-validation --purpose publish
```

## 7. Data that must not be used

Most academic signature sets (for example GPDS-Synthetic, MCYT-75, and common copies of CEDAR and
BHSig260) allow non-commercial research only. Register such a set with `--license-class research-only`.
The tool then allows `benchmark` only: it refuses `calibrate`, `train` and `publish`. A set whose
licence is not known must be registered as `unknown`; the tool then refuses every use.
