# Plan: Stage 4, the locked score

Status: draft plan, 2026-11-27. No code is written yet.
Complexity: Large (4 code phases and 1 data phase).

## Summary

Stage 4 adds a number: a **likelihood ratio (LR)**. The LR tells how much more likely the
handwriting is if the named person wrote it than if someone else (a skilled forger) wrote it.

The number is **locked**. A case can show it only when a real, consented data set has tested it,
against pass marks that were written down (and time stamped) before the test. Synthetic data can
never unlock it. Until real data passes, the tool says "No score: this method is not validated"
and gives no number.

This keeps the rule from the start of the project: no score until the data proves it.

## What is true today

- Stage 3 measures the screens on synthetic data only. No real data set exists yet.
- The licence gate and the consent gate exist (`datasets.py`). Consent already has a `calibrate`
  scope and a `publish` scope.
- So after Stage 4, the score stays locked in every real case until the pilot data (Phase 5) passes.

## Requirements

1. **Explainable score.** Measured features of the signature (shape, slant, spacing, stroke width,
   ink spread). No trained neural network: it needs training data and licences that we do not have,
   and it is hard to explain in court.
2. **Calibrated LR.** The raw score becomes an LR with a simple fit (2 numbers). The LR is limited to
   what the data size can support (the "empirical lower and upper bound", ELUB).
3. **Stated propositions.** Each LR names its two propositions, for example
   "Hp: the known writer wrote it" and "Hd: a skilled forger wrote it". Only pairs that the
   validation tested are allowed.
4. **Hard gate.** A calibration is usable in a case only if all of these are true:
   - It was fitted on real data (not synthetic), licence `own` or `commercial`, and every item has
     consent scope `calibrate`.
   - A separate real data set tested it. No writer is in both sets. Every item has consent scope `publish`.
   - The pass marks (criteria) were hashed before the test, and the test passed them all.
   - The case is inside the tested conditions (capture type, resolution, number of known samples).
   There is no override flag.
5. **Checkable.** The other side's checker (`verify_case.py`, standard library only) can recompute the
   LR from the recorded raw score and the calibration file, and can check the calibration file hash.
6. **Same habits as Stages 1 to 3.** Each step is one ledger event. Same data and settings give the
   same results hash. Tests first.

## Patterns to mirror

| Category | Source | Pattern |
|---|---|---|
| Naming | `src/forensic_hand/cli.py:172` | One `cmd_<name>` per command; one module per job |
| Naming | `src/forensic_hand/validation.py:118` | One `<name>_task` function per validation task |
| Errors | `src/forensic_hand/datasets.py:38` | A plain `Exception` subclass with a plain-English message |
| Errors | `src/forensic_hand/cli.py:28` | The CLI prints `error: ...` to stderr |
| Ledger | `src/forensic_hand/work.py:25` | `_record` appends one event; it removes a stored file if the append fails |
| Results | `src/forensic_hand/validation.py:216` | Results hash over the dossier, without the clock time |
| Settings | `src/forensic_hand/config.py:8` | Values in `DEFAULTS`, one comment each; the hash goes in the log |
| Checker | `src/forensic_hand/verify_case.py:449` | Made files are checked by hash; standard library only |
| Tests | `tests/test_validation.py:1` | pytest, `parametrize`, `approx`, the CLI through `main()` |

## Files to change

| File | Action | Why |
|---|---|---|
| `src/forensic_hand/writer.py` | CREATE | Features of one crop, and the raw score of a questioned crop against known crops |
| `src/forensic_hand/calibrate.py` | CREATE | Score to LR fit, ELUB bounds, calibration file, release gate |
| `src/forensic_hand/prereg.py` | CREATE | Pass marks file: write, hash, time stamp, check |
| `src/forensic_hand/metrics.py` | UPDATE | Cllr, Cllr-min (PAV), rates of misleading evidence, Tippett data, writer-level bootstrap |
| `src/forensic_hand/validation.py` | UPDATE | New task `writer-score`; LR section in the dossier |
| `src/forensic_hand/config.py` | UPDATE | Score settings (feature list, minimum known samples) |
| `src/forensic_hand/work.py` | UPDATE | `run_score`: one ledger event per score |
| `src/forensic_hand/report.py` | UPDATE | Score section: LR, propositions, conditions, limits; or "No score" and why |
| `src/forensic_hand/server.py`, `web/*` | UPDATE | Score panel in the workbench; shows lock state |
| `src/forensic_hand/verify_case.py` | UPDATE | Check the calibration file hash and recompute the LR |
| `src/forensic_hand/cli.py` | UPDATE | `calibrate`, `prereg`, `release`, `score` |
| `tests/test_writer.py`, `test_calibrate.py`, `test_prereg.py`, `test_score.py` | CREATE | Tests first, per phase |
| `README.md`, `docs/validation/collection-protocol.md` | UPDATE | New commands; data split and sizes for the pilot |

## Phases

Each phase is its own branch and pull request, reviewed with CodeRabbit before merge.

### Phase 1: Features and raw score (branch `feat/stage4-writer-score`)

- Use the same ink preparation as the copy check (`clones.prepare`): ink separation, ruled lines removed.
- Features per crop: aspect ratio; ink density on a coarse grid; slant histogram; stroke width
  spread; direction histogram; row and column ink profiles; number of ink parts and loops.
- Raw score: distance from the questioned crop to the known crops, scaled by how much the known
  crops differ from each other. This needs 5 or more known crops (the same rule as the known-sample warning).
- Add the task `writer-score` to `fhand validate`: AUC and EER against skilled forgeries and other
  writers, per stratum.
- **No case use in this phase.** The score appears only in validation dossiers.
- Check: `pytest`; `fhand validate` on `synth` data shows the new table with the synthetic banner.

### Phase 2: Calibration to LR (branch `feat/stage4-calibration`)

- `fhand calibrate MANIFEST --propositions skilled-forgery --out calib.json`
- Fit: log10 LR = a × score + b (logistic regression, plain numpy, weighted so the class sizes do not matter).
- ELUB bounds from the data size, so a small data set cannot give a huge LR.
- Calibration file: feature version, settings hash, a, b, bounds, propositions, conditions,
  data manifest hashes, writer list hash, status (`demo`, `candidate` or `released`), results hash.
- Synthetic data always gives status `demo`.
- Dossier: Cllr, Cllr-min, the rates of misleading evidence both ways, and a Tippett plot
  (inline SVG, nothing from the internet). Intervals by writer-level bootstrap, because pairs from
  one writer are not independent.
- Check: hand-checked metric values in tests; same data gives the same calibration hash.

### Phase 3: Pass marks and release (branch `feat/stage4-release`)

- `fhand prereg write criteria.json` and `fhand prereg stamp criteria.json`: hash the pass marks and
  get a trusted time stamp (reuse `tsa.py`). This proves the marks came before the test.
- Proposed pass marks (to confirm with practising examiners before use):
  - Cllr below 1 (must be better than no system), target 0.5 or less.
  - Misleading evidence for Hp on skilled forgeries: 5% or less, with the 95% upper bound at 10% or less.
  - Minimum data: 30 writers in the test set, 5 skilled forgeries per writer, 2 or more forgers.
- `fhand release calib.json --dossier D --criteria C`: refuses unless the dossier is real data, the
  writers are disjoint, the consent scopes are right, the criteria hash is in the dossier, the criteria
  stamp is older than the dossier, and every mark passed. Then it writes status `released`.
- Check: tests that each failed condition gives its own refusal message.

### Phase 4: Use in a case (branch `feat/stage4-case-score`)

- `fhand score CASE --calibration calib.json --questioned C1 --known C2 C3 C4 C5 C6`
- Refuses a calibration that is not `released`, and a case outside its tested conditions. It says why.
- The calibration file goes into the case store (read-only) and into the next seal.
- One ledger event per score: feature values, raw score, calibration hash, LR, bounds, propositions.
- Report: the LR, the propositions, a verbal equivalent, the tested conditions and the limits.
  The report says that the examiner decides and that the LR is one input.
- Workbench: a Score panel. With no released calibration it shows "Locked" and the reason.
- Checker: recomputes the LR from the raw score with `math` only, and checks the calibration hash.
- Check: a test that a `demo` calibration is refused in a case (the most important test);
  the checker finds a changed LR; `fhand export` includes the calibration file.

### Phase 5: Real data pilot (your part, not code)

- Collect data with `docs/validation/collection-protocol.md`.
- Split the writers into two groups before you look at any results: one group to fit, one to test.
- Write and stamp the pass marks. Then run `calibrate`, `validate` and `release`.
- Have a lawyer check the consent form first (it is a draft).

## Risks

| Risk | Level | What we do |
|---|---|---|
| No real data yet, so the score stays locked | High | The plan is honest about it. Phases 1 to 4 still give the full method, tested on synthetic data |
| Synthetic forgeries are easier than human forgeries, so synthetic numbers look too good | High | Synthetic gives `demo` only; the dossier banner stays |
| The simple features may not separate skilled forgeries well | Medium | The gate stops a weak method. Cllr shows it. That is a valid result |
| Pairs from one writer are not independent, so intervals look too narrow | Medium | Writer-level bootstrap for the intervals |
| An LR in court invites attack. Canada tests new science for reliability (R v J.-L.J., 2000 SCC 51; White Burgess, 2015 SCC 23) | Medium | Stated propositions, tested conditions, pre-registered marks, a checker for the other side. A lawyer checks before first use |
| A distance transform in plain numpy is slow on big crops | Low | Crops are small; measure it in Phase 1 |

## Sources to check before quoting

- Meuwly, Ramos and Haraksim (2017), a guideline for the validation of LR methods (Forensic Science International).
- ENFSI Guideline for Evaluative Reporting in Forensic Science (2015).
- Vergeer and others (2016), the ELUB bounds (Science and Justice).
- Brümmer and du Preez (2006), Cllr.

## Validation commands

```powershell
.\.venv\Scripts\python.exe -m pytest
```

```powershell
.\.venv\Scripts\fhand.exe synth data\synth-s4 --writers 30 --seed 4
```

```powershell
.\.venv\Scripts\fhand.exe validate data\synth-s4\manifest.json --out data\validation-s4
```

## Acceptance

- [ ] Phases 1 to 4 merged, each after a CodeRabbit review with no open findings
- [ ] All tests pass
- [ ] A `demo` calibration is refused in a case, with a clear reason
- [ ] The checker recomputes every LR in a case
- [ ] The README says plainly that the score is locked until real data passes
