# Test record: Stage 4, the locked score

Plan: `docs/plans/stage4-score.plan.md`. Tool version 0.1.0. Python 3.14 on Windows 11.
All data in these tests is synthetic. It proves the logic. It is not proof on real casework.

## User journeys

1. As a validator, I want a raw writer score in the validation dossier, so that I can see how well
   the measures separate genuine signatures from forgeries before anyone calibrates them.
2. As an examiner, I want each measure to be explainable and independent of the scan resolution,
   so that I can say in court what the tool measured.
3. (Phases 2 to 4 add their journeys below.)

## Phase 1: measures and raw score (branch `feat/stage4-writer-score`)

| Step | Command | Result |
|---|---|---|
| RED | `pytest tests/test_writer.py` | `ImportError: cannot import name 'writer'` (commit 96e9714) |
| GREEN | `pytest` (whole suite) | all pass; one server test (`test_a_large_body_is_refused`) failed once with a Windows connection abort and passed on two reruns, on the old and the new code |
| Coverage | `pytest tests/test_writer.py tests/test_validation.py --cov` | `writer.py` 98%, `validation.py` 99% |
| Lint | `ruff check src tests` | all checks passed |

| # | What is guaranteed | Test |
|---|---|---|
| 1 | The measures of one picture are the same each time; shares sum to 1 | `test_features_have_every_group_and_are_repeatable` |
| 2 | A crop with no ink has no measures | `test_a_blank_crop_has_no_features` |
| 3 | The same signature at 300 and 600 DPI gives close measures | `test_features_do_not_depend_on_the_scan_resolution` |
| 4 | A stamp of another colour is removed before the measures | `test_a_stamp_of_another_colour_is_removed_before_the_features` |
| 5 | The score is minus the mean log ratio, worked by hand | `test_the_score_is_minus_the_mean_log_ratio_worked_by_hand` |
| 6 | One measure cannot decide the score alone (limit 2.5 per measure) | `test_one_group_cannot_decide_the_score_alone` |
| 7 | Fewer than 5 known signatures are refused | `test_too_few_known_signatures_are_refused` |
| 8 | Measures of another feature version are refused | `test_a_feature_record_of_another_version_is_refused` |
| 9 | Genuine signatures score higher than forgeries and other writers (4 synthetic writers) | `test_genuine_signatures_score_higher_than_forgeries_and_other_writers` |
| 10 | The dossier holds the writer score per stratum, with the right pair counts | `test_the_validation_measures_the_writer_score_per_stratum` |
| 11 | Too few genuine signatures per writer: the task says why and measures nothing | `test_the_writer_score_is_skipped_with_a_reason_when_writers_have_too_few_signatures` |
| 12 | The dossier page says the score is raw and not a likelihood ratio | `test_the_dossier_explains_that_the_writer_score_is_raw` |
| 13 | The copy check gives the same results after its ink step was shared | the existing copy check and validation tests |

### Measured on a larger synthetic set (not a test)

20 writers, 8 genuine and 3 skilled forgeries each, seed 4. Known signatures: 5 clean scans.

| Stratum | AUC, skilled forgery | AUC, other writer |
|---|---|---|
| clean | 0.931 | 1.000 |
| jpeg | 0.887 | 1.000 |
| stamp (other colour) | 0.883 | 0.994 |
| ruled | 0.835 | 0.998 |
| blur | 0.675 | 0.992 |
| stamp-same (pen colour) | 0.582 | 0.844 |
| dpi150 | 0.479 | 0.978 |

The score is weak on blurred, low-resolution and same-colour-stamp scans when the known scans are
clean. Phase 4 must refuse a case that is outside the conditions that the calibration tested.
