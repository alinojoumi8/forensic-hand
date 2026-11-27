# Test record: Stage 4, the locked score

Plan: `docs/plans/stage4-score.plan.md`. Tool version 0.1.0. Python 3.14 on Windows 11.
All data in these tests is synthetic. It proves the logic. It is not proof on real casework.

## User journeys

1. As a validator, I want a raw writer score in the validation dossier, so that I can see how well
   the measures separate genuine signatures from forgeries before anyone calibrates them.
2. As an examiner, I want each measure to be explainable and independent of the scan resolution,
   so that I can say in court what the tool measured.
3. As a validator, I want to turn the raw score into a likelihood ratio on data whose licence and
   consent allow it, and to measure that LR on other writers, so that its error rates are known.
4. (Phases 3 and 4 add their journeys below.)

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

### CodeRabbit review 10 (phase 1): 2 findings, both fixed (commit e7f2b5b)

| Finding | Fix | Test (RED, then GREEN) |
|---|---|---|
| A clean item whose `sample` name differs from its id lost all its pairs | Pairs are keyed by the clean original's own id (`validation._origin`), in the writer score and the copy check | `test_clean_items_may_carry_a_sample_name_that_differs_from_their_id` (RED: the clean stratum was missing) |
| The 40-pixel minimum of the line removal made small crops differ at 2 resolutions | The writer score uses relative lengths only (`fixed_minimum=False`); the copy check is unchanged | `test_a_small_loop_is_measured_the_same_at_twice_the_resolution` (RED: 1 part at 1x, 2 parts at 2x) |

## Phase 2: calibration to a likelihood ratio (branch `feat/stage4-calibration`)

| Step | Command | Result |
|---|---|---|
| RED | `pytest tests/test_calibrate.py` on the phase 1 code | `ImportError: cannot import name 'calibrate'` |
| GREEN | `pytest tests/test_calibrate.py tests/test_writer.py tests/test_synth.py tests/test_cli.py tests/test_datasets.py` | all pass |
| Lint | `ruff check src tests` | all checks passed |

| # | What is guaranteed | Test |
|---|---|---|
| 1 | Cllr is 1 for "always LR 1", log2(1.1) for LR 10 and 1/10, near 0 for strong correct LRs | `test_cllr_*` |
| 2 | Cllr-min is 0 for separated scores, 1 for identical scores, and never above a fitted system | `test_cllr_min_*` |
| 3 | Misleading-evidence rates count the wrong side of LR 1, with Wilson intervals | `test_misleading_evidence_rates_count_the_wrong_side_of_1` |
| 4 | The writer bootstrap repeats with a seed and draws whole writers | `test_the_writer_bootstrap_is_repeatable_and_resamples_whole_writers` |
| 5 | The fit finds ln LR = 2 x score for N(1,1) against N(-1,1), and does not depend on class sizes | `test_the_fit_*` |
| 6 | A score that does not separate the classes is refused | `test_a_score_that_does_not_separate_is_refused` |
| 7 | Bounds worked by hand: 10 pairs a side allow log10 LR 1 at most; no information gives LR 1 | `test_the_bounds_worked_by_hand`, `test_a_system_with_no_information_gets_bounds_of_lr_1` |
| 8 | Synthetic data gives a demo calibration that records its model, conditions, writers and pairs | `test_a_synthetic_calibration_is_a_demo`, `test_the_calibration_records_its_model_conditions_and_data` |
| 9 | The same data gives the same calibration hash; a changed file is refused | `test_the_same_data_gives_the_same_calibration`, `test_a_changed_calibration_file_is_refused` |
| 10 | Other score settings, research-only data, data without calibrate consent and unknown propositions are refused | `test_a_calibration_of_other_settings_is_refused`, `test_research_only_data_cannot_calibrate`, `test_data_without_consent_to_calibrate_is_left_out_and_reported`, `test_an_unknown_proposition_is_refused` |
| 11 | The LR stays inside its bounds | `test_applying_the_calibration_keeps_the_lr_inside_its_bounds` |
| 12 | Validation measures Cllr, Cllr-min, Cllr-cal, misleading rates and Tippett data on new writers | `test_the_validation_measures_the_lr_on_new_data` |
| 13 | Strata outside the calibration are not measured; reused writers are reported | `test_strata_outside_the_calibration_are_not_measured`, `test_writers_used_to_calibrate_are_reported_when_they_are_tested_again` |
| 14 | The dossier shows the LR section, the demo banner and a Tippett plot | `test_the_dossier_shows_the_lr_section_with_a_tippett_plot` |
| 15 | `calibrate` and `validate --calibration` work end to end; an existing file is not overwritten | `test_the_calibrate_and_validate_commands` |

Known flaky test, not caused by Stage 4: `tests/test_server.py::test_a_large_body_is_refused` failed twice in
full runs with a Windows `ConnectionAbortedError` (the server answers 413 before the client has sent the
300 kB body). It passed 6 times out of 6 on its own.
