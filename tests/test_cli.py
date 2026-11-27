from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from conftest import fake_tsr, tiff_with_preview_block

import forensic_hand
from forensic_hand import tsa
from forensic_hand.cli import main


def _intake(tmp_path, sharp_png, other_png, *extra):
    case_dir = tmp_path / "cli-case"
    rc = main(["intake", str(case_dir), "--title", "CLI test",
               "--questioned", str(sharp_png), "--known", str(other_png), *extra])
    return case_dir, rc


def test_intake_builds_a_sealed_case_with_a_report(tmp_path, sharp_png, other_png, capsys):
    case_dir, rc = _intake(tmp_path, sharp_png, other_png)
    out = capsys.readouterr().out
    assert rc == 0
    assert (case_dir / "reports" / "report.html").is_file()
    assert (case_dir / "seals" / "seal-0001.json").is_file()
    assert "Q1" in out and "K1" in out and "report.html" in out
    assert main(["verify", str(case_dir), "--skip-tsa-signature"]) == 0


def test_intake_of_a_tiff_with_a_preview_block_finishes(tmp_path, other_png, capsys):
    # Found on the CVL database: intake added the file, then crashed (TypeError): no check, seal or report.
    tif = tiff_with_preview_block(tmp_path / "scan.tif")
    case_dir, rc = _intake(tmp_path, tif, other_png)
    assert rc == 0 and (case_dir / "reports" / "report.html").is_file()
    assert (case_dir / "seals" / "seal-0001.json").is_file()
    assert main(["verify", str(case_dir), "--skip-tsa-signature"]) == 0


def test_intake_does_not_use_the_network_unless_asked(tmp_path, sharp_png, other_png, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network was used")
    monkeypatch.setattr(tsa, "request_timestamp", boom)
    monkeypatch.setattr("urllib.request.urlopen", boom)
    case_dir, rc = _intake(tmp_path, sharp_png, other_png)
    assert rc == 0 and list((case_dir / "seals").glob("*.tsr")) == []


def test_intake_with_the_timestamp_flag_asks_the_time_stamp_server(tmp_path, sharp_png, other_png, monkeypatch):
    seen = {}

    def request(url, digest, timeout=20):
        seen["url"] = url
        return fake_tsr(digest, 5), 5
    monkeypatch.setattr(tsa, "request_timestamp", request)
    case_dir, rc = _intake(tmp_path, sharp_png, other_png, "--timestamp", "--tsa-url", "http://tsa.invalid/x")
    assert rc == 0 and seen["url"] == "http://tsa.invalid/x"
    assert (case_dir / "seals" / "seal-0001.tsr").is_file()


def test_a_failed_time_stamp_keeps_the_case_and_returns_1(tmp_path, sharp_png, other_png, monkeypatch, capsys):
    def request(url, digest, timeout=20):
        raise tsa.TimestampError("server is down")
    monkeypatch.setattr(tsa, "request_timestamp", request)
    case_dir, rc = _intake(tmp_path, sharp_png, other_png, "--timestamp")
    assert rc == 1
    assert "server is down" in capsys.readouterr().err
    assert (case_dir / "reports" / "report.html").is_file()
    assert main(["verify", str(case_dir), "--skip-tsa-signature"]) == 0


def test_verify_returns_1_after_tampering(tmp_path, sharp_png, other_png, capsys):
    case_dir, _ = _intake(tmp_path, sharp_png, other_png)
    stored = next((case_dir / "evidence").iterdir())
    os.chmod(stored, stat.S_IWRITE | stat.S_IREAD)
    stored.write_bytes(stored.read_bytes() + b"x")
    capsys.readouterr()
    assert main(["verify", str(case_dir), "--skip-tsa-signature"]) == 1
    assert "PROBLEM" in capsys.readouterr().out


def test_verify_can_print_json(tmp_path, sharp_png, other_png, capsys):
    case_dir, _ = _intake(tmp_path, sharp_png, other_png)
    capsys.readouterr()
    assert main(["verify", str(case_dir), "--skip-tsa-signature", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_the_step_by_step_commands_work(tmp_path, sharp_png, other_png, capsys):
    case_dir = str(tmp_path / "steps")
    assert main(["new", case_dir, "--title", "Step case"]) == 0
    assert main(["add", case_dir, str(sharp_png), "--role", "questioned", "--date", "2024-06-01"]) == 0
    assert main(["add", case_dir, str(other_png), "--role", "known", "--signer", "A. Example"]) == 0
    assert main(["date", case_dir, "K1", "2023-02-03"]) == 0
    assert main(["check", case_dir]) == 0
    assert main(["seal", case_dir]) == 0
    assert main(["report", case_dir]) == 0
    assert main(["verify", case_dir, "--skip-tsa-signature"]) == 0
    html = (Path(case_dir) / "reports" / "report.html").read_text(encoding="utf-8")
    assert "2023-02-03" in html and "A. Example" in html and "Step case" in html


def test_add_takes_many_files_at_once(tmp_path, sharp_png, other_png, capsys):
    case_dir = str(tmp_path / "many")
    main(["new", case_dir, "--title", "t"])
    capsys.readouterr()
    assert main(["add", case_dir, str(sharp_png), str(other_png), "--role", "known"]) == 0
    out = capsys.readouterr().out
    assert "K1" in out and "K2" in out


@pytest.mark.parametrize("argv_tail", [
    ["add", "{case}", "{missing}", "--role", "known"],
    ["add", "{case}", "{png}", "--role", "known", "--date", "June 2021"],
    ["date", "{case}", "K7", "2021-01-01"],
    ["seal", "{case}", "--timestamp", "--tsa-url", "file:///etc/passwd"],
    ["check", "{nocase}"],
])
def test_bad_input_returns_an_error_code_and_a_plain_message(tmp_path, sharp_png, capsys, argv_tail):
    case_dir = tmp_path / "errs"
    main(["new", str(case_dir), "--title", "t"])
    capsys.readouterr()
    values = {"case": str(case_dir), "missing": str(tmp_path / "nope.png"), "png": str(sharp_png),
              "nocase": str(tmp_path / "no-such-case")}
    rc = main([a.format(**values) for a in argv_tail])
    err = capsys.readouterr().err
    assert rc in (1, 2) and err.startswith("error:") and "Traceback" not in err


def test_new_on_a_folder_with_files_returns_2(tmp_path, capsys):
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "x.txt").write_text("x")
    assert main(["new", str(tmp_path / "busy"), "--title", "t"]) == 2
    assert capsys.readouterr().err.startswith("error:")


def test_no_command_prints_help_and_returns_2(capsys):
    assert main([]) == 2
    assert "intake" in capsys.readouterr().out


def _export(tmp_path, sharp_png, other_png) -> Path:
    case_dir, _ = _intake(tmp_path, sharp_png, other_png)
    bundle = tmp_path / "bundle.zip"
    assert main(["export", str(case_dir), str(bundle)]) == 0
    out = tmp_path / "unpacked"
    with zipfile.ZipFile(bundle) as z:
        z.extractall(out)
    return out


def _plain_python_verify(folder: Path):
    """Run the bundled checker with NO installed packages (-I -S): standard library only."""
    return subprocess.run(
        [sys.executable, "-I", "-S", str(folder / "verify_case.py"), str(folder), "--skip-tsa-signature"],
        capture_output=True, text=True, timeout=120, check=False,
    )


def test_an_exported_bundle_verifies_with_plain_python_only(tmp_path, sharp_png, other_png):
    out = _export(tmp_path, sharp_png, other_png)
    done = _plain_python_verify(out)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "RESULT: OK" in done.stdout


def test_a_tampered_bundle_fails_with_plain_python_only(tmp_path, sharp_png, other_png):
    out = _export(tmp_path, sharp_png, other_png)
    stored = next((out / "evidence").iterdir())
    os.chmod(stored, stat.S_IWRITE | stat.S_IREAD)
    stored.write_bytes(stored.read_bytes()[:-1] + b"\x00")
    done = _plain_python_verify(out)
    assert done.returncode == 1 and "RESULT: PROBLEMS FOUND" in done.stdout


def test_the_bundled_checker_is_the_same_file_as_the_package_checker(tmp_path, sharp_png, other_png):
    out = _export(tmp_path, sharp_png, other_png)
    package_file = Path(forensic_hand.__file__).parent / "verify_case.py"
    assert (out / "verify_case.py").read_bytes() == package_file.read_bytes()


def test_export_refuses_to_overwrite(tmp_path, sharp_png, other_png, capsys):
    case_dir, _ = _intake(tmp_path, sharp_png, other_png)
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"old")
    assert main(["export", str(case_dir), str(bundle)]) == 2
    assert bundle.read_bytes() == b"old"
