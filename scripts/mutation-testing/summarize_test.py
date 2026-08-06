"""Tests for summarize.py: gremlins-JSON -> summary-JSON, and the CLI's
own argument handling (the surface pinned down by pythonsecurity:S8707 —
see summarize.py's LABEL_RE check)."""
import json
import sys

import pytest

import summarize


def _write_gremlins_json(path, mutations):
    path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file_name": "internal/core/x.go",
                        "mutations": mutations,
                    }
                ]
            }
        )
    )


def test_wrong_arg_count_exits_2(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["summarize.py"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_invalid_label_rejected_before_touching_filesystem(capsys, monkeypatch):
    # A path-shaped "label" (traversal, absolute path, embedded separator)
    # must be rejected by the allowlist regex before it ever reaches a
    # filesystem call -- this is the actual fix for pythonsecurity:S8707:
    # validate the untrusted argument itself, rather than validating a path
    # built from it after the fact.
    monkeypatch.delenv("MUTATION_STATE_DIR", raising=False)
    monkeypatch.setattr(sys, "argv", ["summarize.py", "../../etc/passwd"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2
    assert "not a valid label" in capsys.readouterr().err


def test_missing_state_dir_env_exits_2(capsys, monkeypatch):
    monkeypatch.delenv("MUTATION_STATE_DIR", raising=False)
    monkeypatch.setattr(sys, "argv", ["summarize.py", "core"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2
    assert "MUTATION_STATE_DIR" in capsys.readouterr().err


def test_missing_result_file_exits_2(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", "core"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2
    assert "last-core.json" in capsys.readouterr().err


def test_directory_in_place_of_result_file_rejected(capsys, monkeypatch, tmp_path):
    (tmp_path / "last-core.json").mkdir()
    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", "core"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2


def test_symlinked_result_file_is_read(capsys, monkeypatch, tmp_path):
    real = tmp_path / "real.json"
    _write_gremlins_json(real, [{"status": "KILLED", "line": 1, "column": 1, "type": "t"}])
    (tmp_path / "last-core.json").symlink_to(real)

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", "core"])
    summarize.main()

    summary = json.loads(capsys.readouterr().out)
    assert summary["total_mutants"] == 1


def test_summary_counts_and_efficacy(capsys, monkeypatch, tmp_path):
    _write_gremlins_json(
        tmp_path / "last-core.json",
        [
            {"status": "KILLED", "line": 10, "column": 2, "type": "ARITHMETIC_BASE"},
            {"status": "KILLED", "line": 11, "column": 2, "type": "CONDITIONALS_BOUNDARY"},
            {"status": "LIVED", "line": 12, "column": 3, "type": "NEGATE_CONDITIONALS"},
            {"status": "NOT_VIABLE", "line": 13, "column": 1, "type": "INVERT_LOOP"},
        ],
    )

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", "core"])
    summarize.main()

    summary = json.loads(capsys.readouterr().out)
    assert summary["label"] == "core"
    assert summary["total_mutants"] == 4
    assert summary["counts"] == {"KILLED": 2, "LIVED": 1, "NOT_VIABLE": 1}
    # 2 killed / (2 killed + 1 lived) = 66.67%
    assert summary["test_efficacy_pct"] == pytest.approx(66.67)
    assert summary["lived"] == [
        {"file": "internal/core/x.go", "line": 12, "column": 3, "type": "NEGATE_CONDITIONALS"}
    ]


def test_efficacy_is_none_when_nothing_scored(capsys, monkeypatch, tmp_path):
    _write_gremlins_json(
        tmp_path / "last-core.json", [{"status": "NOT_VIABLE", "line": 1, "column": 1, "type": "t"}]
    )

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", "core"])
    summarize.main()

    summary = json.loads(capsys.readouterr().out)
    assert summary["test_efficacy_pct"] is None
    assert summary["lived"] == []


def test_no_files_key_produces_empty_summary(capsys, monkeypatch, tmp_path):
    (tmp_path / "last-core.json").write_text(json.dumps({}))

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", "core"])
    summarize.main()

    summary = json.loads(capsys.readouterr().out)
    assert summary["total_mutants"] == 0
    assert summary["counts"] == {}
    assert summary["test_efficacy_pct"] is None
