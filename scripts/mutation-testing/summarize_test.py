"""Tests for summarize.py: gremlins-JSON -> summary-JSON, and the CLI's
own argument/path handling (the surface pinned down by pythonsecurity:S8707 —
see summarize.py's MUTATION_STATE_DIR containment check)."""
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
    monkeypatch.setattr(sys, "argv", ["summarize.py", "only-one-arg"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_missing_state_dir_env_exits_2(capsys, monkeypatch, tmp_path):
    result = tmp_path / "result.json"
    _write_gremlins_json(result, [])
    monkeypatch.delenv("MUTATION_STATE_DIR", raising=False)
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(result), "core"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2
    assert "MUTATION_STATE_DIR" in capsys.readouterr().err


def test_path_outside_state_dir_rejected(capsys, monkeypatch, tmp_path):
    # A resolved, real, regular file -- but outside MUTATION_STATE_DIR --
    # must still be rejected (pythonsecurity:S8707): realpath()/isfile()
    # alone don't restrict *where* the file lives.
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    outside = tmp_path / "outside.json"
    _write_gremlins_json(outside, [{"status": "KILLED", "line": 1, "column": 1, "type": "t"}])

    monkeypatch.setenv("MUTATION_STATE_DIR", str(state_dir))
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(outside), "core"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2


def test_missing_file_exits_2_without_opening(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    missing = tmp_path / "does-not-exist.json"
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(missing), "core"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2
    assert str(missing) in capsys.readouterr().err


def test_directory_path_rejected(capsys, monkeypatch, tmp_path):
    # A directory resolves via realpath but must still be rejected — only a
    # regular file is a valid gremlins result.
    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(tmp_path), "core"])
    with pytest.raises(SystemExit) as exc:
        summarize.main()
    assert exc.value.code == 2


def test_symlink_to_real_file_is_resolved_and_read(capsys, monkeypatch, tmp_path):
    real = tmp_path / "real.json"
    _write_gremlins_json(real, [{"status": "KILLED", "line": 1, "column": 1, "type": "t"}])
    link = tmp_path / "link.json"
    link.symlink_to(real)

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(link), "core"])
    summarize.main()

    summary = json.loads(capsys.readouterr().out)
    assert summary["total_mutants"] == 1


def test_summary_counts_and_efficacy(capsys, monkeypatch, tmp_path):
    result = tmp_path / "result.json"
    _write_gremlins_json(
        result,
        [
            {"status": "KILLED", "line": 10, "column": 2, "type": "ARITHMETIC_BASE"},
            {"status": "KILLED", "line": 11, "column": 2, "type": "CONDITIONALS_BOUNDARY"},
            {"status": "LIVED", "line": 12, "column": 3, "type": "NEGATE_CONDITIONALS"},
            {"status": "NOT_VIABLE", "line": 13, "column": 1, "type": "INVERT_LOOP"},
        ],
    )

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(result), "core"])
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
    result = tmp_path / "result.json"
    _write_gremlins_json(result, [{"status": "NOT_VIABLE", "line": 1, "column": 1, "type": "t"}])

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(result), "core"])
    summarize.main()

    summary = json.loads(capsys.readouterr().out)
    assert summary["test_efficacy_pct"] is None
    assert summary["lived"] == []


def test_no_files_key_produces_empty_summary(capsys, monkeypatch, tmp_path):
    result = tmp_path / "result.json"
    result.write_text(json.dumps({}))

    monkeypatch.setenv("MUTATION_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["summarize.py", str(result), "core"])
    summarize.main()

    summary = json.loads(capsys.readouterr().out)
    assert summary["total_mutants"] == 0
    assert summary["counts"] == {}
    assert summary["test_efficacy_pct"] is None
