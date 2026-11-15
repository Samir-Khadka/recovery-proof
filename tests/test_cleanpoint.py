"""Tests for the clean-point scorer: heuristics, recommendation, and the
false-positive rate measured on the clean fixtures."""
import math
from pathlib import Path

import pytest

from recovery_proof.cleanpoint import (
    FLAG_THRESHOLD,
    clean_point_main,
    load_canaries,
    recommend,
    score_db_point,
    score_file_point,
    shannon_entropy,
)

FIX = Path(__file__).parent.parent / "fixtures" / "clean-point"


def _canaries():
    return load_canaries(FIX / "canaries.yaml")


def test_entropy_low_for_text_high_for_random():
    assert shannon_entropy(b"hello world\n" * 100) < 4.0
    assert shannon_entropy(bytes(range(256)) * 4) > 7.9
    assert shannon_entropy(b"") == 0.0


def test_clean_point_scores_zero():
    s = score_file_point(FIX / "clean", None, _canaries())
    assert s["score"] == 0 and s["flagged"] is False
    assert s["evidence"] == []


def test_clean_point_compressed_files_do_not_count_as_entropy():
    # clean/ holds a real zip and a random-bytes .jpg — both high-entropy by
    # content, both excluded by type. The canary is intact, nothing changed.
    s = score_file_point(FIX / "clean", None, _canaries())
    assert not any(e["heuristic"] == "high-entropy files" for e in s["evidence"])


def test_ordinary_day_change_is_not_flagged():
    prev = score_file_point(FIX / "clean", None, _canaries())["files"]
    s = score_file_point(FIX / "clean2", prev, _canaries())
    assert s["flagged"] is False
    assert s["score"] == 8  # 2/10 files changed = 20% of 40 mass-change points
    assert any(e["heuristic"] == "mass change vs previous point" for e in s["evidence"])


def test_mass_change_alone_is_a_signal_not_a_verdict():
    prev = score_file_point(FIX / "clean", None, _canaries())["files"]
    s = score_file_point(FIX / "mass-change", prev, _canaries())
    assert s["flagged"] is False
    assert s["score"] == 22  # 5/9 files changed = 56% of 40 points


def test_infected_point_is_flagged_with_all_the_evidence():
    prev = score_file_point(FIX / "clean", None, _canaries())["files"]
    s = score_file_point(FIX / "infected", prev, _canaries())
    assert s["flagged"] is True
    assert s["score"] == 100  # capped: the raw points sum past 100
    heuristics = {e["heuristic"] for e in s["evidence"]}
    assert heuristics == {"known ransomware extension", "ransom note filename",
                          "canary changed", "high-entropy files",
                          "mass change vs previous point"}


def test_canary_missing_flags_the_point(tmp_path):
    point = tmp_path / "p"
    point.mkdir()
    (point / "notes.txt").write_text("hello\n")
    s = score_file_point(point, None, [{"path": "canary.txt", "sha256": "00" * 32}])
    assert s["flagged"] is True
    assert any(e["heuristic"] == "canary missing" for e in s["evidence"])


def test_single_encrypted_extension_alone_does_not_flag(tmp_path):
    point = tmp_path / "p"
    point.mkdir()
    (point / "backup.enc").write_text("legitimately encrypted backup\n")
    s = score_file_point(point, None, [])
    assert s["flagged"] is False
    assert s["score"] == 25


def test_recommendation_rules():
    def pt(name, flagged):
        return {"point": name, "flagged": flagged, "score": 80 if flagged else 0}
    # No flags: the newest point.
    r = recommend([pt("p1", False), pt("p2", False)])
    assert r["clean_point"] == "p2"
    # A flag: the point before the first flagged one, even if a later point is clean.
    r = recommend([pt("p1", False), pt("p2", True), pt("p3", False)])
    assert r["clean_point"] == "p1"
    assert r["flagged_points"] == ["p2"]
    # Every point flagged: no clean point.
    r = recommend([pt("p1", True), pt("p2", True)])
    assert r["clean_point"] is None
    # Empty: no clean point.
    assert recommend([])["clean_point"] is None


def test_load_canaries_bad_file(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("canaries:\n  - path: x.txt\n")
    with pytest.raises(ValueError, match="path \\+ sha256"):
        load_canaries(p)


def test_false_positive_rate_on_clean_fixtures_is_zero():
    """The measured FP rate: every clean point scores below the flag
    threshold. This is the number the README reports."""
    canaries = _canaries()
    clean_points = [FIX / "clean", FIX / "clean2", FIX / "mass-change"]
    prev = None
    flagged = 0
    for p in clean_points:
        s = score_file_point(p, prev, canaries)
        prev = s["files"]
        flagged += 1 if s["flagged"] else 0
    # Plus the two clean DB points.
    prev_db = None
    for p in [FIX / "db-clean1.sql", FIX / "db-clean2.sql"]:
        s = score_db_point(p, prev_db)
        prev_db = s["files"]
        flagged += 1 if s["flagged"] else 0
    assert flagged == 0, "a clean fixture was flagged — the FP rate is not zero"


def test_db_points_small_change_clean_mass_change_flagged():
    prev = score_db_point(FIX / "db-clean1.sql", None)["files"]
    s = score_db_point(FIX / "db-clean2.sql", prev)
    assert s["flagged"] is False and s["score"] == 6
    prev = s["files"]
    s = score_db_point(FIX / "db-mass.sql", prev)
    assert s["flagged"] is True and s["score"] == 77


def test_db_point_without_copy_data_is_not_measurable(tmp_path):
    p = tmp_path / "mysqldump.sql"
    p.write_text("INSERT INTO users VALUES (1, 'a');\n")
    s = score_db_point(p, None)
    assert s["flagged"] is False
    assert "not measurable" in s["evidence"][0]["detail"]


def test_clean_point_cli_exit_codes(tmp_path, capsys):
    assert clean_point_main([
        str(FIX / "clean"), str(FIX / "clean2"),
        "--canaries", str(FIX / "canaries.yaml")]) == 0
    assert "Last clean point" in capsys.readouterr().out

    assert clean_point_main([
        str(FIX / "clean"), str(FIX / "infected"),
        "--canaries", str(FIX / "canaries.yaml")]) == 0
    # A clean point exists (clean), even though infected was flagged.

    assert clean_point_main([str(FIX / "infected")]) == 1  # no clean point
    assert "No clean point found" in capsys.readouterr().out

    assert clean_point_main([str(tmp_path / "missing")]) == 2
    assert clean_point_main([
        str(FIX / "clean"), str(FIX / "db-clean1.sql")]) == 2  # mixed kinds
