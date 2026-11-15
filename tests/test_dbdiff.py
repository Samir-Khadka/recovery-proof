"""Tests for the SQL-dump row comparison."""
from pathlib import Path

import pytest

from recovery_proof.dbdiff import compare_dumps, parse_sql_dump

FIX = Path(__file__).parent.parent / "fixtures" / "clean-point"


def test_parse_sql_dump_counts_rows_per_table():
    tables = parse_sql_dump(FIX / "db-clean1.sql")
    assert set(tables) == {"users", "orders"}
    assert sum(tables["users"].values()) == 10
    assert sum(tables["orders"].values()) == 20


def test_compare_identical_dumps_is_zero():
    a = parse_sql_dump(FIX / "db-clean1.sql")
    frac, detail = compare_dumps(a, a)
    assert frac == 0.0
    assert "0/" in detail


def test_compare_small_change():
    a = parse_sql_dump(FIX / "db-clean1.sql")
    b = parse_sql_dump(FIX / "db-clean2.sql")
    frac, detail = compare_dumps(b, a)
    # 1 user added + 1 order edited, out of 31 rows.
    assert frac == pytest.approx(2 / 31, abs=0.001)
    assert "2/31 rows differ" in detail


def test_compare_mass_change():
    a = parse_sql_dump(FIX / "db-clean2.sql")
    b = parse_sql_dump(FIX / "db-mass.sql")
    frac, detail = compare_dumps(b, a)
    assert frac == pytest.approx(24 / 31, abs=0.001)
    assert "24/31 rows differ" in detail


def test_compare_table_added_or_removed(tmp_path):
    a = tmp_path / "a.sql"
    a.write_text("COPY t (id) FROM stdin;\n1\n2\n\\.\n")
    b = tmp_path / "b.sql"
    b.write_text("COPY t (id) FROM stdin;\n1\n2\n\\.\nCOPY u (id) FROM stdin;\n9\n\\.\n")
    frac, detail = compare_dumps(parse_sql_dump(b), parse_sql_dump(a))
    assert frac == pytest.approx(1 / 3, abs=0.001)  # 1 added row out of 3
    assert "2 tables" in detail
