"""Generate the clean-point fixtures deterministically (seed 42).

Run from the repo root:  python scripts/make_cleanpoint_fixtures.py
The fixtures are committed: tests run the scorer over them and assert the
measured false-positive rate (0 flagged clean points) and the detection
rate on the infected points. Regenerating must produce identical files.
"""
from __future__ import annotations

import hashlib
import random
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "clean-point"
SEED = 42

TEXT_FILES = {
    "notes.txt": "Meeting notes\n- ship the restore checker\n- call the bank about the RTO\n",
    "data.csv": "id,name,amount\n1,alice,1200\n2,bob,3400\n3,carol,560\n",
    "app.py": "def greet(name):\n    return f\"hello {name}\"\n\n\nif __name__ == \"__main__\":\n    print(greet(\"world\"))\n",
    "config.json": '{\n  "database": "app",\n  "pool": 10,\n  "timeout_s": 30\n}\n',
    "report.md": "# Weekly report\n\nRestores: 7/7 passed. Median restore 42s.\n",
    "canary.txt": "recovery-proof canary — do not touch\n",
}


def _write_clean(d: Path, rng: random.Random) -> None:
    d.mkdir(parents=True, exist_ok=True)
    for name, content in TEXT_FILES.items():
        (d / name).write_text(content)
    # A real zip (compressed — high entropy is expected, must not count).
    with zipfile.ZipFile(d / "archive.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inside.txt", "archived notes\n" * 50)
    # A .jpg by extension with random bytes (excluded by extension, not content).
    (d / "photo.jpg").write_bytes(bytes(rng.randrange(256) for _ in range(4096)))
    # A minimal 1x1 PNG (real bytes, also excluded by extension).
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de"
        "0000000c4944415478da6360000000020001e221bc330000000049454e44ae426082")
    (d / "logo.png").write_bytes(png)


def _copy(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def main() -> None:
    rng = random.Random(SEED)
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)

    # --- clean point
    clean = ROOT / "clean"
    _write_clean(clean, rng)

    # --- canaries (the canary.txt from the clean point)
    canary_hash = hashlib.sha256((clean / "canary.txt").read_bytes()).hexdigest()
    (ROOT / "canaries.yaml").write_text(
        "# Canary files: known content, planted in the backup.\n"
        "# If a canary's hash differs (or the file is gone) in a later point,\n"
        "# that point is flagged on its own.\n"
        "canaries:\n"
        f"  - path: canary.txt\n    sha256: {canary_hash}\n"
    )

    # --- clean2: an ordinary day (1 file changed, 1 added) — must NOT flag.
    clean2 = ROOT / "clean2"
    _copy(clean, clean2)
    (clean2 / "notes.txt").write_text(
        "Meeting notes\n- ship the restore checker\n- call the bank about the RTO\n- new: review the drill\n")
    (clean2 / "todo.txt").write_text("- buy milk\n- rotate the backup key\n")

    # --- infected: ransomware signs on top of the clean point.
    infected = ROOT / "infected"
    _copy(clean, infected)
    (infected / "notes.txt.locked").write_bytes(
        bytes(rng.randrange(256) for _ in range(2048)))
    (infected / "README_TO_DECRYPT.txt").write_text(
        "Your files have been encrypted. Send 0.5 BTC to ...\n")
    (infected / "data.csv").write_bytes(
        bytes(rng.randrange(256) for _ in range(2048)))  # high-entropy .csv
    (infected / "canary.txt").write_text("recovery-proof canary — TAMPERED\n")

    # --- mass-change: most files changed, canary intact (mass change alone).
    mass = ROOT / "mass-change"
    _copy(clean, mass)
    for name in ["notes.txt", "data.csv", "app.py", "config.json", "report.md"]:
        (mass / name).write_text((mass / name).read_text() + "\n# rewritten\n")

    # --- database dumps (pg_dump plain format, COPY blocks)
    def dump(path: Path, users, orders):
        lines = ["-- Recovery Proof clean-point DB fixture\n",
                 "CREATE TABLE users (id integer, email text);\n",
                 "COPY public.users (id, email) FROM stdin;\n"]
        lines += [f"{i}\t{email}\n" for i, email in users]
        lines += ["\\.\n", "CREATE TABLE orders (id integer, user_id integer, total_cents integer);\n",
                  "COPY public.orders (id, user_id, total_cents) FROM stdin;\n"]
        lines += [f"{i}\t{u}\t{t}\n" for i, u, t in orders]
        lines += ["\\.\n"]
        path.write_text("".join(lines))

    users1 = [(i, f"user{i}@example.com") for i in range(1, 11)]
    orders1 = [(i, (i % 10) + 1, 1000 + i * 7) for i in range(1, 21)]
    dump(ROOT / "db-clean1.sql", users1, orders1)
    # db-clean2: one new user, one order changed (small change).
    dump(ROOT / "db-clean2.sql",
         users1 + [(11, "user11@example.com")],
         [(i, u, t + 1 if i == 3 else t) for i, u, t in orders1])
    # db-mass: most rows changed (mass change).
    dump(ROOT / "db-mass.sql",
         [(i, f"user{i}@other.com") for i in range(1, 9)] + users1[8:],
         [(i, u, 9999) for i, u, t in orders1[:15]] + orders1[15:])

    print(f"fixtures written to {ROOT}")


if __name__ == "__main__":
    main()
