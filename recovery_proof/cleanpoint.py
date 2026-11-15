"""Clean-point detection (Recovery Proof v0.5, Phase 4).

Given a series of restore points — directories of files, or plain-SQL
database dumps — score each point for ransomware signs and recommend the
**last clean point**: the newest point with no signs found. The
recommendation always lists its evidence, so a human can disagree with it.

Language contract (PLAN.md §6, non-negotiable): results are described as
"no signs found", never "guaranteed clean". A heuristic can miss an attack;
a clean score is the absence of the signs we look for, not proof of safety.

Heuristics v1 (each point scores 0–100; flagged at >= 50):

File points (a directory of files):
- Known ransomware extension: 25 points per file whose name ends in a
  known ransomware extension (list in RANSOMWARE_EXTENSIONS), capped at 50.
- Ransom note filename: 40 points for a file named like a ransom note
  (README_TO_DECRYPT, DECRYPT_INSTRUCTIONS, ...).
- Canary changed or missing: 50 points. A canary is a file the user plants
  with a known SHA-256 (see canaries.yaml); if its content differs from the
  expected hash, or the file is gone, the point is flagged on its own.
- High-entropy files: 0–30 points = 30 × (fraction of text-like files with
  Shannon entropy >= 7.5 bits/byte). Encrypted files are high-entropy.
  Files whose type is normally compressed (zip, jpg, mp4, pdf, docx, ...)
  are excluded — their high entropy is expected, not a sign.
- Mass change vs the previous point: 0–40 points = 40 × (fraction of files
  added, modified, or deleted since the previous point). Ransomware
  encrypts many files at once; a normal day changes few.

Database points (plain-SQL dumps, .sql):
- Mass change vs the previous dump: 0–100 points = 100 × (fraction of rows
  that differ, measured per table by hashing each COPY row). Flagged when
  more than half the rows changed. A dump is text, so the file heuristics
  do not apply; only the row-level change rate is measured.

The last clean point is the newest point older than the *earliest* flagged
point. A later point that scores clean after a flagged one is noted but not
recommended: a clean heuristic score does not prove an infection is gone.
If no point is flagged, the last clean point is the newest point. If every
point is flagged, there is no clean point in the range examined.

The false-positive rate is measured, not asserted: the test suite runs the
scorer over clean fixtures (normal files, compressed files, media, and
ordinary day-to-day changes) and asserts zero flagged points. The measured
rate is reported in the README.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import sys
from pathlib import Path

log = logging.getLogger("recovery-proof.cleanpoint")

HEURISTICS_VERSION = "1"
FLAG_THRESHOLD = 50

# File extensions whose content is normally compressed/encoded, so high
# entropy is expected and is NOT a sign. (docx/xlsx/pptx are zip files.)
COMPRESSED_EXTENSIONS = {
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".mp4", ".mp3",
    ".avi", ".mov", ".mkv", ".pdf", ".docx", ".xlsx", ".pptx",
    ".woff", ".woff2", ".ttf", ".otf", ".jar", ".war", ".apk", ".dmg", ".iso",
}

# Ransomware extensions, curated from public ransomware naming. A single
# hit is a moderate signal (25 points), not a flag on its own — some of
# these (.enc, .aes) are also legitimate encryption extensions.
RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".cry", ".ransom", ".ransomware",
    ".encrypt", ".enc", ".aes", ".rsa", ".locky", ".cerber", ".zepto",
    ".odin", ".wallet", ".dharma", ".phobos", ".ryuk", ".sodinokibi",
    ".maze", ".conti", ".revil", ".blackcat", ".lockbit", ".avos",
    ".hive", ".medusa", ".akira", ".play", ".cactus", ".rhysida",
    ".8base", ".bianlian", ".lockbit3", ".djvu", ".djvut", ".mmpa",
}

# Ransom-note filenames (case-insensitive, prefix match on the stem).
RANSOM_NOTE_STEMS = {
    "readme_to_decrypt", "decrypt_instructions", "how_to_decrypt",
    "your_files_are_encrypted", "decrypt_your_files", "ransom_note",
    "readme_decrypt", "how_to_recover", "recover_your_files",
    "attention_readme", "read_me_to_decrypt",
}

ENTROPY_THRESHOLD_BITS = 7.5
ENTROPY_SAMPLE_BYTES = 65536
ENTROPY_MAX_POINTS = 30
MASS_CHANGE_MAX_POINTS = 40
EXTENSION_POINTS_PER_FILE = 25
EXTENSION_MAX_POINTS = 50
RANSOM_NOTE_POINTS = 40
CANARY_POINTS = 50

EXIT_CLEAN = 0
EXIT_NO_CLEAN_POINT = 1
EXIT_INFRA = 2


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0–8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(root: Path):
    """All files under root, as (relative_posix_path, absolute_path)."""
    for p in sorted(root.rglob("*")):
        if p.is_file():
            yield p.relative_to(root).as_posix(), p


def _is_text_like(path: Path) -> bool:
    return path.suffix.lower() not in COMPRESSED_EXTENSIONS


def score_file_point(point: Path, previous: dict | None,
                     canaries: list[dict]) -> dict:
    """Score one file restore point. ``previous`` is the previous point's
    file map {rel_path: sha256} (or None for the first point)."""
    files: dict[str, str] = {}
    evidence: list[dict] = []
    points = 0.0

    # --- known extensions + ransom notes
    ext_hits: list[str] = []
    note_hits: list[str] = []
    for rel, _ in _iter_files(point):
        name = Path(rel).name
        if any(name.lower().endswith(ext) for ext in RANSOMWARE_EXTENSIONS):
            ext_hits.append(rel)
        stem = Path(name).stem.lower()
        if any(stem.startswith(s) for s in RANSOM_NOTE_STEMS):
            note_hits.append(rel)
    if ext_hits:
        earned = min(EXTENSION_MAX_POINTS, EXTENSION_POINTS_PER_FILE * len(ext_hits))
        points += earned
        evidence.append({"heuristic": "known ransomware extension",
                         "points": earned,
                         "detail": f"{len(ext_hits)} file(s): " + ", ".join(ext_hits[:5])})
    if note_hits:
        points += RANSOM_NOTE_POINTS
        evidence.append({"heuristic": "ransom note filename",
                         "points": RANSOM_NOTE_POINTS,
                         "detail": f"{len(note_hits)} file(s): " + ", ".join(note_hits[:5])})

    # --- canaries
    for canary in canaries:
        rel = canary["path"]
        expected = canary["sha256"]
        target = point / rel
        if not target.is_file():
            points += CANARY_POINTS
            evidence.append({"heuristic": "canary missing",
                             "points": CANARY_POINTS,
                             "detail": f"canary {rel} is missing from this point"})
        elif _file_hash(target) != expected:
            points += CANARY_POINTS
            evidence.append({"heuristic": "canary changed",
                             "points": CANARY_POINTS,
                             "detail": f"canary {rel} no longer matches its known hash"})

    # --- high-entropy files (text-like files only)
    high = 0
    total_text = 0
    high_names: list[str] = []
    for rel, abs_path in _iter_files(point):
        if not _is_text_like(abs_path):
            continue
        total_text += 1
        with open(abs_path, "rb") as f:
            sample = f.read(ENTROPY_SAMPLE_BYTES)
        if shannon_entropy(sample) >= ENTROPY_THRESHOLD_BITS:
            high += 1
            high_names.append(rel)
    if total_text and high:
        frac = high / total_text
        earned = round(ENTROPY_MAX_POINTS * frac, 1)
        points += earned
        evidence.append({"heuristic": "high-entropy files",
                         "points": earned,
                         "detail": f"{high}/{total_text} text-like files are high-entropy "
                                   f"(>= {ENTROPY_THRESHOLD_BITS} bits/byte): "
                                   + ", ".join(high_names[:5])})

    # --- mass change vs the previous point
    for rel, abs_path in _iter_files(point):
        files[rel] = _file_hash(abs_path)
    if previous is not None:
        prev_keys = set(previous)
        cur_keys = set(files)
        changed = len(prev_keys ^ cur_keys)
        changed += sum(1 for k in prev_keys & cur_keys if previous[k] != files[k])
        denom = max(len(prev_keys | cur_keys), 1)
        frac = changed / denom
        earned = round(MASS_CHANGE_MAX_POINTS * frac, 1)
        points += earned
        evidence.append({"heuristic": "mass change vs previous point",
                         "points": earned,
                         "detail": f"{changed}/{denom} files added, modified, or deleted "
                                   f"({frac * 100:.0f}%)"})
    return {
        "point": str(point),
        "kind": "files",
        # The score is capped at 100; the evidence lists the per-heuristic
        # points, which can sum past 100 on a badly infected point.
        "score": min(100, int(round(points))),
        "flagged": points >= FLAG_THRESHOLD,
        "evidence": evidence,
        "files": files,
    }


def score_db_point(point: Path, previous: dict | None) -> dict:
    """Score one database restore point (a plain-SQL dump). Only the
    row-level mass-change rate is measurable from a dump."""
    from .dbdiff import compare_dumps, parse_sql_dump
    evidence: list[dict] = []
    points = 0.0
    current = parse_sql_dump(point)
    if not current:
        evidence.append({"heuristic": "mass change vs previous dump",
                         "points": 0.0,
                         "detail": "no COPY data in this dump (mysqldump-style?) — "
                                   "mass change is not measurable"})
    elif previous is not None:
        frac, detail = compare_dumps(current, previous)
        points = round(100 * frac, 1)
        evidence.append({"heuristic": "mass change vs previous dump",
                         "points": points,
                         "detail": detail})
    return {
        "point": str(point),
        "kind": "database",
        # The score is capped at 100 (see score_file_point).
        "score": min(100, int(round(points))),
        "flagged": points >= FLAG_THRESHOLD,
        "evidence": evidence,
        "files": current,
    }


def load_canaries(path: Path | None) -> list[dict]:
    """Canary config: [{path: rel, sha256: hex}]. YAML or JSON."""
    if path is None:
        return []
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        import yaml
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    items = data.get("canaries") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError(f"canaries file {path} must list canaries")
    out = []
    for item in items:
        if not isinstance(item, dict) or "path" not in item or "sha256" not in item:
            raise ValueError(f"canaries file {path}: each canary needs path + sha256")
        out.append({"path": item["path"], "sha256": item["sha256"].lower()})
    return out


def recommend(points: list[dict]) -> dict:
    """The last clean point: the newest point older than the earliest
    flagged point. If none is flagged, the newest point. If every point is
    flagged, there is no clean point."""
    flagged_idx = [i for i, p in enumerate(points) if p["flagged"]]
    if not flagged_idx:
        last = points[-1] if points else None
        return {"clean_point": last["point"] if last else None,
                "clean_index": len(points) - 1 if points else None,
                "reason": "no signs found in any point examined",
                "flagged_points": []}
    first_flagged = min(flagged_idx)
    if first_flagged == 0:
        return {"clean_point": None, "clean_index": None,
                "reason": "the earliest point examined already shows signs",
                "flagged_points": [points[i]["point"] for i in flagged_idx]}
    clean = points[first_flagged - 1]
    return {"clean_point": clean["point"], "clean_index": first_flagged - 1,
            "reason": f"the point before the first flagged point "
                      f"({points[first_flagged]['point']})",
            "flagged_points": [points[i]["point"] for i in flagged_idx]}


# ---------------------------------------------------------------- CLI
def parse_clean_point_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Score restore points for ransomware signs and recommend "
                    "the last clean point.")
    ap.add_argument("points", nargs="+", type=Path,
                    help="restore points in order (oldest first): directories "
                         "of files, or plain-SQL database dumps (.sql)")
    ap.add_argument("--canaries", type=Path,
                    help="canary config file (YAML or JSON): [{path, sha256}]")
    ap.add_argument("--threshold", type=int, default=FLAG_THRESHOLD,
                    help=f"score at which a point is flagged (default {FLAG_THRESHOLD})")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--output", type=Path, help="write the report here as well as stdout")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def render_text(result: dict) -> str:
    lines = [f"Clean-point analysis (heuristics v{HEURISTICS_VERSION})", ""]
    for p in result["points"]:
        mark = "FLAG " if p["flagged"] else "ok   "
        lines.append(f"{mark}{p['point']} — score {p['score']}/100")
        for e in p["evidence"]:
            lines.append(f"       +{e['points']:.0f} {e['heuristic']}: {e['detail']}")
        if not p["evidence"]:
            lines.append("       no signs found")
    lines.append("")
    rec = result["recommendation"]
    if rec["clean_point"]:
        lines.append(f"Last clean point: {rec['clean_point']}")
        lines.append(f"  ({rec['reason']})")
    else:
        lines.append("No clean point found in the range examined.")
        lines.append(f"  ({rec['reason']})")
    if rec["flagged_points"]:
        lines.append(f"Flagged points: {', '.join(rec['flagged_points'])}")
    lines.append("")
    lines.append("Language note: a clean score means no signs were found, "
                 "not that the point is guaranteed clean.")
    return "\n".join(lines) + "\n"


def clean_point_main(argv=None) -> int:
    args = parse_clean_point_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    try:
        canaries = load_canaries(args.canaries)
    except (ValueError, FileNotFoundError, KeyError) as e:
        log.error("canaries error: %s", e)
        return EXIT_INFRA
    kinds = set()
    for p in args.points:
        if not p.exists():
            log.error("restore point not found: %s", p)
            return EXIT_INFRA
        kinds.add("database" if p.is_file() and p.suffix.lower() == ".sql" else "files")
    if len(kinds) > 1:
        log.error("do not mix file directories and .sql dumps in one run")
        return EXIT_INFRA
    kind = kinds.pop()
    scored: list[dict] = []
    previous = None
    for p in args.points:
        if kind == "database":
            scored.append(score_db_point(p, previous))
        else:
            scored.append(score_file_point(p, previous, canaries))
        previous = scored[-1]["files"]
        # The flag threshold is configurable; re-evaluate after scoring.
        scored[-1]["flagged"] = scored[-1]["score"] >= args.threshold
    # Strip the internal file maps from the output.
    for s in scored:
        s.pop("files", None)
    result = {"heuristics_version": HEURISTICS_VERSION,
              "threshold": args.threshold,
              "points": scored,
              "recommendation": recommend(scored)}
    if args.format == "json":
        out = json.dumps(result, indent=2) + "\n"
    else:
        out = render_text(result)
    sys.stdout.write(out)
    if args.output:
        args.output.write_text(out)
    return EXIT_CLEAN if result["recommendation"]["clean_point"] else EXIT_NO_CLEAN_POINT


if __name__ == "__main__":
    sys.exit(clean_point_main())
