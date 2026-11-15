"""Recovery Proof CLI: check a restore, report the measured recovery time.

``recovery-proof check`` passes its arguments straight through to the
checker's own parser (``recovery_proof.check.parse_check_args``), so the
check subcommand has exactly one definition of its flags.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .check import check_main
from .history import default_results_path
from .report import build_report


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="recovery-proof",
        description="Prove your backups actually restore.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="restore a Postgres backup and run checks",
                   add_help=False)
    sub.add_parser("audit", help="S3 backup protection audit (read-only)",
                   add_help=False)
    sub.add_parser("score", help="recovery readiness score (0-100) per system",
                   add_help=False)
    sub.add_parser("dashboard", help="static HTML dashboard from the histories",
                   add_help=False)
    sub.add_parser("clean-point", help="score restore points for ransomware signs",
                   add_help=False)
    sub.add_parser("drill", help="run a recovery drill from a YAML runbook",
                   add_help=False)
    sub.add_parser("k8s", help="verify a K8s workload can be restored",
                   add_help=False)
    sub.add_parser("vm", help="verify a VM backup can be restored",
                   add_help=False)
    report_p = sub.add_parser("report", help="measured recovery time from the results history")
    report_p.add_argument("--system", default=None,
                          help="label to report on (default: all systems)")
    report_p.add_argument("--results", type=Path, default=default_results_path(),
                          help="results history file")
    report_p.add_argument("--format", choices=["md", "json"], default="md")
    report_p.add_argument("--last", type=int, default=5,
                          help="recent runs to list (0 = none)")
    return ap


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "check":
        # Hand the whole tail (including -h) to the checker's own parser.
        return check_main(argv[1:])
    if argv and argv[0] == "audit":
        # Same: the audit has its own parser (recovery_proof.audit).
        from .audit import audit_main
        return audit_main(argv[1:])
    if argv and argv[0] == "score":
        from .score import score_main
        return score_main(argv[1:])
    if argv and argv[0] == "dashboard":
        from .dashboard import dashboard_main
        return dashboard_main(argv[1:])
    if argv and argv[0] == "clean-point":
        from .cleanpoint import clean_point_main
        return clean_point_main(argv[1:])
    if argv and argv[0] == "drill":
        from .drill import drill_main
        return drill_main(argv[1:])
    if argv and argv[0] == "k8s":
        from .k8s import k8s_main
        return k8s_main(argv[1:])
    if argv and argv[0] == "vm":
        from .vm import vm_main
        return vm_main(argv[1:])
    args = build_parser().parse_args(argv)
    if args.command == "report":
        try:
            print(build_report(args.results, args.system, args.last, args.format), end="")
        except ValueError as e:
            print(f"recovery-proof report: {e}", file=sys.stderr)
            return 2
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
