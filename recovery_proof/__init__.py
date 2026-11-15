"""Recovery Proof — prove your backups actually restore.

A vendor-neutral restore-testing layer. The Postgres checker restores a
backup into an ephemeral container, runs integrity and smoke-test checks,
records the measured restore time, and produces audit-ready proof.

Extracted from the Incident Copilot restore checker
(https://github.com/Samir-Khadka/incident-copilot, restore/check.py) and
extended: database integrity checks, an append-only results history with a
measured-RTO report, and a standalone CLI that works without the Copilot API.
"""

__version__ = "0.3.0"
