"""Tests for the Kubernetes restore verifier (Phase 6 — K8s)."""
import json
from pathlib import Path

import pytest

from recovery_proof.k8s import (
    _image_tag,
    inspect_velero,
    k8s_main,
    run_k8s,
    verify_manifests,
)

FIX = Path(__file__).parent.parent / "fixtures" / "k8s"


def test_image_tag():
    assert _image_tag("registry.example.com/app:1.4.2") == "1.4.2"
    assert _image_tag("registry.example.com:5000/app:1.0") == "1.0"
    assert _image_tag("app") is None
    assert _image_tag("app:latest") == "latest"


def test_good_manifests_are_restorable():
    r = verify_manifests(FIX / "manifests")
    assert r["restorable"] is True
    assert r["resources"] == 6
    assert r["findings"] == []


def test_broken_manifests_report_each_problem():
    r = verify_manifests(FIX / "manifests-broken")
    assert r["restorable"] is False
    checks = {(f["severity"], f["check"]) for f in r["findings"]}
    assert ("warning", "images are pinned") in checks
    assert ("error", "references exist") in checks
    assert ("error", "Services select a workload") in checks
    assert any("shop-config-missing" in f["detail"] for f in r["findings"])


def test_manifests_missing_directory(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        verify_manifests(tmp_path / "nope")


def test_manifests_empty_directory(tmp_path):
    with pytest.raises(ValueError, match="no YAML/JSON manifests"):
        verify_manifests(tmp_path)


def test_duplicate_resource_is_an_error(tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "a.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  namespace: shop\n")
    (d / "b.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n  namespace: shop\n")
    r = verify_manifests(d)
    assert r["restorable"] is False
    assert any(f["check"] == "no duplicate resources" for f in r["findings"])


def test_pvc_without_storage_request_is_an_error(tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "pvc.yaml").write_text(
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: data\n"
        "  namespace: shop\nspec:\n  accessModes: [ReadWriteOnce]\n")
    r = verify_manifests(d)
    assert r["restorable"] is False
    assert any(f["check"] == "PVCs request storage" for f in r["findings"])
    # No storageClassName is a warning, not an error.
    assert any(f["severity"] == "warning" and f["check"] == "PVCs name a storage class"
               for f in r["findings"])


def test_good_velero_backup_is_usable():
    r = inspect_velero(FIX / "velero-backup")
    assert r["usable"] is True
    assert r["phase"] == "Completed"
    assert r["format_version"] == "1.1.0"
    assert r["resources"] == 6
    assert r["by_kind"]["deployments"] == 1
    assert r["by_kind"]["persistentvolumeclaims"] == 1
    assert r["findings"] == []


def test_failed_velero_backup_is_not_usable():
    r = inspect_velero(FIX / "velero-backup-failed")
    assert r["usable"] is False
    assert r["phase"] == "Failed"
    assert any(f["check"] == "backup completed" for f in r["findings"])
    assert any(f["check"] == "no validation errors" for f in r["findings"])


def test_bare_tarball_skips_metadata_checks():
    r = inspect_velero(FIX / "velero-backup" / "nightly.tar.gz")
    assert r["usable"] is True  # the tarball reads and holds resources
    assert r["phase"] is None
    assert any(f["check"] == "backup metadata present" for f in r["findings"])


def test_velero_backup_missing(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        inspect_velero(tmp_path / "nope")


def test_pvc_without_snapshot_is_a_warning(tmp_path):
    # A backup whose PVC uid is not in volumeBackups.
    import shutil
    dest = tmp_path / "velero"
    shutil.copytree(FIX / "velero-backup", dest)
    meta = json.loads((dest / "velero-backup.json").read_text())
    meta["status"]["volumeBackups"] = {}
    (dest / "velero-backup.json").write_text(json.dumps(meta))
    r = inspect_velero(dest)
    assert r["usable"] is True  # a warning, not an error
    assert any(f["check"] == "PVCs have volume snapshots" for f in r["findings"])


def test_cross_check_passes_for_good_pair():
    r = run_k8s(FIX / "manifests", FIX / "velero-backup")
    assert r["ok"] is True
    assert r["cross_check"] == []


def test_cross_check_flags_a_workload_missing_from_the_backup(tmp_path):
    # Manifests define a deployment the backup does not hold.
    d = tmp_path / "m"
    d.mkdir()
    (d / "dep.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: ghost\n"
        "  namespace: shop\nspec:\n  selector:\n    matchLabels:\n      app: ghost\n"
        "  template:\n    metadata:\n      labels:\n        app: ghost\n"
        "    spec:\n      containers:\n        - name: g\n          image: example.com/g:1.0\n")
    r = run_k8s(d, FIX / "velero-backup")
    assert r["ok"] is False
    assert any("ghost" in f["detail"] and "not in the Velero backup" in f["detail"]
               for f in r["cross_check"])


def test_k8s_cli_exit_codes(tmp_path, capsys):
    assert k8s_main(["--manifests", str(FIX / "manifests"),
                     "--velero", str(FIX / "velero-backup")]) == 0
    assert "Verdict: OK" in capsys.readouterr().out
    assert k8s_main(["--manifests", str(FIX / "manifests-broken")]) == 1
    assert k8s_main([]) == 2  # neither --manifests nor --velero
    assert k8s_main(["--manifests", str(tmp_path / "nope")]) == 2
