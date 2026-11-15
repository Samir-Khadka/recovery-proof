"""Tests for the VM restore verifier (Phase 6 — VM)."""
from pathlib import Path

import pytest

from recovery_proof.vm import (
    detect_format,
    inspect_image,
    inspect_qcow2,
    inspect_raw,
    run_vm,
    verify_domain,
    vm_main,
)

FIX = Path(__file__).parent.parent / "fixtures" / "vm"


def test_detect_format():
    assert detect_format(FIX / "base.qcow2") == "qcow2"
    assert detect_format(FIX / "disk.raw") == "raw"


def test_good_qcow2_is_usable():
    r = inspect_qcow2(FIX / "base.qcow2")
    assert r["usable"] is True
    assert r["version"] == 3
    assert r["virtual_size"] == 1 << 20
    assert r["cluster_size"] == 1 << 16
    assert r["backing_file"] is None
    assert r["allocated_clusters"] == 1
    assert r["l2_tables"] == 1
    assert r["findings"] == []


def test_overlay_backing_chain_resolves():
    r = inspect_qcow2(FIX / "overlay.qcow2")
    assert r["usable"] is True
    assert r["backing_file"] == "base.qcow2"
    assert len(r["backing_chain"]) == 1
    assert r["backing_chain"][0].endswith("base.qcow2")


def test_overlay_with_missing_backing_file_is_not_usable():
    r = inspect_qcow2(FIX / "overlay-missing.qcow2")
    assert r["usable"] is False
    assert r["backing_file"] == "gone.qcow2"
    assert any(f["check"] == "backing file exists" for f in r["findings"])


def test_truncated_qcow2_is_not_usable():
    r = inspect_qcow2(FIX / "truncated.qcow2")
    assert r["usable"] is False
    assert any(f["check"] == "L2 tables are in the file" for f in r["findings"])


def test_corrupt_l2_entry_is_not_usable():
    r = inspect_qcow2(FIX / "corrupt-l2.qcow2")
    assert r["usable"] is False
    assert any(f["check"] == "data clusters are in the file" for f in r["findings"])


def test_bad_magic_is_not_qcow2(tmp_path):
    p = tmp_path / "bad.qcow2"
    p.write_bytes(b"NOPE" + b"\x00" * 200)
    r = inspect_qcow2(p)
    assert r["usable"] is False
    assert any("bad magic" in f["detail"] for f in r["findings"])


def test_raw_with_signatures():
    r = inspect_raw(FIX / "disk.raw")
    assert r["usable"] is True
    assert "MBR partition table" in r["signatures"]
    assert "ext4 filesystem" in r["signatures"]
    assert r["findings"] == []


def test_blank_raw_is_a_warning_not_an_error():
    r = inspect_raw(FIX / "blank.raw")
    assert r["usable"] is True
    assert r["signatures"] == []
    assert any(f["severity"] == "warning" for f in r["findings"])


def test_inspect_image_dispatches():
    assert inspect_image(FIX / "base.qcow2")["format"] == "qcow2"
    assert inspect_image(FIX / "disk.raw")["format"] == "raw"
    with pytest.raises(ValueError, match="not found"):
        inspect_image(FIX / "nope.qcow2")


def test_good_domain_is_restorable():
    r = verify_domain(FIX / "domain.xml", FIX)
    assert r["restorable"] is True
    assert r["name"] == "shop-vm"
    assert len(r["disks"]) == 1
    assert r["disks"][0]["source"] == "base.qcow2"
    assert r["disks"][0]["detected_format"] == "qcow2"
    assert r["findings"] == []


def test_domain_with_missing_disk_is_not_restorable():
    r = verify_domain(FIX / "domain-broken.xml", FIX)
    assert r["restorable"] is False
    assert any(f["check"] == "disk files exist" for f in r["findings"])


def test_domain_driver_mismatch_is_an_error():
    r = verify_domain(FIX / "domain-mismatch.xml", FIX)
    assert r["restorable"] is False
    assert any(f["check"] == "driver format matches the image" for f in r["findings"])


def test_domain_xml_that_does_not_parse(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<domain><unclosed>")
    with pytest.raises(ValueError, match="does not parse"):
        verify_domain(p)


def test_domain_without_name_is_an_error(tmp_path):
    p = tmp_path / "noname.xml"
    p.write_text("<domain type='kvm'><memory unit='KiB'>1024</memory>"
                 "<vcpu>1</vcpu><os><type>hvm</type></os><devices/></domain>")
    r = verify_domain(p)
    assert r["restorable"] is False
    assert any(f["check"] == "domain has a name" for f in r["findings"])


def test_run_vm_good_pair_is_ok():
    r = run_vm(FIX / "base.qcow2", FIX / "domain.xml", FIX)
    assert r["ok"] is True
    # The fixture dir holds other images, so the cross-check warns (not errors).
    assert all(f["severity"] == "warning" for f in r["cross_check"])


def test_run_vm_image_not_in_domain_is_an_error(tmp_path):
    # A clean backup dir holding only the domain's disk.
    clean = tmp_path / "backup"
    clean.mkdir()
    import shutil
    shutil.copy(FIX / "base.qcow2", clean / "base.qcow2")
    shutil.copy(FIX / "disk.raw", clean / "disk.raw")
    shutil.copy(FIX / "domain.xml", clean / "domain.xml")
    r = run_vm(clean / "disk.raw", clean / "domain.xml", clean)
    assert r["ok"] is False
    assert any(f["check"] == "the domain uses this image" for f in r["cross_check"])


def test_vm_cli_exit_codes(capsys):
    assert vm_main(["--image", str(FIX / "base.qcow2"),
                    "--domain", str(FIX / "domain.xml"),
                    "--backup-dir", str(FIX)]) == 0
    assert "Verdict: OK" in capsys.readouterr().out
    assert vm_main(["--image", str(FIX / "truncated.qcow2")]) == 1
    assert vm_main([]) == 2
    assert vm_main(["--image", str(FIX / "nope.qcow2")]) == 2
