"""VM restore verification (Recovery Proof v0.8, Phase 6 — VM).

Three questions, answered from files (no hypervisor needed):
1. Is this disk image structurally sound? (qcow2: header, L1/L2 tables,
   refcount table, backing chain. raw: partition/filesystem signatures.)
2. Can this VM be recreated from its libvirt domain XML? (every disk
   exists, the declared driver format matches the detected image format,
   memory/CPU/OS are present, every interface has a source.)
3. With both: does the domain's disk match the image, and is every image
   in the backup directory referenced by a domain?

Format (verified against the QEMU spec, docs/specs/qcow2.txt, 2026-11-15):
all numbers big-endian. Header: magic "QFI\\xfb" (0-3), version 2 or 3
(4-7), backing_file_offset (8-15) + backing_file_size (16-19, <= 1023),
cluster_bits (20-23, >= 9, max 2 MiB cluster), size (24-31, virtual disk
size), crypt_method (32-35, 0 none / 1 AES), l1_size (36-39),
l1_table_offset (40-47, cluster-aligned), refcount_table_offset (48-55),
refcount_table_clusters (56-59), nb_snapshots (60-63), snapshots_offset
(64-71). Version 3 adds incompatible/compatible/autoclear features
(72-95), refcount_order (96-99), header_length (100-103, 72 for v2).
L1 entry: bits 9-55 = L2 table offset (0 = unallocated), bit 63 = copied.
L2 entry: bits 0-61 = cluster descriptor, bit 62 = compressed, bit 63 =
copied. Standard cluster descriptor: bit 0 = reads as zeros, bits 9-55 =
host cluster offset (0 = unallocated). Compressed descriptor: bits 0-x =
host offset (not necessarily aligned), x+1-61 = compressed size in
512-byte sectors, x = 62 - (cluster_bits - 8).

Findings have a severity: error (blocks a restore) or warning (risky but
restorable). The verdict is usable/restorable when there are no errors.

Limits, stated plainly: the verifier reads the tables, not the data — it
proves the image's structure is sound, not that the guest's filesystem
is intact (that is what the restore checker is for). It does not run
qemu-img, so it cannot catch corruption qemu-img check would find inside
a data cluster. A raw image has no structure to verify beyond its
signatures; a blank raw image is a warning, not an error. vmdk is not
supported yet — qcow2 and raw only.
"""
from __future__ import annotations

import argparse
import json
import logging
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger("recovery-proof.vm")

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_INFRA = 2

QCOW_MAGIC = b"QFI\xfb"
QCOW_VERSIONS = (2, 3)
MAX_BACKING_CHAIN = 10
MAX_CLUSTER_BITS = 21  # 2 MiB, qemu's implementation limit

# Raw-image signatures: (name, offset, bytes). A raw image with none of
# these is blank, encrypted, or corrupt — a warning, not an error.
RAW_SIGNATURES = [
    ("MBR partition table", 510, b"\x55\xaa"),
    ("GPT partition table", 512, b"EFI PART"),
    ("ext4 filesystem", 1080, b"\x53\xef"),
    ("XFS filesystem", 0, b"XFSB"),
    ("NTFS filesystem", 3, b"NTFS    "),
    ("FAT filesystem", 82, b"FAT32   "),
    ("LUKS encrypted volume", 0, b"LUKS\xba\xbe"),
]


def _finding(severity: str, check: str, detail: str) -> dict:
    return {"severity": severity, "check": check, "detail": detail}


def _read_at(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    return f.read(size)


def _parse_qcow2_header(data: bytes) -> dict:
    """Parse the qcow2 header. Raises ValueError on a bad header."""
    if len(data) < 72:
        raise ValueError("file is too small for a qcow2 header (needs 72 bytes)")
    magic, version = struct.unpack_from(">4sI", data, 0)
    if magic != QCOW_MAGIC:
        raise ValueError("not a qcow2 image (bad magic)")
    if version not in QCOW_VERSIONS:
        raise ValueError(f"unsupported qcow2 version {version}")
    (backing_off, backing_size, cluster_bits, size, crypt_method,
     l1_size, l1_off, refcount_off, refcount_clusters,
     nb_snapshots, snapshots_off) = struct.unpack_from(">QIIQIIQQIIQ", data, 8)
    if cluster_bits < 9 or cluster_bits > MAX_CLUSTER_BITS:
        raise ValueError(f"cluster_bits {cluster_bits} is out of range (9–{MAX_CLUSTER_BITS})")
    if size == 0:
        raise ValueError("virtual disk size is 0")
    if crypt_method not in (0, 1):
        raise ValueError(f"unknown crypt_method {crypt_method}")
    if backing_size > 1023:
        raise ValueError(f"backing_file_size {backing_size} exceeds 1023")
    header = {"version": version, "backing_file_offset": backing_off,
              "backing_file_size": backing_size, "cluster_bits": cluster_bits,
              "cluster_size": 1 << cluster_bits, "size": size,
              "crypt_method": crypt_method, "l1_size": l1_size,
              "l1_table_offset": l1_off, "refcount_table_offset": refcount_off,
              "refcount_table_clusters": refcount_clusters,
              "nb_snapshots": nb_snapshots, "snapshots_offset": snapshots_off,
              "refcount_order": 4, "header_length": 72}
    if version >= 3:
        if len(data) < 104:
            raise ValueError("file is too small for a qcow2 v3 header (needs 104 bytes)")
        (incompat, compat, autoclear, refcount_order,
         header_length) = struct.unpack_from(">QQQII", data, 72)
        header.update({"incompatible_features": incompat,
                       "compatible_features": compat,
                       "autoclear_features": autoclear,
                       "refcount_order": refcount_order,
                       "header_length": header_length})
        if incompat != 0:
            raise ValueError(f"unknown incompatible features 0x{incompat:x}")
    return header


def inspect_qcow2(path: Path, _depth: int = 0) -> dict:
    """Inspect a qcow2 image: header, L1/L2 tables, refcount table, and
    the backing chain (recursed, depth-limited, cycle-checked)."""
    findings: list[dict] = []
    file_size = path.stat().st_size
    try:
        with open(path, "rb") as f:
            header = _parse_qcow2_header(_read_at(f, 0, 104))
    except (ValueError, OSError) as e:
        return {"format": "qcow2", "path": str(path), "file_size": file_size,
                "version": None, "virtual_size": None, "cluster_size": None,
                "backing_file": None, "backing_chain": [],
                "l1_entries": 0, "l2_tables": 0, "allocated_clusters": 0,
                "zero_clusters": 0, "compressed_clusters": 0, "snapshots": [],
                "findings": [_finding("error", "header parses", str(e))],
                "usable": False}
    with open(path, "rb") as f:
        cluster_size = header["cluster_size"]
        # --- backing file name (stored in the first cluster, after the header)
        backing_name = None
        if header["backing_file_offset"] and header["backing_file_size"]:
            raw = _read_at(f, header["backing_file_offset"], header["backing_file_size"])
            backing_name = raw.decode("utf-8", errors="replace")
        # --- L1 table
        l1_off = header["l1_table_offset"]
        l1_size = header["l1_size"]
        if l1_off % cluster_size != 0:
            findings.append(_finding("error", "L1 table is aligned",
                                     f"L1 table offset {l1_off} is not cluster-aligned"))
        if l1_off + l1_size * 8 > file_size:
            findings.append(_finding("error", "L1 table is in the file",
                                     f"L1 table ({l1_size} entries at {l1_off}) runs past EOF "
                                     f"({file_size} bytes)"))
            l1_entries: list[int] = []
        else:
            l1_entries = list(struct.unpack_from(f">{l1_size}Q",
                                                 _read_at(f, l1_off, l1_size * 8), 0))
        # --- refcount table
        rc_off = header["refcount_table_offset"]
        if rc_off % cluster_size != 0:
            findings.append(_finding("error", "refcount table is aligned",
                                     f"refcount table offset {rc_off} is not cluster-aligned"))
        if rc_off + header["refcount_table_clusters"] * cluster_size > file_size:
            findings.append(_finding("error", "refcount table is in the file",
                                     f"refcount table at {rc_off} runs past EOF"))
        # --- walk L1 -> L2 -> clusters
        allocated = zero = compressed = 0
        l2_tables = 0
        for entry in l1_entries:
            l2_off = entry & 0x00FFFFFFFFFFFE00  # bits 9-55
            if l2_off == 0:
                continue
            if l2_off % cluster_size != 0:
                findings.append(_finding("error", "L2 tables are aligned",
                                         f"L2 table offset {l2_off} is not cluster-aligned"))
                continue
            if l2_off + cluster_size > file_size:
                findings.append(_finding("error", "L2 tables are in the file",
                                         f"L2 table at {l2_off} runs past EOF"))
                continue
            l2_tables += 1
            l2_entries = struct.unpack_from(f">{cluster_size // 8}Q",
                                            _read_at(f, l2_off, cluster_size), 0)
            for l2 in l2_entries:
                if l2 == 0:
                    continue
                if l2 & (1 << 62):
                    # Compressed cluster: bits 0-x = host offset, x+1-61 = size in sectors.
                    x = 62 - (header["cluster_bits"] - 8)
                    host_off = l2 & ((1 << (x + 1)) - 1)
                    sectors = (l2 >> (x + 1)) & ((1 << (61 - x)) - 1)
                    compressed += 1
                    if host_off + sectors * 512 > file_size:
                        findings.append(_finding("error", "compressed clusters are in the file",
                                                 f"compressed cluster at {host_off} "
                                                 f"({sectors} sectors) runs past EOF"))
                    continue
                desc = l2 & ((1 << 62) - 1)
                if desc & 1:
                    zero += 1  # reads as zeros; the host offset is a preallocation hint
                    continue
                host_off = desc & 0x00FFFFFFFFFFFE00  # bits 9-55
                if host_off == 0:
                    continue  # unallocated
                allocated += 1
                if host_off % cluster_size != 0:
                    findings.append(_finding("error", "data clusters are aligned",
                                             f"data cluster offset {host_off} is not "
                                             f"cluster-aligned"))
                elif host_off + cluster_size > file_size:
                    findings.append(_finding("error", "data clusters are in the file",
                                             f"data cluster at {host_off} runs past EOF"))
        # --- snapshots (names only — the table is informational here)
        snapshots: list[str] = []
        if header["nb_snapshots"]:
            snap_off = header["snapshots_offset"]
            if snap_off == 0 or snap_off >= file_size:
                findings.append(_finding("error", "snapshot table is in the file",
                                         f"snapshot table at {snap_off} is outside the file"))
            else:
                try:
                    pos = snap_off
                    for _ in range(header["nb_snapshots"]):
                        entry = _read_at(f, pos, 40)
                        (snap_l1_off, snap_l1_size, id_len, name_len,
                         date_sec, date_nsec) = struct.unpack_from(">QIIHHII", entry, 0)
                        extra_size = struct.unpack_from(">I", entry, 36)[0]
                        name_off = pos + 40 + extra_size
                        name = _read_at(f, name_off + id_len, name_len).decode(
                            "utf-8", errors="replace")
                        snapshots.append(name)
                        pos = name_off + id_len + name_len
                        pos = (pos + 7) // 8 * 8  # 8-byte aligned
                except Exception as e:  # noqa: BLE001 - a bad snapshot table is a finding
                    findings.append(_finding("error", "snapshot table parses",
                                             f"snapshot table: {e}"))
    if header["crypt_method"] == 1:
        findings.append(_finding("warning", "encryption is readable",
                                 "legacy AES encryption — the structure is checked, "
                                 "but the verifier cannot read encrypted clusters"))
    errors = [f for f in findings if f["severity"] == "error"]
    result = {"format": "qcow2", "path": str(path), "file_size": file_size,
              "version": header["version"],
              "virtual_size": header["size"],
              "cluster_size": cluster_size,
              "backing_file": backing_name,
              "backing_chain": [],
              "l1_entries": l1_size, "l2_tables": l2_tables,
              "allocated_clusters": allocated,
              "zero_clusters": zero, "compressed_clusters": compressed,
              "snapshots": snapshots,
              "findings": findings,
              "usable": not errors}
    # --- backing chain (recursed; depth-limited; cycle-checked)
    if backing_name and _depth < MAX_BACKING_CHAIN:
        backing_path = Path(backing_name)
        if not backing_path.is_absolute():
            backing_path = path.parent / backing_path
        if not backing_path.exists():
            result["findings"].append(_finding(
                "error", "backing file exists",
                f"backing file '{backing_name}' not found (looked at {backing_path})"))
            result["usable"] = False
        else:
            with open(backing_path, "rb") as bf:
                if bf.read(4) == QCOW_MAGIC:
                    chain = inspect_qcow2(backing_path, _depth + 1)
                    result["backing_chain"] = [chain["path"]] + chain["backing_chain"]
                    if not chain["usable"]:
                        result["findings"].append(_finding(
                            "error", "backing file is usable",
                            f"backing file '{backing_name}' is not usable"))
                        result["usable"] = False
                else:
                    result["backing_chain"] = [str(backing_path)]
    elif backing_name:
        result["findings"].append(_finding(
            "warning", "backing chain is short",
            f"backing chain deeper than {MAX_BACKING_CHAIN} — not followed further"))
    return result


def inspect_raw(path: Path) -> dict:
    """Inspect a raw disk image: look for partition/filesystem signatures."""
    findings: list[dict] = []
    file_size = path.stat().st_size
    with open(path, "rb") as f:
        head = _read_at(f, 0, 4096)
        signatures = []
        for name, offset, magic in RAW_SIGNATURES:
            if len(head) >= offset + len(magic) and head[offset:offset + len(magic)] == magic:
                signatures.append(name)
    if not signatures:
        findings.append(_finding("warning", "disk has a recognisable signature",
                                 "no partition table or filesystem signature found — "
                                 "the disk may be blank, encrypted, or corrupt"))
    return {"format": "raw", "path": str(path), "file_size": file_size,
            "signatures": signatures, "findings": findings,
            "usable": True}  # a raw image has no structure to be broken


def detect_format(path: Path) -> str:
    """qcow2, raw, or unknown (by magic bytes)."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head == QCOW_MAGIC:
        return "qcow2"
    return "raw"


def inspect_image(path: Path) -> dict:
    """Inspect a disk image, dispatching on its detected format."""
    if not path.is_file():
        raise ValueError(f"disk image not found: {path}")
    if detect_format(path) == "qcow2":
        return inspect_qcow2(path)
    return inspect_raw(path)


# ---------------------------------------------------------------- libvirt XML
def verify_domain(xml_path: Path, backup_dir: Path | None = None) -> dict:
    """Verify a libvirt domain XML: disks exist, formats match, resources sane."""
    findings: list[dict] = []
    if not xml_path.is_file():
        raise ValueError(f"domain XML not found: {xml_path}")
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        raise ValueError(f"domain XML does not parse: {e}") from None
    if root.tag != "domain":
        raise ValueError(f"domain XML root is <{root.tag}>, expected <domain>")
    base = backup_dir or xml_path.parent
    name = (root.findtext("name") or "").strip()
    if not name:
        findings.append(_finding("error", "domain has a name",
                                 "no <name> in the domain XML"))
    uuid = (root.findtext("uuid") or "").strip()
    memory = root.findtext("memory")
    vcpu = root.findtext("vcpu")

    def _positive_int(text) -> bool:
        try:
            return int(text or 0) > 0
        except (ValueError, TypeError):
            return False

    if not _positive_int(memory):
        findings.append(_finding("error", "domain has memory",
                                 "no usable <memory> in the domain XML"))
    if not _positive_int(vcpu):
        findings.append(_finding("error", "domain has vCPUs",
                                 "no usable <vcpu> in the domain XML"))
    os_type = root.find("os/type")
    if os_type is None or not (os_type.text or "").strip():
        findings.append(_finding("error", "domain has an OS type",
                                 "no <os><type> in the domain XML"))
    disks: list[dict] = []
    devices = root.find("devices")
    if devices is None:
        findings.append(_finding("error", "domain has devices",
                                 "no <devices> in the domain XML"))
    else:
        for disk in devices.findall("disk"):
            device = disk.get("device") or "disk"
            if device != "disk":
                continue  # cdrom/floppy without a source is normal
            target = disk.find("target")
            dev = (target.get("dev") if target is not None else None) or "?"
            source = disk.find("source")
            src = source.get("file") if source is not None else None
            driver = disk.find("driver")
            declared = driver.get("type") if driver is not None else None
            if not src:
                findings.append(_finding("error", "disks have a source",
                                         f"disk {dev}: no <source file>"))
                disks.append({"dev": dev, "source": None, "declared_format": declared,
                              "exists": False, "detected_format": None})
                continue
            src_path = Path(src)
            if not src_path.is_absolute():
                src_path = base / src_path
            exists = src_path.is_file()
            detected = detect_format(src_path) if exists else None
            if not exists:
                findings.append(_finding("error", "disk files exist",
                                         f"disk {dev}: source '{src}' not found "
                                         f"(looked at {src_path})"))
            elif declared and declared != detected:
                findings.append(_finding("error", "driver format matches the image",
                                         f"disk {dev}: driver says {declared!r} but the "
                                         f"file is {detected}"))
            elif not declared:
                findings.append(_finding("warning", "disks declare a format",
                                         f"disk {dev}: no driver type — assuming {detected}"))
            disks.append({"dev": dev, "source": src, "declared_format": declared,
                          "exists": exists, "detected_format": detected})
        for iface in devices.findall("interface"):
            if iface.find("source") is None:
                findings.append(_finding("error", "interfaces have a source",
                                         "an <interface> has no <source>"))
    errors = [f for f in findings if f["severity"] == "error"]
    return {"kind": "domain", "path": str(xml_path), "name": name or None,
            "uuid": uuid or None, "memory": memory, "vcpu": vcpu,
            "disks": disks,
            "interfaces": len(devices.findall("interface")) if devices is not None else 0,
            "findings": findings,
            "restorable": not errors}


def run_vm(image: Path | None, domain: Path | None,
           backup_dir: Path | None = None) -> dict:
    """Run the VM verification. Returns the combined result dict."""
    if image is None and domain is None:
        raise ValueError("give --image, --domain, or both")
    result: dict = {"image": None, "domain": None, "cross_check": []}
    if image is not None:
        result["image"] = inspect_image(image)
    if domain is not None:
        result["domain"] = verify_domain(domain, backup_dir)
    if image is not None and domain is not None:
        # The domain's disks must include the image given.
        sources = {d["source"] for d in result["domain"]["disks"] if d["source"]}
        image_name = image.name
        if image_name not in sources and str(image) not in sources:
            result["cross_check"].append(_finding(
                "error", "the domain uses this image",
                f"image {image_name} is not referenced by the domain XML"))
        # Every image file in the backup directory should be referenced.
        base = backup_dir or domain.parent
        for candidate in sorted(base.iterdir()):
            if candidate.is_file() and candidate.suffix.lower() in (".qcow2", ".img", ".raw"):
                if candidate.name not in sources and str(candidate) not in sources:
                    result["cross_check"].append(_finding(
                        "warning", "images in the backup are referenced",
                        f"{candidate.name} is in the backup directory but no domain "
                        f"references it"))
    errors = 0
    if result["image"]:
        errors += sum(1 for f in result["image"]["findings"] if f["severity"] == "error")
    if result["domain"]:
        errors += sum(1 for f in result["domain"]["findings"] if f["severity"] == "error")
    errors += sum(1 for f in result["cross_check"] if f["severity"] == "error")
    result["ok"] = errors == 0
    return result


def render_text(result: dict) -> str:
    lines = ["VM restore verification", ""]
    if result["image"]:
        img = result["image"]
        if img["format"] == "qcow2":
            lines.append(f"Image ({img['path']}): qcow2 v{img['version']}, "
                         f"virtual {img['virtual_size']} bytes, "
                         f"{img['allocated_clusters']} allocated clusters"
                         + (f", backing file {img['backing_file']}" if img["backing_file"] else "")
                         + f" — {'usable' if img['usable'] else 'NOT usable'}")
            if img["snapshots"]:
                lines.append(f"  snapshots: {', '.join(img['snapshots'])}")
        else:
            sigs = ", ".join(img["signatures"]) if img["signatures"] else "none"
            lines.append(f"Image ({img['path']}): raw, {img['file_size']} bytes, "
                         f"signatures: {sigs} — usable")
        for f in img["findings"]:
            lines.append(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")
        if not img["findings"]:
            lines.append("  no findings")
    if result["domain"]:
        d = result["domain"]
        lines.append(f"Domain ({d['path']}): {d['name'] or '?'} — "
                     f"{'restorable' if d['restorable'] else 'NOT restorable'}")
        for disk in d["disks"]:
            lines.append(f"  disk {disk['dev']}: {disk['source']} "
                         f"({disk['declared_format'] or 'undeclared'} / "
                         f"{disk['detected_format'] or 'missing'})")
        for f in d["findings"]:
            lines.append(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")
        if not d["findings"]:
            lines.append("  no findings")
    if result["cross_check"]:
        lines.append("Cross-check:")
        for f in result["cross_check"]:
            lines.append(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")
    elif result["image"] and result["domain"]:
        lines.append("Cross-check: the domain uses this image.")
    lines.append("")
    lines.append("Verdict: " + ("OK — the VM can be recreated from this backup."
                                if result["ok"] else
                                "NOT OK — see the errors above."))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- CLI
def parse_vm_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Verify a VM backup can be restored: inspect a disk "
                    "image, a libvirt domain XML, or both.")
    ap.add_argument("--image", type=Path, help="disk image file (.qcow2, .img, .raw)")
    ap.add_argument("--domain", type=Path, help="libvirt domain XML file")
    ap.add_argument("--backup-dir", type=Path,
                    help="directory holding the backup (resolves relative disk paths)")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--output", type=Path, help="write the report here as well as stdout")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def vm_main(argv=None) -> int:
    args = parse_vm_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    try:
        result = run_vm(args.image, args.domain, args.backup_dir)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    if args.format == "json":
        out = json.dumps(result, indent=2) + "\n"
    else:
        out = render_text(result)
    sys.stdout.write(out)
    if args.output:
        args.output.write_text(out)
    return EXIT_OK if result["ok"] else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(vm_main())
