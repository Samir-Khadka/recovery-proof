"""Generate the VM fixtures deterministically.

Run from the repo root:  python scripts/make_vm_fixtures.py
The fixtures are committed: tests run the verifier over them. The qcow2
images are minimal but structurally valid, built to the QEMU spec
(docs/specs/qcow2.txt): v3 header, 64 KiB clusters, 1 MiB virtual disk,
one L1 entry, one L2 table, one data cluster, a valid refcount table +
block.
"""
from __future__ import annotations

import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "vm"

CLUSTER_BITS = 16
CLUSTER_SIZE = 1 << CLUSTER_BITS  # 64 KiB
VIRTUAL_SIZE = 1 << 20  # 1 MiB
L1_SIZE = 1


def _qcow2_header(backing_name: bytes | None = None) -> bytearray:
    """A v3 header (104 bytes) for the fixture layout:
    cluster 0 header, 1 L1, 2 refcount table, 3 refcount block, 4 L2, 5 data.
    """
    h = bytearray(104)
    struct.pack_into(">4sI", h, 0, b"QFI\xfb", 3)
    if backing_name:
        # The backing file name lives in cluster 0, right after the header.
        struct.pack_into(">QI", h, 8, 104, len(backing_name))
    else:
        struct.pack_into(">QI", h, 8, 0, 0)
    struct.pack_into(">I", h, 20, CLUSTER_BITS)
    struct.pack_into(">Q", h, 24, VIRTUAL_SIZE)
    struct.pack_into(">I", h, 32, 0)  # crypt_method: none
    struct.pack_into(">I", h, 36, L1_SIZE)
    struct.pack_into(">Q", h, 40, CLUSTER_SIZE)  # L1 table: cluster 1
    struct.pack_into(">Q", h, 48, 2 * CLUSTER_SIZE)  # refcount table: cluster 2
    struct.pack_into(">I", h, 56, 1)  # refcount table clusters
    struct.pack_into(">I", h, 60, 0)  # nb_snapshots
    struct.pack_into(">Q", h, 64, 0)  # snapshots_offset
    struct.pack_into(">QQQ", h, 72, 0, 0, 0)  # feature bitmasks
    struct.pack_into(">I", h, 96, 4)  # refcount_order (16-bit entries)
    struct.pack_into(">I", h, 100, 104)  # header_length
    return h


def _build_qcow2(backing_name: bytes | None = None,
                 corrupt_l2: bool = False) -> bytes:
    """A minimal valid qcow2 image (6 clusters = 384 KiB)."""
    img = bytearray(6 * CLUSTER_SIZE)
    # --- cluster 0: header (+ backing name)
    img[0:104] = _qcow2_header(backing_name)
    if backing_name:
        img[104:104 + len(backing_name)] = backing_name
    # --- cluster 1: L1 table (1 entry -> L2 table at cluster 4, copied flag)
    struct.pack_into(">Q", img, CLUSTER_SIZE, (1 << 63) | (4 * CLUSTER_SIZE))
    # --- cluster 2: refcount table (1 entry -> refcount block at cluster 3)
    struct.pack_into(">Q", img, 2 * CLUSTER_SIZE, 3 * CLUSTER_SIZE)
    # --- cluster 3: refcount block (16-bit entries; clusters 0-5 in use)
    for i in range(6):
        struct.pack_into(">H", img, 3 * CLUSTER_SIZE + i * 2, 1)
    # --- cluster 4: L2 table (8192 entries; entry 0 -> data cluster 5)
    data_off = 0x50000 if not corrupt_l2 else 0xA00000  # past EOF when corrupt
    struct.pack_into(">Q", img, 4 * CLUSTER_SIZE, (1 << 63) | data_off)
    # --- cluster 5: data
    img[5 * CLUSTER_SIZE:5 * CLUSTER_SIZE + 64] = b"RECOVERY-PROOF-VM-FIXTURE" * 2 + b"\x00" * 16
    return bytes(img)


def _domain_xml(disk_file: str, driver: str = "qcow2") -> str:
    return f"""<domain type='kvm'>
  <name>shop-vm</name>
  <uuid>11111111-2222-3333-4444-555555555555</uuid>
  <memory unit='KiB'>2097152</memory>
  <vcpu placement='static'>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-8.0'>hvm</type>
    <boot dev='hd'/>
  </os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='{driver}'/>
      <source file='{disk_file}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='bridge'>
      <source bridge='br0'/>
      <model type='virtio'/>
    </interface>
  </devices>
</domain>
"""


def _raw_image(with_signatures: bool = True) -> bytes:
    img = bytearray(1 << 20)
    if with_signatures:
        img[510:512] = b"\x55\xaa"  # MBR
        img[1080:1082] = b"\x53\xef"  # ext4 magic
    return bytes(img)


def main() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    # --- good qcow2 + domain
    (ROOT / "base.qcow2").write_bytes(_build_qcow2())
    (ROOT / "domain.xml").write_text(_domain_xml("base.qcow2"))
    # --- overlay qcow2 whose backing file is base.qcow2
    (ROOT / "overlay.qcow2").write_bytes(_build_qcow2(b"base.qcow2"))
    (ROOT / "domain-overlay.xml").write_text(_domain_xml("overlay.qcow2"))
    # --- overlay whose backing file is missing
    (ROOT / "overlay-missing.qcow2").write_bytes(_build_qcow2(b"gone.qcow2"))
    # --- truncated qcow2 (cut mid-L2-table)
    good = _build_qcow2()
    (ROOT / "truncated.qcow2").write_bytes(good[:300000])
    # --- qcow2 whose L2 entry points past EOF
    (ROOT / "corrupt-l2.qcow2").write_bytes(_build_qcow2(corrupt_l2=True))
    # --- raw images
    (ROOT / "disk.raw").write_bytes(_raw_image(True))
    (ROOT / "blank.raw").write_bytes(_raw_image(False))
    # --- broken domain: a missing disk + a driver/format mismatch
    (ROOT / "domain-broken.xml").write_text(_domain_xml("missing.qcow2"))
    (ROOT / "domain-mismatch.xml").write_text(_domain_xml("base.qcow2", driver="raw"))
    print(f"fixtures written to {ROOT}")


if __name__ == "__main__":
    main()
