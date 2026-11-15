"""Kubernetes restore verification (Recovery Proof v0.7, Phase 6 — K8s).

Two questions, answered from files (no cluster needed):
1. Can this workload be recreated from its manifests? (a manifest bundle,
   usually from Git) — every referenced ConfigMap/Secret/PVC exists, every
   container image is pinned, every Service selects a workload, no
   duplicate resource, every PVC asks for storage.
2. Is this Velero backup usable? (a backup directory from object storage,
   or a bare .tar.gz) — the backup completed, the format is one we
   understand, the tarball reads, its resources are valid JSON, and every
   PVC that should have a volume snapshot has one.

With both, the verifier cross-checks: every workload the manifests define
must appear in the backup, or it is not backed up.

Format (verified against the Velero docs, velero.io output-file-format,
2026-11-15): object storage holds <backup-name>/velero-backup.json
(the Backup resource: spec + status.phase + status.formatVersion +
status.volumeBackups) next to <backup-name>.tar.gz. The tarball holds
resources/<kind>/... in format 1.1 (per-API-group-version sub-directories,
preferred version suffixed "-preferredversion") or format 1 (no version
directories). Companion files (<name>-volumesnapshots.json.gz, etc.) are
read when present.

Findings have a severity: error (blocks a restore) or warning (risky but
restorable). The verdict is usable/restorable when there are no errors.
A bare tarball (no velero-backup.json) is inspected without the phase and
snapshot checks, and says so.

Limits, stated plainly: the verifier reads the whole tarball (it parses
every resource file's JSON), so a very large backup is slow; it does not
talk to a cluster, so it cannot know the cluster's default storage class
(a PVC without one is a warning, not an error), and it cannot prove a
volume snapshot's data is intact — only that the snapshot exists.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import logging
import sys
import tarfile
from pathlib import Path

log = logging.getLogger("recovery-proof.k8s")

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_INFRA = 2

SUPPORTED_FORMAT_MAJOR = 1
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}


def _finding(severity: str, check: str, detail: str) -> dict:
    return {"severity": severity, "check": check, "detail": detail}


def _load_yaml_docs(path: Path) -> list[dict]:
    import yaml
    docs = []
    for doc in yaml.safe_load_all(path.read_text()):
        if doc is not None:
            docs.append(doc)
    return docs


def _image_tag(image: str) -> str | None:
    """The tag of a container image, or None if unpinned (no tag)."""
    last_slash = image.rfind("/")
    last_colon = image.rfind(":")
    if last_colon <= last_slash:
        return None
    return image[last_colon + 1:]


def _pod_template(doc: dict) -> dict | None:
    """The pod template of a workload, or the Pod itself."""
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec", {})
    if kind == "CronJob":
        return doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    return doc.get("spec", {}).get("template", {}).get("spec", {})


def _pod_labels(doc: dict) -> dict:
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("metadata", {}).get("labels", {}) or {}
    if kind == "CronJob":
        return (doc.get("spec", {}).get("jobTemplate", {}).get("spec", {})
                .get("template", {}).get("metadata", {}).get("labels", {}) or {})
    return doc.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {}) or {}


def verify_manifests(directory: Path) -> dict:
    """Verify a directory of K8s YAML manifests. Returns the result dict."""
    findings: list[dict] = []
    resources: list[dict] = []
    if not directory.is_dir():
        raise ValueError(f"manifests directory not found: {directory}")
    files = sorted(p for p in directory.rglob("*")
                   if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".json"))
    if not files:
        raise ValueError(f"no YAML/JSON manifests in {directory}")
    for path in files:
        try:
            docs = _load_yaml_docs(path) if path.suffix.lower() != ".json" else [json.loads(path.read_text())]
        except Exception as e:  # noqa: BLE001 - a bad file is a finding, not a crash
            findings.append(_finding("error", "manifest parses",
                                     f"{path.name}: {e}"))
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                findings.append(_finding("error", "manifest parses",
                                         f"{path.name}: a document is not a mapping"))
                continue
            kind = doc.get("kind")
            meta = doc.get("metadata") or {}
            name = meta.get("name")
            if not kind or not name:
                findings.append(_finding("error", "manifest parses",
                                         f"{path.name}: a document has no kind or metadata.name"))
                continue
            resources.append({"kind": kind, "name": name,
                              "namespace": meta.get("namespace") or "default",
                              "doc": doc})
    # --- duplicates
    seen: dict[tuple, Path] = {}
    for r in resources:
        key = (r["kind"], r["namespace"], r["name"])
        if key in seen:
            findings.append(_finding("error", "no duplicate resources",
                                     f"{r['kind']}/{r['namespace']}/{r['name']} defined twice"))
        seen[key] = True
    index = {(r["kind"], r["namespace"], r["name"]) for r in resources}

    def _exists(kind: str, namespace: str, name: str) -> bool:
        return (kind, namespace, name) in index

    for r in resources:
        ns = r["namespace"]
        doc = r["doc"]
        kind = r["kind"]
        # --- workload references + image pinning
        if kind in WORKLOAD_KINDS:
            spec = _pod_template(doc) or {}
            for container in spec.get("containers", []) + spec.get("initContainers", []):
                image = container.get("image") or ""
                tag = _image_tag(image)
                if tag is None or tag == "latest":
                    findings.append(_finding("warning", "images are pinned",
                                             f"{kind}/{ns}/{r['name']}: container "
                                             f"'{container.get('name')}' uses unpinned image '{image}'"))
                for env in container.get("env", []) or []:
                    vf = env.get("valueFrom") or {}
                    for ref_kind, ref_key in (("ConfigMap", "configMapKeyRef"),
                                              ("Secret", "secretKeyRef")):
                        ref = vf.get(ref_key)
                        if ref and not _exists(ref_kind, ns, ref.get("name")):
                            findings.append(_finding("error", "references exist",
                                                     f"{kind}/{ns}/{r['name']}: {ref_kind} "
                                                     f"'{ref.get('name')}' not in the bundle"))
                for env_from in container.get("envFrom", []) or []:
                    for ref_kind, ref_key in (("ConfigMap", "configMapRef"),
                                              ("Secret", "secretRef")):
                        ref = env_from.get(ref_key)
                        if ref and not _exists(ref_kind, ns, ref.get("name")):
                            findings.append(_finding("error", "references exist",
                                                     f"{kind}/{ns}/{r['name']}: {ref_kind} "
                                                     f"'{ref.get('name')}' not in the bundle"))
            for vol in spec.get("volumes", []) or []:
                for ref_kind, ref_key in (("ConfigMap", "configMap"),
                                          ("Secret", "secret")):
                    ref = vol.get(ref_key)
                    if ref and not _exists(ref_kind, ns, ref.get("name")):
                        findings.append(_finding("error", "references exist",
                                                 f"{kind}/{ns}/{r['name']}: {ref_kind} "
                                                 f"'{ref.get('name')}' not in the bundle"))
                claim = vol.get("persistentVolumeClaim")
                if claim and not _exists("PersistentVolumeClaim", ns, claim.get("claimName")):
                    findings.append(_finding("error", "references exist",
                                             f"{kind}/{ns}/{r['name']}: PVC "
                                             f"'{claim.get('claimName')}' not in the bundle"))
        # --- PVC storage
        if kind == "PersistentVolumeClaim":
            storage = ((doc.get("spec", {}).get("resources", {}).get("requests", {}) or {})
                       .get("storage"))
            if not storage:
                findings.append(_finding("error", "PVCs request storage",
                                         f"PVC/{ns}/{r['name']}: no storage request"))
            if not doc.get("spec", {}).get("storageClassName"):
                findings.append(_finding("warning", "PVCs name a storage class",
                                         f"PVC/{ns}/{r['name']}: no storageClassName — "
                                         f"relies on the cluster default"))
        # --- Service selectors
        if kind == "Service":
            selector = doc.get("spec", {}).get("selector") or {}
            if selector:
                matched = any(
                    all(_pod_labels(w["doc"]).get(k) == v for k, v in selector.items())
                    for w in resources
                    if w["kind"] in WORKLOAD_KINDS and w["namespace"] == ns)
                if not matched:
                    findings.append(_finding("error", "Services select a workload",
                                             f"Service/{ns}/{r['name']}: selector {selector} "
                                             f"matches no workload in the bundle"))
    errors = [f for f in findings if f["severity"] == "error"]
    return {"kind": "manifests", "path": str(directory),
            "resources": len(resources),
            "resource_list": [{"kind": r["kind"], "name": r["name"],
                               "namespace": r["namespace"]} for r in resources],
            "findings": findings,
            "restorable": not errors}


def _parse_velero_metadata(directory: Path) -> dict | None:
    meta_path = directory / "velero-backup.json"
    if not meta_path.is_file():
        return None
    return json.loads(meta_path.read_text())


def _find_tarball(directory: Path) -> Path | None:
    tars = sorted(directory.glob("*.tar.gz"))
    if tars:
        return tars[0]
    return None


def _tarball_resources(tar_path: Path) -> tuple[list[dict], list[dict]]:
    """(resources, findings) from a Velero .tar.gz. Each resource is
    {kind, namespace, name, uid} parsed from its path + JSON content."""
    resources: list[dict] = []
    findings: list[dict] = []
    try:
        tf = tarfile.open(tar_path, "r:gz")
    except (tarfile.TarError, OSError, EOFError) as e:
        findings.append(_finding("error", "tarball reads",
                                 f"{tar_path.name}: {e}"))
        return resources, findings
    with tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        resource_members = [m for m in members
                            if m.name.startswith("resources/") and m.name.endswith(".json")]
        if not resource_members:
            findings.append(_finding("error", "tarball holds resources",
                                     f"{tar_path.name}: no resources/*.json files"))
        for m in resource_members:
            parts = m.name.split("/")
            # resources/<kind>/[version/]cluster|namespaces/<ns>/<name>.json
            if len(parts) < 4:
                continue
            kind_plural = parts[1]
            if "namespaces" in parts:
                ns_idx = parts.index("namespaces")
                namespace = parts[ns_idx + 1] if ns_idx + 1 < len(parts) else "default"
            else:
                namespace = "cluster"
            name = Path(parts[-1]).stem
            try:
                data = json.loads(tf.extractfile(m).read())
                uid = (data.get("metadata") or {}).get("uid")
            except Exception as e:  # noqa: BLE001 - a bad resource file is a finding
                findings.append(_finding("error", "resource files are valid JSON",
                                         f"{m.name}: {e}"))
                uid = None
            resources.append({"kind": kind_plural, "namespace": namespace,
                              "name": name, "uid": uid})
    return resources, findings


def inspect_velero(path: Path) -> dict:
    """Inspect a Velero backup: a directory (object-storage layout) or a
    bare .tar.gz. Returns the result dict."""
    findings: list[dict] = []
    metadata: dict | None = None
    tarball: Path | None = None
    if path.is_dir():
        metadata = _parse_velero_metadata(path)
        tarball = _find_tarball(path)
        if tarball is None:
            findings.append(_finding("error", "tarball present",
                                     f"{path}: no *.tar.gz in the backup directory"))
    elif path.is_file() and path.name.endswith(".tar.gz"):
        tarball = path
    else:
        raise ValueError(f"velero backup not found: {path} (expected a directory "
                         f"or a .tar.gz)")
    phase = (metadata or {}).get("status", {}).get("phase") if metadata else None
    format_version = (metadata or {}).get("status", {}).get("formatVersion") if metadata else None
    if metadata is None:
        findings.append(_finding("warning", "backup metadata present",
                                 "no velero-backup.json — phase and snapshot checks skipped"))
    else:
        if phase != "Completed":
            findings.append(_finding("error", "backup completed",
                                     f"phase is {phase!r}, not 'Completed'"))
        if format_version:
            try:
                major = int(str(format_version).split(".")[0])
            except ValueError:
                major = None
            if major != SUPPORTED_FORMAT_MAJOR:
                findings.append(_finding("error", "format version supported",
                                         f"formatVersion {format_version!r} is not major version "
                                         f"{SUPPORTED_FORMAT_MAJOR}"))
        for err in (metadata.get("status", {}) or {}).get("validationErrors") or []:
            findings.append(_finding("error", "no validation errors",
                                     f"validation error: {err}"))
    resources: list[dict] = []
    if tarball is not None:
        resources, tar_findings = _tarball_resources(tarball)
        findings.extend(tar_findings)
    # --- PVCs without volume snapshots
    if metadata and (metadata.get("spec") or {}).get("snapshotVolumes", True):
        volume_backups = (metadata.get("status", {}) or {}).get("volumeBackups") or {}
        snapshotted = set(volume_backups)
        # The companion -volumesnapshots.json.gz lists snapshots too.
        for gz_path in path.glob("*-volumesnapshots.json.gz") if path.is_dir() else []:
            try:
                data = json.loads(gzip.open(gz_path, "rt").read())
                for item in data if isinstance(data, list) else []:
                    uid = (item.get("spec") or {}).get("persistentVolumeClaimName")
                    if uid:
                        snapshotted.add(uid)
            except Exception:  # noqa: BLE001 - a bad companion file is not fatal
                pass
        for r in resources:
            if r["kind"] == "persistentvolumeclaims" and r["uid"] not in snapshotted:
                findings.append(_finding("warning", "PVCs have volume snapshots",
                                         f"PVC/{r['namespace']}/{r['name']}: in the backup "
                                         f"without a volume snapshot — its data may not restore"))
    # --- namespaces the spec said to include but that hold nothing
    if metadata:
        included = (metadata.get("spec") or {}).get("includedNamespaces") or []
        if included and included != ["*"]:
            present_ns = {r["namespace"] for r in resources}
            for ns in included:
                if ns not in present_ns:
                    findings.append(_finding("warning", "included namespaces present",
                                             f"namespace '{ns}' is in includedNamespaces but "
                                             f"holds no resources in the backup"))
    errors = [f for f in findings if f["severity"] == "error"]
    by_kind: dict[str, int] = {}
    for r in resources:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    return {"kind": "velero", "path": str(path),
            "phase": phase, "format_version": format_version,
            "resources": len(resources), "by_kind": by_kind,
            "resource_list": resources,
            "findings": findings,
            "usable": not errors}


def cross_check(manifests_result: dict, velero_result: dict,
                manifest_resources: list[dict], velero_resources: list[dict]) -> list[dict]:
    """Every workload the manifests define must appear in the backup."""
    findings: list[dict] = []
    # Velero stores kinds pluralised and lower-cased (deployments, services).
    in_backup = {(r["kind"], r["namespace"], r["name"]) for r in velero_resources}
    for r in manifest_resources:
        if r["kind"] not in WORKLOAD_KINDS:
            continue
        # Velero stores kinds pluralised and lower-cased (deployments,
        # statefulsets, daemonsets, jobs, cronjobs, pods).
        plural = r["kind"].lower() + "s"
        if (plural, r["namespace"], r["name"]) not in in_backup:
            findings.append(_finding("error", "manifest workloads are backed up",
                                     f"{r['kind']}/{r['namespace']}/{r['name']}: in the "
                                     f"manifests but not in the Velero backup"))
    return findings


def run_k8s(manifests: Path | None, velero: Path | None) -> dict:
    """Run the K8s verification. Returns the combined result dict."""
    if manifests is None and velero is None:
        raise ValueError("give --manifests, --velero, or both")
    result: dict = {"manifests": None, "velero": None, "cross_check": []}
    if manifests is not None:
        result["manifests"] = verify_manifests(manifests)
    if velero is not None:
        result["velero"] = inspect_velero(velero)
    if manifests is not None and velero is not None:
        result["cross_check"] = cross_check(
            result["manifests"], result["velero"],
            result["manifests"]["resource_list"],
            result["velero"]["resource_list"])
    errors = 0
    if result["manifests"]:
        errors += sum(1 for f in result["manifests"]["findings"] if f["severity"] == "error")
    if result["velero"]:
        errors += sum(1 for f in result["velero"]["findings"] if f["severity"] == "error")
    errors += sum(1 for f in result["cross_check"] if f["severity"] == "error")
    result["ok"] = errors == 0
    return result


def render_text(result: dict) -> str:
    lines = ["Kubernetes restore verification", ""]
    if result["manifests"]:
        m = result["manifests"]
        lines.append(f"Manifests ({m['path']}): {m['resources']} resources — "
                     f"{'restorable' if m['restorable'] else 'NOT restorable'}")
        for f in m["findings"]:
            lines.append(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")
        if not m["findings"]:
            lines.append("  no findings")
    if result["velero"]:
        v = result["velero"]
        lines.append(f"Velero backup ({v['path']}): phase {v['phase']}, "
                     f"format {v['format_version']}, {v['resources']} resources — "
                     f"{'usable' if v['usable'] else 'NOT usable'}")
        for f in v["findings"]:
            lines.append(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")
        if not v["findings"]:
            lines.append("  no findings")
    if result["cross_check"]:
        lines.append("Cross-check (manifest workloads in the backup):")
        for f in result["cross_check"]:
            lines.append(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")
    elif result["manifests"] and result["velero"]:
        lines.append("Cross-check: every manifest workload is in the backup.")
    lines.append("")
    lines.append("Verdict: " + ("OK — the workload can be recreated from this "
                                "backup." if result["ok"] else
                                "NOT OK — see the errors above."))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- CLI
def parse_k8s_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Verify a Kubernetes workload can be restored: check a "
                    "manifest bundle, a Velero backup, or both.")
    ap.add_argument("--manifests", type=Path, help="directory of K8s YAML manifests")
    ap.add_argument("--velero", type=Path,
                    help="Velero backup directory (object-storage layout) or a .tar.gz")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--output", type=Path, help="write the report here as well as stdout")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def k8s_main(argv=None) -> int:
    args = parse_k8s_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    try:
        result = run_k8s(args.manifests, args.velero)
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
    sys.exit(k8s_main())
