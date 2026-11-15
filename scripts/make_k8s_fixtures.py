"""Generate the K8s fixtures deterministically.

Run from the repo root:  python scripts/make_k8s_fixtures.py
The fixtures are committed: tests run the verifier over them. The Velero
backup is synthetic but follows the documented format (velero.io
output-file-format, format 1.1): <name>/velero-backup.json next to
<name>.tar.gz, with resources/<kind>/... inside the tarball.
"""
from __future__ import annotations

import gzip
import io
import json
import shutil
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "k8s"

APP_NS = "shop"
PVC_UID = "pvc-11111111-2222-3333-4444-555555555555"


def _manifests() -> dict[str, str]:
    return {
        "namespace.yaml": """apiVersion: v1
kind: Namespace
metadata:
  name: shop
""",
        "configmap.yaml": """apiVersion: v1
kind: ConfigMap
metadata:
  name: shop-config
  namespace: shop
data:
  LOG_LEVEL: info
""",
        "secret.yaml": """apiVersion: v1
kind: Secret
metadata:
  name: shop-secret
  namespace: shop
type: Opaque
stringData:
  DB_PASSWORD: hunter2
""",
        "pvc.yaml": """apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: shop-data
  namespace: shop
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: standard
  resources:
    requests:
      storage: 10Gi
""",
        "deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop-api
  namespace: shop
spec:
  replicas: 2
  selector:
    matchLabels:
      app: shop-api
  template:
    metadata:
      labels:
        app: shop-api
    spec:
      containers:
        - name: api
          image: registry.example.com/shop-api:1.4.2
          env:
            - name: LOG_LEVEL
              valueFrom:
                configMapKeyRef:
                  name: shop-config
                  key: LOG_LEVEL
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: shop-secret
                  key: DB_PASSWORD
          envFrom:
            - configMapRef:
                name: shop-config
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: shop-data
""",
        "service.yaml": """apiVersion: v1
kind: Service
metadata:
  name: shop-api
  namespace: shop
spec:
  selector:
    app: shop-api
  ports:
    - port: 80
      targetPort: 8000
""",
    }


def _resource(kind: str, api_version: str, name: str, namespace: str | None,
              extra: dict | None = None) -> dict:
    doc = {"kind": kind, "apiVersion": api_version,
           "metadata": {"name": name, "uid": f"uid-{kind.lower()}-{name}"}}
    if namespace:
        doc["metadata"]["namespace"] = namespace
    if extra:
        doc.update(extra)
    return doc


def _velero_tarball() -> bytes:
    """A synthetic Velero backup tarball (format 1.1 layout)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(path: str, doc: dict):
            data = json.dumps(doc).encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        add("resources/namespaces/cluster/shop.json",
            _resource("Namespace", "v1", "shop", None))
        add("resources/configmaps/namespaces/shop/shop-config.json",
            _resource("ConfigMap", "v1", "shop-config", APP_NS))
        add("resources/secrets/namespaces/shop/shop-secret.json",
            _resource("Secret", "v1", "shop-secret", APP_NS))
        # The PVC's uid matches the volumeBackups key in velero-backup.json.
        pvc = _resource("PersistentVolumeClaim", "v1", "shop-data", APP_NS,
                        {"spec": {"accessModes": ["ReadWriteOnce"],
                                  "storageClassName": "standard",
                                  "resources": {"requests": {"storage": "10Gi"}}}})
        pvc["metadata"]["uid"] = PVC_UID
        add("resources/persistentvolumeclaims/namespaces/shop/shop-data.json", pvc)
        add("resources/deployments/namespaces/shop/shop-api.json",
            _resource("Deployment", "apps/v1", "shop-api", APP_NS))
        add("resources/services/namespaces/shop/shop-api.json",
            _resource("Service", "v1", "shop-api", APP_NS))
    return buf.getvalue()


def _velero_metadata(phase: str, validation_errors: list | None = None) -> dict:
    return {
        "kind": "Backup", "apiVersion": "velero.io/v1",
        "metadata": {"name": "nightly", "namespace": "velero",
                     "uid": "a12345cb-75f5-11e7-b4c2-abcdef123456",
                     "creationTimestamp": "2026-11-15T00:00:00Z"},
        "spec": {"includedNamespaces": ["shop"], "excludedNamespaces": None,
                 "includedResources": ["*"], "excludedResources": None,
                 "labelSelector": None, "snapshotVolumes": True, "ttl": "24h0m0s"},
        "status": {"version": 1, "formatVersion": "1.1.0",
                   "expiration": "2026-11-16T00:00:00Z", "phase": phase,
                   "volumeBackups": {
                       PVC_UID: {"snapshotID": "snap-04b1a8e11dfb33ab0",
                                 "type": "gp2", "iops": 100}},
                   "validationErrors": validation_errors},
    }


def main() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    # --- good manifest bundle
    good = ROOT / "manifests"
    good.mkdir(parents=True)
    for name, text in _manifests().items():
        (good / name).write_text(text)
    # --- broken manifest bundle: a missing ConfigMap, an unpinned image,
    # and a Service whose selector matches nothing.
    broken = ROOT / "manifests-broken"
    broken.mkdir(parents=True)
    for name, text in _manifests().items():
        (broken / name).write_text(text)
    dep = (broken / "deployment.yaml").read_text()
    dep = dep.replace("registry.example.com/shop-api:1.4.2",
                      "registry.example.com/shop-api:latest")
    dep = dep.replace("shop-config", "shop-config-missing")
    (broken / "deployment.yaml").write_text(dep)
    svc = (broken / "service.yaml").read_text()
    svc = svc.replace("app: shop-api", "app: nothing-here")
    (broken / "service.yaml").write_text(svc)
    # --- good Velero backup (object-storage layout)
    velero = ROOT / "velero-backup"
    velero.mkdir(parents=True)
    (velero / "velero-backup.json").write_text(
        json.dumps(_velero_metadata("Completed"), indent=2))
    (velero / "nightly.tar.gz").write_bytes(_velero_tarball())
    # --- failed Velero backup: phase Failed + a validation error.
    failed = ROOT / "velero-backup-failed"
    failed.mkdir(parents=True)
    (failed / "velero-backup.json").write_text(
        json.dumps(_velero_metadata("Failed", ["backup item action failed"]), indent=2))
    (failed / "nightly.tar.gz").write_bytes(_velero_tarball())
    print(f"fixtures written to {ROOT}")


if __name__ == "__main__":
    main()
