#!/usr/bin/env python3
"""
Annotate Deployment - Takes a PQC analysis report and annotates a Kubernetes
deployment manifest with the compliance results.

Usage:
  python annotate_deployment.py <report.json> <deployment.yaml> [output.yaml]
"""

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def annotate_from_report(report: dict, deployment: dict) -> dict:
    """Apply PQC compliance annotations from analysis report to a K8s deployment."""
    annotations = report.get("kubernetesAnnotations", {})

    components = report.get("findings", [])
    algorithms = set()
    hash_algos = set()
    min_tls = "1.3"
    min_sym_bits = 256
    openssl_version = ""
    hybrid_mode = False

    for finding in components:
        variant = finding.get("variant", "")
        if variant:
            algorithms.add(variant)

        if finding.get("category") == "weak-hash-algorithm":
            hash_algos.add(variant)

        if finding.get("category") == "non-pqc-cipher-suite":
            for suite in finding.get("nonPqcSuites", []):
                algorithms.add(suite)

    for finding in report.get("findings", []):
        key_size = finding.get("keySize")
        if key_size and finding.get("severity") in ("medium", "high"):
            min_sym_bits = min(min_sym_bits, key_size)

    annotations["pqc.security.io/algorithms-detected"] = ",".join(sorted(algorithms))
    if hash_algos:
        annotations["pqc.security.io/hash-algorithms"] = ",".join(sorted(hash_algos))
    annotations["pqc.security.io/min-symmetric-key-bits"] = str(min_sym_bits)
    annotations["pqc.security.io/hybrid-mode"] = str(hybrid_mode).lower()

    if "metadata" not in deployment:
        deployment["metadata"] = {}
    if "annotations" not in deployment["metadata"]:
        deployment["metadata"]["annotations"] = {}

    deployment["metadata"]["annotations"].update(annotations)
    return deployment


def main():
    if len(sys.argv) < 3:
        print("Usage: annotate_deployment.py <report.json> <deployment.yaml> [output.yaml]")
        sys.exit(1)

    if yaml is None:
        print("ERROR: PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    report_path = sys.argv[1]
    deployment_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else deployment_path

    with open(report_path) as f:
        report = json.load(f)

    with open(deployment_path) as f:
        deployment = yaml.safe_load(f)

    annotated = annotate_from_report(report, deployment)

    with open(output_path, "w") as f:
        yaml.dump(annotated, f, default_flow_style=False, sort_keys=False)

    print(f"Annotated deployment written to: {output_path}")


if __name__ == "__main__":
    main()
