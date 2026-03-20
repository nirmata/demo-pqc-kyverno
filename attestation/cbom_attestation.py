#!/usr/bin/env python3
"""
CBOM Attestation Generator

Wraps a CBOM and its PQC analysis report into an in-toto attestation
predicate suitable for attaching to OCI images via cosign.

The attestation follows the in-toto Statement v1 spec:
  https://in-toto.io/Statement/v1

Predicate type: https://pqc.security.io/cbom/v1

The predicate embeds the full CBOM and compliance summary so that
Kyverno verifyImages rules can inspect the cryptographic inventory
directly from the image attestation -- no deployment annotations needed.
"""

import json
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


PREDICATE_TYPE = "https://pqc.security.io/cbom/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

QUANTUM_VULNERABLE_VARIANTS = {
    "RSA", "ECDSA", "ECDH", "DH", "DSA", "ElGamal",
}
DEPRECATED_HASH_VARIANTS = {"MD5", "SHA-1", "MD4", "MD2"}
WEAK_TLS_VERSIONS = {"1.0", "1.1", "1.2"}
LEGACY_OPENSSL_VERSIONS = {
    "1.0.2", "1.1.0", "1.1.1",
    "3.0.0", "3.0.1", "3.0.2", "3.1.0", "3.1.1",
}


def build_predicate(cbom: dict, report: dict) -> dict:
    """Build the pqc-cbom/v1 predicate from CBOM + analysis report."""
    algorithms_detected = _extract_algorithms(cbom)
    protocols_detected = _extract_protocols(cbom)
    libraries_detected = _extract_libraries(cbom)

    vulnerable_algos = [a for a in algorithms_detected
                        if a["variant"] in QUANTUM_VULNERABLE_VARIANTS]
    pqc_algos = [a for a in algorithms_detected if a.get("pqcReady", False)]

    min_tls = _extract_min_tls(cbom)
    openssl_version = _extract_openssl_version(cbom)
    min_sym_bits = _extract_min_symmetric_bits(cbom)
    hash_algos = _extract_hash_algorithms(cbom)
    has_hybrid = _detect_hybrid_mode(cbom)

    compliance = report.get("pqcCompliance", {})

    return {
        "cbom": cbom,
        "pqcCompliance": {
            "isCompliant": compliance.get("isCompliant", False),
            "deploymentAllowed": compliance.get("deploymentAllowed", False),
            "complianceLevel": compliance.get("complianceLevel", "unknown"),
        },
        "cryptoInventory": {
            "algorithmsDetected": [a["name"] for a in algorithms_detected],
            "vulnerableAlgorithms": [a["name"] for a in vulnerable_algos],
            "pqcAlgorithms": [a["name"] for a in pqc_algos],
            "hashAlgorithms": hash_algos,
            "minSymmetricKeyBits": min_sym_bits,
            "minTlsVersion": min_tls,
            "opensslVersion": openssl_version,
            "hybridMode": has_hybrid,
        },
        "severityCounts": report.get("severityCounts", {}),
        "findings": report.get("findings", []),
        "scanTimestamp": datetime.now(timezone.utc).isoformat(),
        "scannerVersion": "1.0.0",
    }


def build_attestation(
    image_ref: str,
    image_digest: str,
    cbom: dict,
    report: dict,
) -> dict:
    """Build a complete in-toto Statement wrapping the CBOM predicate."""
    predicate = build_predicate(cbom, report)

    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": image_ref,
                "digest": {"sha256": image_digest},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def _extract_algorithms(cbom: dict) -> List[dict]:
    results = []
    for comp in cbom.get("components", []):
        crypto = comp.get("cryptoProperties", {})
        if crypto.get("assetType") == "algorithm":
            algo = crypto.get("algorithmProperties", {})
            results.append({
                "name": comp.get("name", ""),
                "variant": algo.get("variant", ""),
                "primitive": algo.get("primitive", ""),
                "keySize": algo.get("keySize"),
                "pqcReady": algo.get("pqcReady", False),
                "nistQuantumSecurityLevel": algo.get("nistQuantumSecurityLevel", 0),
            })
    return results


def _extract_protocols(cbom: dict) -> List[dict]:
    results = []
    for comp in cbom.get("components", []):
        crypto = comp.get("cryptoProperties", {})
        if crypto.get("assetType") == "protocol":
            proto = crypto.get("protocolProperties", {})
            results.append({
                "name": comp.get("name", ""),
                "type": proto.get("type", ""),
                "version": proto.get("version", ""),
            })
    return results


def _extract_libraries(cbom: dict) -> List[dict]:
    libs = {}
    for comp in cbom.get("components", []):
        for dep in comp.get("dependencies", []):
            lib_name = dep.get("library", "")
            if lib_name and lib_name not in libs:
                libs[lib_name] = {
                    "name": lib_name,
                    "version": dep.get("version", "unknown"),
                    "purl": dep.get("purl", ""),
                }
    return list(libs.values())


def _extract_min_tls(cbom: dict) -> Optional[str]:
    versions = []
    for comp in cbom.get("components", []):
        crypto = comp.get("cryptoProperties", {})
        proto = crypto.get("protocolProperties", {})
        if proto.get("type") == "tls" and proto.get("version"):
            versions.append(proto["version"])
    return min(versions) if versions else None


def _extract_openssl_version(cbom: dict) -> Optional[str]:
    for comp in cbom.get("components", []):
        for dep in comp.get("dependencies", []):
            if dep.get("library", "").lower() == "openssl":
                return dep.get("version")
    return None


def _extract_min_symmetric_bits(cbom: dict) -> Optional[int]:
    min_bits = None
    for comp in cbom.get("components", []):
        crypto = comp.get("cryptoProperties", {})
        algo = crypto.get("algorithmProperties", {})
        if algo.get("primitive") == "symmetric-encryption" and algo.get("keySize"):
            size = algo["keySize"]
            if min_bits is None or size < min_bits:
                min_bits = size
    return min_bits


def _extract_hash_algorithms(cbom: dict) -> List[str]:
    hashes = set()
    for comp in cbom.get("components", []):
        crypto = comp.get("cryptoProperties", {})
        algo = crypto.get("algorithmProperties", {})
        if algo.get("primitive") == "hash":
            hashes.add(algo.get("variant", comp.get("name", "")))
    return sorted(hashes)


def _detect_hybrid_mode(cbom: dict) -> bool:
    hybrid_indicators = {"X25519-ML-KEM", "P256-ML-KEM", "P384-ML-KEM", "ECDH-ML-KEM"}
    for comp in cbom.get("components", []):
        algo = comp.get("cryptoProperties", {}).get("algorithmProperties", {})
        variant = algo.get("variant", "")
        for indicator in hybrid_indicators:
            if indicator in variant:
                return True
    return False


def main():
    if len(sys.argv) < 4:
        print("Usage: cbom_attestation.py <cbom.json> <report.json> <image_ref> [image_digest]")
        print()
        print("Generates an in-toto attestation wrapping the CBOM for cosign.")
        print("  cbom.json:     Path to the CycloneDX-Crypto CBOM")
        print("  report.json:   Path to the PQC analysis report")
        print("  image_ref:     OCI image reference (e.g. registry.io/app:v1)")
        print("  image_digest:  SHA256 digest of the image (optional, computed if omitted)")
        sys.exit(1)

    cbom_path = sys.argv[1]
    report_path = sys.argv[2]
    image_ref = sys.argv[3]
    image_digest = sys.argv[4] if len(sys.argv) > 4 else hashlib.sha256(
        image_ref.encode()
    ).hexdigest()

    with open(cbom_path) as f:
        cbom = json.load(f)
    with open(report_path) as f:
        report = json.load(f)

    attestation = build_attestation(image_ref, image_digest, cbom, report)

    output_name = f"attestation-{Path(cbom_path).stem}.json"
    with open(output_name, "w") as f:
        json.dump(attestation, f, indent=2)

    print(f"Attestation generated: {output_name}")
    print(f"  Image:      {image_ref}")
    print(f"  Digest:     sha256:{image_digest[:16]}...")
    print(f"  Predicate:  {PREDICATE_TYPE}")
    print(f"  Compliant:  {attestation['predicate']['pqcCompliance']['isCompliant']}")
    print(f"  Vulnerable: {len(attestation['predicate']['cryptoInventory']['vulnerableAlgorithms'])} algorithms")


if __name__ == "__main__":
    main()
