#!/usr/bin/env python3
"""
PQC Vulnerability Analyzer - Analyzes CBOM files to identify quantum-vulnerable
cryptographic assets and generates compliance reports.

Checks:
  1. Quantum-vulnerable asymmetric algorithms (RSA, ECDSA, ECDH, DH, DSA)
  2. Insufficient key sizes for symmetric algorithms (AES-128 under Grover's attack)
  3. Weak hash functions (MD5, SHA-1)
  4. Deprecated TLS versions (< 1.3)
  5. Non-PQC cipher suites
  6. Missing NIST PQC algorithm coverage

Output: JSON compliance report + Kubernetes-compatible annotation payload
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

QUANTUM_VULNERABLE_VARIANTS = {
    "RSA", "ECDSA", "ECDH", "DH", "DSA", "ElGamal",
}

NIST_PQC_ALGORITHMS = {
    "ML-KEM": {"type": "key-encapsulation", "fips": "FIPS 203"},
    "ML-DSA": {"type": "digital-signature", "fips": "FIPS 204"},
    "SLH-DSA": {"type": "digital-signature", "fips": "FIPS 205"},
    "FN-DSA": {"type": "digital-signature", "fips": "draft"},
}

HYBRID_PQC_VARIANTS = {
    "X25519-ML-KEM-768", "X25519-ML-KEM-1024",
    "P256-ML-KEM-768", "P384-ML-KEM-1024",
    "ECDH-ML-KEM", "RSA-ML-KEM",
}

DEPRECATED_HASH_VARIANTS = {"MD5", "SHA-1", "MD4", "MD2"}

MIN_SYMMETRIC_KEY_BITS_PQC = 256

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"


class PQCAnalyzer:
    def __init__(self, cbom: dict):
        self.cbom = cbom
        self.findings: List[dict] = []
        self.summary: Dict[str, Any] = {
            "total_components": 0,
            "pqc_ready": 0,
            "quantum_vulnerable": 0,
            "needs_migration": 0,
        }

    def analyze(self) -> dict:
        components = self.cbom.get("components", [])
        self.summary["total_components"] = len(components)

        for component in components:
            crypto_props = component.get("cryptoProperties", {})
            asset_type = crypto_props.get("assetType")

            if asset_type == "algorithm":
                self._analyze_algorithm(component)
            elif asset_type == "protocol":
                self._analyze_protocol(component)
            elif asset_type == "certificate":
                self._analyze_certificate(component)

        self._check_pqc_coverage()
        return self._build_report()

    def _analyze_algorithm(self, component: dict):
        algo_props = component["cryptoProperties"].get("algorithmProperties", {})
        variant = algo_props.get("variant", "")
        primitive = algo_props.get("primitive", "")
        key_size = algo_props.get("keySize")
        pqc_ready = algo_props.get("pqcReady", False)
        nist_level = algo_props.get("nistQuantumSecurityLevel", 0)
        evidence = component.get("evidence", {})

        if variant in QUANTUM_VULNERABLE_VARIANTS:
            self.summary["quantum_vulnerable"] += 1
            self.summary["needs_migration"] += 1

            migration_target = self._suggest_migration(variant, primitive)

            self.findings.append({
                "id": f"PQC-VULN-{len(self.findings)+1:03d}",
                "severity": SEVERITY_CRITICAL,
                "category": "quantum-vulnerable-algorithm",
                "component": component.get("name"),
                "bomRef": component.get("bom-ref"),
                "description": (
                    f"{variant} is vulnerable to quantum attack via Shor's algorithm. "
                    f"Key size {key_size} provides 0 bits of quantum security."
                ),
                "primitive": primitive,
                "variant": variant,
                "keySize": key_size,
                "evidence": evidence,
                "recommendation": f"Migrate to {migration_target['algorithm']} ({migration_target['fips']})",
                "migrationTarget": migration_target,
                "cweId": "CWE-327",
                "complianceViolation": True,
            })
            return

        if variant in HYBRID_PQC_VARIANTS or variant in NIST_PQC_ALGORITHMS:
            self.summary["pqc_ready"] += 1
            self.findings.append({
                "id": f"PQC-INFO-{len(self.findings)+1:03d}",
                "severity": SEVERITY_INFO,
                "category": "pqc-compliant",
                "component": component.get("name"),
                "bomRef": component.get("bom-ref"),
                "description": f"{variant} is a NIST-approved post-quantum algorithm.",
                "variant": variant,
                "nistQuantumSecurityLevel": nist_level,
                "complianceViolation": False,
            })
            return

        if primitive == "symmetric-encryption":
            if key_size and key_size < MIN_SYMMETRIC_KEY_BITS_PQC:
                self.summary["needs_migration"] += 1
                self.findings.append({
                    "id": f"PQC-WARN-{len(self.findings)+1:03d}",
                    "severity": SEVERITY_MEDIUM,
                    "category": "insufficient-quantum-security",
                    "component": component.get("name"),
                    "bomRef": component.get("bom-ref"),
                    "description": (
                        f"{variant} with {key_size}-bit key provides only "
                        f"{key_size // 2} bits of security under Grover's algorithm. "
                        f"Minimum {MIN_SYMMETRIC_KEY_BITS_PQC} bits recommended."
                    ),
                    "variant": variant,
                    "keySize": key_size,
                    "evidence": evidence,
                    "recommendation": "Upgrade to AES-256 for quantum resilience",
                    "complianceViolation": True,
                })
            else:
                self.summary["pqc_ready"] += 1
            return

        if primitive == "hash":
            if variant in DEPRECATED_HASH_VARIANTS:
                self.findings.append({
                    "id": f"PQC-WARN-{len(self.findings)+1:03d}",
                    "severity": SEVERITY_HIGH if variant == "MD5" else SEVERITY_MEDIUM,
                    "category": "weak-hash-algorithm",
                    "component": component.get("name"),
                    "bomRef": component.get("bom-ref"),
                    "description": f"{variant} is cryptographically broken and must not be used.",
                    "variant": variant,
                    "evidence": evidence,
                    "recommendation": "Use SHA-256 or SHA-384 minimum",
                    "complianceViolation": True,
                })
                self.summary["needs_migration"] += 1
            else:
                self.summary["pqc_ready"] += 1
            return

        if pqc_ready:
            self.summary["pqc_ready"] += 1
        else:
            self.summary["needs_migration"] += 1

    def _analyze_protocol(self, component: dict):
        proto_props = component["cryptoProperties"].get("protocolProperties", {})
        proto_version = proto_props.get("version", "")
        evidence = component.get("evidence", {})

        if proto_version in ("1.0", "1.1"):
            self.findings.append({
                "id": f"PQC-VULN-{len(self.findings)+1:03d}",
                "severity": SEVERITY_CRITICAL,
                "category": "deprecated-protocol",
                "component": component.get("name"),
                "bomRef": component.get("bom-ref"),
                "description": f"TLS {proto_version} is deprecated and uses quantum-vulnerable key exchange.",
                "protocolVersion": proto_version,
                "evidence": evidence,
                "recommendation": "Upgrade to TLS 1.3 with PQC cipher suites",
                "complianceViolation": True,
            })
            self.summary["quantum_vulnerable"] += 1
            return

        cipher_suites = proto_props.get("cipherSuites", [])
        non_pqc_suites = [s for s in cipher_suites if not s.get("pqcReady", False)]

        if non_pqc_suites:
            self.findings.append({
                "id": f"PQC-WARN-{len(self.findings)+1:03d}",
                "severity": SEVERITY_HIGH,
                "category": "non-pqc-cipher-suite",
                "component": component.get("name"),
                "bomRef": component.get("bom-ref"),
                "description": (
                    f"TLS {proto_version} has {len(non_pqc_suites)} cipher suite(s) "
                    f"without post-quantum protection."
                ),
                "nonPqcSuites": [s["name"] for s in non_pqc_suites],
                "evidence": evidence,
                "recommendation": "Add PQC key exchange (ML-KEM) to cipher suites",
                "complianceViolation": True,
            })
            self.summary["needs_migration"] += 1
        else:
            self.summary["pqc_ready"] += 1

    def _analyze_certificate(self, component: dict):
        cert_props = component["cryptoProperties"].get("certificateProperties", {})
        sig_algo = cert_props.get("signatureAlgorithm", "")
        key_algo = cert_props.get("keyAlgorithm", "")

        for algo in [sig_algo, key_algo]:
            for vuln_variant in QUANTUM_VULNERABLE_VARIANTS:
                if vuln_variant.lower() in algo.lower():
                    self.findings.append({
                        "id": f"PQC-VULN-{len(self.findings)+1:03d}",
                        "severity": SEVERITY_CRITICAL,
                        "category": "quantum-vulnerable-certificate",
                        "component": component.get("name"),
                        "bomRef": component.get("bom-ref"),
                        "description": f"Certificate uses quantum-vulnerable algorithm: {algo}",
                        "signatureAlgorithm": sig_algo,
                        "keyAlgorithm": key_algo,
                        "recommendation": "Re-issue certificate with ML-DSA or SLH-DSA signatures",
                        "complianceViolation": True,
                    })
                    self.summary["quantum_vulnerable"] += 1
                    return

    def _check_pqc_coverage(self):
        components = self.cbom.get("components", [])
        found_kem = False
        found_sig = False

        for component in components:
            algo_props = component.get("cryptoProperties", {}).get("algorithmProperties", {})
            variant = algo_props.get("variant", "")
            if variant in NIST_PQC_ALGORITHMS or variant in HYBRID_PQC_VARIANTS:
                if algo_props.get("primitive") == "key-encapsulation":
                    found_kem = True
                elif algo_props.get("primitive") == "digital-signature":
                    found_sig = True

        has_asymmetric = any(
            c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("primitive")
            in ("asymmetric-encryption", "key-agreement", "key-encapsulation")
            for c in components
        )
        has_signatures = any(
            c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("primitive") == "digital-signature"
            for c in components
        )

        if has_asymmetric and not found_kem:
            self.findings.append({
                "id": f"PQC-GAP-{len(self.findings)+1:03d}",
                "severity": SEVERITY_HIGH,
                "category": "missing-pqc-kem",
                "description": "No NIST PQC key encapsulation mechanism (ML-KEM) found. Key exchange is quantum-vulnerable.",
                "recommendation": "Implement ML-KEM (FIPS 203) for key encapsulation",
                "complianceViolation": True,
            })

        if has_signatures and not found_sig:
            self.findings.append({
                "id": f"PQC-GAP-{len(self.findings)+1:03d}",
                "severity": SEVERITY_HIGH,
                "category": "missing-pqc-signature",
                "description": "No NIST PQC digital signature algorithm (ML-DSA/SLH-DSA) found.",
                "recommendation": "Implement ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures",
                "complianceViolation": True,
            })

    def _suggest_migration(self, variant: str, primitive: str) -> dict:
        migration_map = {
            "asymmetric-encryption": {
                "algorithm": "ML-KEM-768",
                "fips": "FIPS 203",
                "nistLevel": 3,
            },
            "key-agreement": {
                "algorithm": "ML-KEM-768",
                "fips": "FIPS 203",
                "nistLevel": 3,
            },
            "key-encapsulation": {
                "algorithm": "ML-KEM-768",
                "fips": "FIPS 203",
                "nistLevel": 3,
            },
            "digital-signature": {
                "algorithm": "ML-DSA-65",
                "fips": "FIPS 204",
                "nistLevel": 3,
            },
        }
        return migration_map.get(primitive, {
            "algorithm": "ML-KEM-768 / ML-DSA-65",
            "fips": "FIPS 203/204",
            "nistLevel": 3,
        })

    def _build_report(self) -> dict:
        compliance_violations = [f for f in self.findings if f.get("complianceViolation")]
        is_compliant = len(compliance_violations) == 0

        critical_count = sum(1 for f in self.findings if f.get("severity") == SEVERITY_CRITICAL)
        high_count = sum(1 for f in self.findings if f.get("severity") == SEVERITY_HIGH)

        deploy_allowed = critical_count == 0

        report = {
            "reportVersion": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": self.cbom.get("metadata", {}).get("component", {}),
            "pqcCompliance": {
                "isCompliant": is_compliant,
                "deploymentAllowed": deploy_allowed,
                "complianceLevel": self._compute_compliance_level(critical_count, high_count),
            },
            "summary": self.summary,
            "severityCounts": {
                "critical": critical_count,
                "high": high_count,
                "medium": sum(1 for f in self.findings if f.get("severity") == SEVERITY_MEDIUM),
                "low": sum(1 for f in self.findings if f.get("severity") == SEVERITY_LOW),
                "info": sum(1 for f in self.findings if f.get("severity") == SEVERITY_INFO),
            },
            "findings": self.findings,
            "kubernetesAnnotations": self._build_k8s_annotations(is_compliant, deploy_allowed, critical_count),
        }
        return report

    def _compute_compliance_level(self, critical: int, high: int) -> str:
        if critical == 0 and high == 0:
            return "fully-pqc-ready"
        if critical == 0:
            return "partially-pqc-ready"
        return "quantum-vulnerable"

    def _build_k8s_annotations(self, is_compliant: bool, deploy_allowed: bool, critical_count: int) -> dict:
        component = self.cbom.get("metadata", {}).get("component", {})
        return {
            "pqc.security.io/compliance": str(is_compliant).lower(),
            "pqc.security.io/deployment-allowed": str(deploy_allowed).lower(),
            "pqc.security.io/critical-findings": str(critical_count),
            "pqc.security.io/scan-timestamp": datetime.now(timezone.utc).isoformat(),
            "pqc.security.io/component-name": component.get("name", ""),
            "pqc.security.io/component-version": component.get("version", ""),
            "pqc.security.io/cbom-attached": "true",
        }


def analyze_cbom_file(cbom_path: str) -> dict:
    with open(cbom_path) as f:
        cbom = json.load(f)
    analyzer = PQCAnalyzer(cbom)
    return analyzer.analyze()


def main():
    if len(sys.argv) < 2:
        print("Usage: pqc_analyzer.py <cbom_file> [output_file]")
        sys.exit(1)

    cbom_path = sys.argv[1]
    report = analyze_cbom_file(cbom_path)

    output_path = sys.argv[2] if len(sys.argv) > 2 else f"pqc-report-{Path(cbom_path).stem}.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nPQC Compliance Report: {output_path}")
    print(f"  Component: {report['component'].get('name')}")
    print(f"  Compliant: {report['pqcCompliance']['isCompliant']}")
    print(f"  Deployment Allowed: {report['pqcCompliance']['deploymentAllowed']}")
    print(f"  Compliance Level: {report['pqcCompliance']['complianceLevel']}")
    print(f"  Critical: {report['severityCounts']['critical']}")
    print(f"  High: {report['severityCounts']['high']}")
    print(f"  Medium: {report['severityCounts']['medium']}")

    if not report["pqcCompliance"]["deploymentAllowed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
