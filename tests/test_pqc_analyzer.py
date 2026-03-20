#!/usr/bin/env python3
"""Tests for the PQC Vulnerability Analyzer module."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from analyzer.pqc_analyzer import PQCAnalyzer


def load_sample_cbom(name: str) -> dict:
    cbom_path = Path(__file__).parent.parent / "cbom" / "samples" / f"{name}.json"
    with open(cbom_path) as f:
        return json.load(f)


class TestVulnerableAppAnalysis(unittest.TestCase):
    """Test analysis of a fully quantum-vulnerable application."""

    @classmethod
    def setUpClass(cls):
        cls.cbom = load_sample_cbom("vulnerable-app-cbom")
        cls.analyzer = PQCAnalyzer(cls.cbom)
        cls.report = cls.analyzer.analyze()

    def test_not_compliant(self):
        self.assertFalse(self.report["pqcCompliance"]["isCompliant"])

    def test_deployment_blocked(self):
        self.assertFalse(self.report["pqcCompliance"]["deploymentAllowed"])

    def test_compliance_level_vulnerable(self):
        self.assertEqual(
            self.report["pqcCompliance"]["complianceLevel"],
            "quantum-vulnerable",
        )

    def test_has_critical_findings(self):
        self.assertGreater(self.report["severityCounts"]["critical"], 0)

    def test_detects_rsa_vulnerability(self):
        rsa_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "RSA"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        self.assertGreater(len(rsa_findings), 0, "Should detect RSA as quantum-vulnerable")

    def test_detects_ecdsa_vulnerability(self):
        ecdsa_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "ECDSA"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        self.assertGreater(len(ecdsa_findings), 0)

    def test_detects_ecdh_vulnerability(self):
        ecdh_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "ECDH"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        self.assertGreater(len(ecdh_findings), 0)

    def test_detects_dh_vulnerability(self):
        dh_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "DH"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        self.assertGreater(len(dh_findings), 0)

    def test_migration_recommendations_present(self):
        critical_findings = [
            f for f in self.report["findings"]
            if f.get("severity") == "critical"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        for finding in critical_findings:
            self.assertIn("migrationTarget", finding)
            target = finding["migrationTarget"]
            self.assertIn("algorithm", target)
            self.assertIn("fips", target)

    def test_rsa_migration_to_ml_kem(self):
        rsa_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "RSA"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        for f in rsa_findings:
            self.assertIn("ML-KEM", f["migrationTarget"]["algorithm"])

    def test_ecdsa_migration_to_ml_dsa(self):
        ecdsa_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "ECDSA"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        for f in ecdsa_findings:
            self.assertIn("ML-DSA", f["migrationTarget"]["algorithm"])

    def test_aes256_marked_pqc_ready(self):
        aes_findings = [
            f for f in self.report["findings"]
            if f.get("category") == "pqc-compliant"
            and "AES" in f.get("component", "")
        ]
        # AES-256 should not trigger a vulnerability
        critical_aes = [
            f for f in self.report["findings"]
            if f.get("severity") == "critical"
            and "AES" in f.get("component", "")
        ]
        self.assertEqual(len(critical_aes), 0)

    def test_non_pqc_cipher_suites_detected(self):
        suite_findings = [
            f for f in self.report["findings"]
            if f.get("category") == "non-pqc-cipher-suite"
        ]
        self.assertGreater(len(suite_findings), 0)

    def test_missing_pqc_kem_gap(self):
        gap_findings = [
            f for f in self.report["findings"]
            if f.get("category") == "missing-pqc-kem"
        ]
        self.assertGreater(len(gap_findings), 0)

    def test_missing_pqc_signature_gap(self):
        gap_findings = [
            f for f in self.report["findings"]
            if f.get("category") == "missing-pqc-signature"
        ]
        self.assertGreater(len(gap_findings), 0)

    def test_k8s_annotations_generated(self):
        annotations = self.report.get("kubernetesAnnotations", {})
        self.assertEqual(annotations["pqc.security.io/compliance"], "false")
        self.assertEqual(annotations["pqc.security.io/deployment-allowed"], "false")
        self.assertIn("pqc.security.io/critical-findings", annotations)
        self.assertIn("pqc.security.io/scan-timestamp", annotations)

    def test_cwe_id_present(self):
        vuln_findings = [
            f for f in self.report["findings"]
            if f.get("category") == "quantum-vulnerable-algorithm"
        ]
        for f in vuln_findings:
            self.assertEqual(f.get("cweId"), "CWE-327")

    def test_evidence_preserved(self):
        vuln_findings = [
            f for f in self.report["findings"]
            if f.get("evidence")
        ]
        for f in vuln_findings:
            evidence = f["evidence"]
            self.assertIn("source", evidence)
            self.assertIn("filePath", evidence)


class TestCompliantAppAnalysis(unittest.TestCase):
    """Test analysis of a fully PQC-compliant application."""

    @classmethod
    def setUpClass(cls):
        cls.cbom = load_sample_cbom("compliant-app-cbom")
        cls.analyzer = PQCAnalyzer(cls.cbom)
        cls.report = cls.analyzer.analyze()

    def test_is_compliant(self):
        self.assertTrue(self.report["pqcCompliance"]["isCompliant"])

    def test_deployment_allowed(self):
        self.assertTrue(self.report["pqcCompliance"]["deploymentAllowed"])

    def test_compliance_level_ready(self):
        self.assertEqual(
            self.report["pqcCompliance"]["complianceLevel"],
            "fully-pqc-ready",
        )

    def test_zero_critical_findings(self):
        self.assertEqual(self.report["severityCounts"]["critical"], 0)

    def test_zero_high_findings(self):
        self.assertEqual(self.report["severityCounts"]["high"], 0)

    def test_ml_kem_recognized(self):
        kem_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "ML-KEM"
        ]
        self.assertGreater(len(kem_findings), 0)
        for f in kem_findings:
            self.assertEqual(f["severity"], "info")
            self.assertFalse(f["complianceViolation"])

    def test_ml_dsa_recognized(self):
        dsa_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "ML-DSA"
        ]
        self.assertGreater(len(dsa_findings), 0)

    def test_slh_dsa_recognized(self):
        slh_findings = [
            f for f in self.report["findings"]
            if f.get("variant") == "SLH-DSA"
        ]
        self.assertGreater(len(slh_findings), 0)

    def test_pqc_ready_count(self):
        self.assertGreater(self.report["summary"]["pqc_ready"], 0)
        self.assertEqual(self.report["summary"]["quantum_vulnerable"], 0)

    def test_k8s_annotations_compliant(self):
        annotations = self.report["kubernetesAnnotations"]
        self.assertEqual(annotations["pqc.security.io/compliance"], "true")
        self.assertEqual(annotations["pqc.security.io/deployment-allowed"], "true")
        self.assertEqual(annotations["pqc.security.io/critical-findings"], "0")


class TestHybridAppAnalysis(unittest.TestCase):
    """Test analysis of a hybrid classical+PQC application."""

    @classmethod
    def setUpClass(cls):
        cls.cbom = load_sample_cbom("hybrid-app-cbom")
        cls.analyzer = PQCAnalyzer(cls.cbom)
        cls.report = cls.analyzer.analyze()

    def test_is_compliant(self):
        self.assertTrue(self.report["pqcCompliance"]["isCompliant"])

    def test_deployment_allowed(self):
        self.assertTrue(self.report["pqcCompliance"]["deploymentAllowed"])

    def test_hybrid_kem_detected(self):
        kem_findings = [
            f for f in self.report["findings"]
            if "X25519-ML-KEM" in f.get("variant", "")
        ]
        self.assertGreater(len(kem_findings), 0)

    def test_zero_critical(self):
        self.assertEqual(self.report["severityCounts"]["critical"], 0)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_empty_cbom(self):
        cbom = {
            "bomFormat": "CycloneDX-Crypto",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
                "component": {"name": "empty", "version": "0.0.0", "type": "application"},
            },
            "components": [],
        }
        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()
        self.assertTrue(report["pqcCompliance"]["isCompliant"])
        self.assertTrue(report["pqcCompliance"]["deploymentAllowed"])
        self.assertEqual(len(report["findings"]), 0)

    def test_only_symmetric_crypto(self):
        cbom = {
            "bomFormat": "CycloneDX-Crypto",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
                "component": {"name": "sym-only", "version": "1.0.0", "type": "application"},
            },
            "components": [
                {
                    "type": "crypto-asset",
                    "name": "AES-256-GCM",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "symmetric-encryption",
                            "variant": "AES",
                            "keySize": 256,
                            "pqcReady": True,
                            "nistQuantumSecurityLevel": 1,
                            "quantumSecurityBits": 128,
                        },
                    },
                }
            ],
        }
        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()
        self.assertTrue(report["pqcCompliance"]["isCompliant"])

    def test_aes_128_flagged(self):
        cbom = {
            "bomFormat": "CycloneDX-Crypto",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
                "component": {"name": "aes128", "version": "1.0.0", "type": "application"},
            },
            "components": [
                {
                    "type": "crypto-asset",
                    "name": "AES-128",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "symmetric-encryption",
                            "variant": "AES",
                            "keySize": 128,
                            "pqcReady": False,
                            "nistQuantumSecurityLevel": 0,
                            "quantumSecurityBits": 64,
                        },
                    },
                }
            ],
        }
        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()
        medium_findings = [f for f in report["findings"] if f["severity"] == "medium"]
        self.assertGreater(len(medium_findings), 0)

    def test_deprecated_tls_10(self):
        cbom = {
            "bomFormat": "CycloneDX-Crypto",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
                "component": {"name": "old-tls", "version": "1.0.0", "type": "application"},
            },
            "components": [
                {
                    "type": "crypto-asset",
                    "name": "TLS-1.0",
                    "cryptoProperties": {
                        "assetType": "protocol",
                        "protocolProperties": {
                            "type": "tls",
                            "version": "1.0",
                            "cipherSuites": [],
                        },
                    },
                }
            ],
        }
        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()
        self.assertFalse(report["pqcCompliance"]["deploymentAllowed"])

    def test_md5_hash_flagged(self):
        cbom = {
            "bomFormat": "CycloneDX-Crypto",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
                "component": {"name": "md5-app", "version": "1.0.0", "type": "application"},
            },
            "components": [
                {
                    "type": "crypto-asset",
                    "name": "MD5",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "hash",
                            "variant": "MD5",
                            "pqcReady": False,
                            "nistQuantumSecurityLevel": 0,
                            "quantumSecurityBits": 0,
                        },
                    },
                }
            ],
        }
        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()
        hash_findings = [
            f for f in report["findings"]
            if f.get("category") == "weak-hash-algorithm"
        ]
        self.assertGreater(len(hash_findings), 0)

    def test_report_structure(self):
        cbom = load_sample_cbom("vulnerable-app-cbom")
        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()

        required_keys = [
            "reportVersion", "timestamp", "component",
            "pqcCompliance", "summary", "severityCounts",
            "findings", "kubernetesAnnotations",
        ]
        for key in required_keys:
            self.assertIn(key, report, f"Missing required key: {key}")

        compliance_keys = ["isCompliant", "deploymentAllowed", "complianceLevel"]
        for key in compliance_keys:
            self.assertIn(key, report["pqcCompliance"])

        severity_keys = ["critical", "high", "medium", "low", "info"]
        for key in severity_keys:
            self.assertIn(key, report["severityCounts"])


if __name__ == "__main__":
    unittest.main()
