#!/usr/bin/env python3
"""Tests for the CBOM attestation module."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.pqc_analyzer import PQCAnalyzer
from attestation.cbom_attestation import (
    build_attestation,
    build_predicate,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
)


SAMPLES_DIR = Path(__file__).parent.parent / "cbom" / "samples"


def load_cbom(name: str) -> dict:
    with open(SAMPLES_DIR / f"{name}.json") as f:
        return json.load(f)


def analyze(cbom: dict) -> dict:
    return PQCAnalyzer(cbom).analyze()


class TestAttestationStructure(unittest.TestCase):
    """Verify in-toto statement structure."""

    @classmethod
    def setUpClass(cls):
        cls.cbom = load_cbom("vulnerable-app-cbom")
        cls.report = analyze(cls.cbom)
        cls.attestation = build_attestation(
            "registry.io/legacy-payment:2.3.1",
            "abc123def456",
            cls.cbom,
            cls.report,
        )

    def test_statement_type(self):
        self.assertEqual(self.attestation["_type"], STATEMENT_TYPE)

    def test_predicate_type(self):
        self.assertEqual(self.attestation["predicateType"], PREDICATE_TYPE)

    def test_subject_present(self):
        subjects = self.attestation["subject"]
        self.assertEqual(len(subjects), 1)
        self.assertEqual(subjects[0]["name"], "registry.io/legacy-payment:2.3.1")
        self.assertIn("sha256", subjects[0]["digest"])

    def test_predicate_has_cbom(self):
        pred = self.attestation["predicate"]
        self.assertIn("cbom", pred)
        self.assertEqual(pred["cbom"]["bomFormat"], "CycloneDX-Crypto")

    def test_predicate_has_compliance(self):
        pred = self.attestation["predicate"]
        self.assertIn("pqcCompliance", pred)
        self.assertIn("isCompliant", pred["pqcCompliance"])
        self.assertIn("deploymentAllowed", pred["pqcCompliance"])

    def test_predicate_has_crypto_inventory(self):
        pred = self.attestation["predicate"]
        inv = pred["cryptoInventory"]
        required_keys = [
            "algorithmsDetected", "vulnerableAlgorithms", "pqcAlgorithms",
            "hashAlgorithms", "minSymmetricKeyBits", "minTlsVersion",
            "opensslVersion", "hybridMode",
        ]
        for key in required_keys:
            self.assertIn(key, inv, f"Missing cryptoInventory key: {key}")

    def test_predicate_has_findings(self):
        pred = self.attestation["predicate"]
        self.assertIn("findings", pred)
        self.assertIn("severityCounts", pred)


class TestVulnerableImagePredicate(unittest.TestCase):
    """Verify predicate content for a vulnerable image."""

    @classmethod
    def setUpClass(cls):
        cbom = load_cbom("vulnerable-app-cbom")
        report = analyze(cbom)
        cls.predicate = build_predicate(cbom, report)

    def test_not_compliant(self):
        self.assertFalse(self.predicate["pqcCompliance"]["isCompliant"])

    def test_deployment_not_allowed(self):
        self.assertFalse(self.predicate["pqcCompliance"]["deploymentAllowed"])

    def test_vulnerable_algorithms_listed(self):
        vuln = self.predicate["cryptoInventory"]["vulnerableAlgorithms"]
        self.assertGreater(len(vuln), 0)
        algo_names = " ".join(vuln)
        self.assertTrue("RSA" in algo_names, f"Expected RSA in {vuln}")

    def test_algorithms_detected(self):
        algos = self.predicate["cryptoInventory"]["algorithmsDetected"]
        self.assertGreater(len(algos), 0)

    def test_openssl_version_detected(self):
        self.assertEqual(self.predicate["cryptoInventory"]["opensslVersion"], "1.1.1w")

    def test_min_tls_version(self):
        self.assertEqual(self.predicate["cryptoInventory"]["minTlsVersion"], "1.2")

    def test_no_hybrid_mode(self):
        self.assertFalse(self.predicate["cryptoInventory"]["hybridMode"])

    def test_critical_findings_count(self):
        self.assertGreater(self.predicate["severityCounts"]["critical"], 0)


class TestCompliantImagePredicate(unittest.TestCase):
    """Verify predicate content for a PQC-compliant image."""

    @classmethod
    def setUpClass(cls):
        cbom = load_cbom("compliant-app-cbom")
        report = analyze(cbom)
        cls.predicate = build_predicate(cbom, report)

    def test_is_compliant(self):
        self.assertTrue(self.predicate["pqcCompliance"]["isCompliant"])

    def test_deployment_allowed(self):
        self.assertTrue(self.predicate["pqcCompliance"]["deploymentAllowed"])

    def test_zero_vulnerable(self):
        vuln = self.predicate["cryptoInventory"]["vulnerableAlgorithms"]
        self.assertEqual(len(vuln), 0)

    def test_pqc_algorithms_present(self):
        pqc = self.predicate["cryptoInventory"]["pqcAlgorithms"]
        self.assertGreater(len(pqc), 0)

    def test_zero_critical(self):
        self.assertEqual(self.predicate["severityCounts"]["critical"], 0)

    def test_min_tls_version_13(self):
        self.assertEqual(self.predicate["cryptoInventory"]["minTlsVersion"], "1.3")


class TestHybridImagePredicate(unittest.TestCase):
    """Verify predicate content for a hybrid PQC image."""

    @classmethod
    def setUpClass(cls):
        cbom = load_cbom("hybrid-app-cbom")
        report = analyze(cbom)
        cls.predicate = build_predicate(cbom, report)

    def test_deployment_allowed(self):
        self.assertTrue(self.predicate["pqcCompliance"]["deploymentAllowed"])

    def test_hybrid_mode_true(self):
        self.assertTrue(self.predicate["cryptoInventory"]["hybridMode"])

    def test_zero_vulnerable(self):
        vuln = self.predicate["cryptoInventory"]["vulnerableAlgorithms"]
        self.assertEqual(len(vuln), 0)


class TestPredicateSerializability(unittest.TestCase):
    """Verify the attestation can be serialized to JSON (for cosign)."""

    def test_full_attestation_serializable(self):
        cbom = load_cbom("vulnerable-app-cbom")
        report = analyze(cbom)
        attestation = build_attestation("img:v1", "abc123", cbom, report)
        serialized = json.dumps(attestation)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["_type"], STATEMENT_TYPE)

    def test_predicate_round_trips(self):
        cbom = load_cbom("compliant-app-cbom")
        report = analyze(cbom)
        predicate = build_predicate(cbom, report)
        rt = json.loads(json.dumps(predicate))
        self.assertEqual(rt["pqcCompliance"]["isCompliant"], True)


if __name__ == "__main__":
    unittest.main()
