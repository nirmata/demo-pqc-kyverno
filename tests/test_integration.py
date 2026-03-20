#!/usr/bin/env python3
"""
Integration tests - Tests the full pipeline from scanning to policy enforcement.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.cbom_scanner import CBOMScanner
from analyzer.pqc_analyzer import PQCAnalyzer


class TestFullPipelineVulnerableCode(unittest.TestCase):
    """End-to-end test: vulnerable source code -> scan -> analyze -> policy check."""

    VULNERABLE_CODE = {
        "payment.py": """
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib

key = RSA.generate(2048)
private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(data, ECDSA(hashes.SHA256()))
digest = hashlib.sha256(b"data").hexdigest()
""",
        "tls_config.conf": """
ssl_protocols TLSv1.2;
ssl_ciphers TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
""",
        "key_exchange.c": """
#include <openssl/dh.h>
DH *dh = DH_generate_parameters_ex(NULL, 2048, DH_GENERATOR_2, NULL);
ECDH_compute_key(secret, 32, pub, priv, NULL);
""",
    }

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        for filename, content in cls.VULNERABLE_CODE.items():
            filepath = Path(cls.tmpdir) / filename
            filepath.write_text(content)

        scanner = CBOMScanner(cls.tmpdir, "legacy-service", "2.0.0")
        cls.cbom = scanner.scan()

        analyzer = PQCAnalyzer(cls.cbom)
        cls.report = analyzer.analyze()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_scanner_finds_rsa(self):
        variants = self._get_algorithm_variants()
        self.assertIn("RSA", variants)

    def test_scanner_finds_ecdsa(self):
        variants = self._get_algorithm_variants()
        self.assertIn("ECDSA", variants)

    def test_scanner_finds_dh(self):
        variants = self._get_algorithm_variants()
        self.assertIn("DH", variants)

    def test_scanner_finds_ecdh(self):
        variants = self._get_algorithm_variants()
        self.assertIn("ECDH", variants)

    def test_analyzer_blocks_deployment(self):
        self.assertFalse(self.report["pqcCompliance"]["deploymentAllowed"])

    def test_analyzer_marks_noncompliant(self):
        self.assertFalse(self.report["pqcCompliance"]["isCompliant"])

    def test_analyzer_has_critical_findings(self):
        self.assertGreater(self.report["severityCounts"]["critical"], 0)

    def test_k8s_annotations_block(self):
        annotations = self.report["kubernetesAnnotations"]
        self.assertEqual(annotations["pqc.security.io/deployment-allowed"], "false")

    def test_migration_recommendations(self):
        critical = [
            f for f in self.report["findings"]
            if f.get("severity") == "critical"
            and f.get("category") == "quantum-vulnerable-algorithm"
        ]
        self.assertGreater(len(critical), 0)
        for f in critical:
            self.assertIn("migrationTarget", f)

    def _get_algorithm_variants(self) -> set:
        variants = set()
        for c in self.cbom["components"]:
            algo = c.get("cryptoProperties", {}).get("algorithmProperties", {})
            if algo.get("variant"):
                variants.add(algo["variant"])
        return variants


class TestFullPipelineCompliantCode(unittest.TestCase):
    """End-to-end test: PQC-compliant source code -> scan -> analyze -> allow."""

    PQC_CODE = {
        "pqc_crypto.py": """
import oqs
kem = oqs.KeyEncapsulation("Kyber768")
sig = oqs.Signature("Dilithium3")
ciphertext, shared_secret = kem.encap_secret(public_key)
signature = sig.sign(message)
""",
        "secure_config.conf": """
ssl_protocols TLSv1.3;
""",
        "symmetric.py": """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.AES256(key), modes.GCM(nonce))
import hashlib
h = hashlib.sha384(data)
""",
    }

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        for filename, content in cls.PQC_CODE.items():
            filepath = Path(cls.tmpdir) / filename
            filepath.write_text(content)

        scanner = CBOMScanner(cls.tmpdir, "pqc-service", "1.0.0")
        cls.cbom = scanner.scan()

        analyzer = PQCAnalyzer(cls.cbom)
        cls.report = analyzer.analyze()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_scanner_finds_pqc_algorithms(self):
        variants = set()
        for c in self.cbom["components"]:
            algo = c.get("cryptoProperties", {}).get("algorithmProperties", {})
            if algo.get("variant"):
                variants.add(algo["variant"])
        self.assertTrue(
            variants.intersection({"ML-KEM", "ML-DSA"}),
            f"Expected PQC algorithms, found: {variants}",
        )

    def test_analyzer_allows_deployment(self):
        self.assertTrue(self.report["pqcCompliance"]["deploymentAllowed"])

    def test_zero_critical_findings(self):
        self.assertEqual(self.report["severityCounts"]["critical"], 0)

    def test_k8s_annotations_allow(self):
        annotations = self.report["kubernetesAnnotations"]
        self.assertEqual(annotations["pqc.security.io/deployment-allowed"], "true")


class TestCBOMToReportToAnnotations(unittest.TestCase):
    """Test the CBOM sample -> report -> K8s annotation flow."""

    def test_vulnerable_sample_generates_blocking_report(self):
        cbom_path = Path(__file__).parent.parent / "cbom" / "samples" / "vulnerable-app-cbom.json"
        with open(cbom_path) as f:
            cbom = json.load(f)

        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()

        self.assertFalse(report["pqcCompliance"]["deploymentAllowed"])
        annotations = report["kubernetesAnnotations"]
        self.assertEqual(annotations["pqc.security.io/deployment-allowed"], "false")

    def test_compliant_sample_generates_allowing_report(self):
        cbom_path = Path(__file__).parent.parent / "cbom" / "samples" / "compliant-app-cbom.json"
        with open(cbom_path) as f:
            cbom = json.load(f)

        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()

        self.assertTrue(report["pqcCompliance"]["deploymentAllowed"])
        annotations = report["kubernetesAnnotations"]
        self.assertEqual(annotations["pqc.security.io/deployment-allowed"], "true")

    def test_hybrid_sample_generates_allowing_report(self):
        cbom_path = Path(__file__).parent.parent / "cbom" / "samples" / "hybrid-app-cbom.json"
        with open(cbom_path) as f:
            cbom = json.load(f)

        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()

        self.assertTrue(report["pqcCompliance"]["deploymentAllowed"])


if __name__ == "__main__":
    unittest.main()
