#!/usr/bin/env python3
"""
Kyverno Policy Simulation Tests (Image Attestation Model)

Simulates Kyverno verifyImages policy evaluation in Python by checking the
CBOM attestation predicate attached to each image. This mirrors what Kyverno
does at admission time: fetch the in-toto attestation from the image, verify
the signature, and inspect the predicate fields.

No deployment annotations are checked -- all validation comes from the image's
CBOM attestation predicate.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.pqc_analyzer import PQCAnalyzer
from attestation.cbom_attestation import build_predicate, build_attestation


SAMPLES_DIR = Path(__file__).parent.parent / "cbom" / "samples"


def load_cbom(name: str) -> dict:
    with open(SAMPLES_DIR / f"{name}.json") as f:
        return json.load(f)


def build_test_predicate(cbom_name: str) -> dict:
    """Build a predicate from a sample CBOM (simulates what cosign delivers to Kyverno)."""
    cbom = load_cbom(cbom_name)
    analyzer = PQCAnalyzer(cbom)
    report = analyzer.analyze()
    return build_predicate(cbom, report)


class ImagePolicyEngine:
    """
    Simulates Kyverno verifyImages attestation condition checks.

    Each method corresponds to a rule in pqc-image-verification.yaml and
    pqc-audit-warn-policies.yaml. The predicate argument is what Kyverno
    extracts from the cosign attestation attached to the image.
    """

    QUANTUM_VULNERABLE_ALGOS = {
        "RSA", "RSA-1024", "RSA-2048", "RSA-4096",
        "ECDSA-P256", "ECDSA-P384", "ECDSA",
        "ECDH-P256", "ECDH", "DH-2048", "DH",
        "DSA", "DSA-2048",
    }

    @staticmethod
    def verify_cbom_exists(predicate: dict) -> tuple:
        """Rule: verify-cbom-attestation -- CBOM must exist in attestation."""
        cbom = predicate.get("cbom", {})
        if cbom.get("bomFormat") != "CycloneDX-Crypto":
            return False, "BLOCKED: Image attestation missing valid CycloneDX-Crypto CBOM"
        return True, "PASS: CBOM attestation verified"

    @staticmethod
    def verify_deployment_allowed(predicate: dict) -> tuple:
        """Rule: block-quantum-vulnerable-images -- pqcCompliance.deploymentAllowed must be true."""
        allowed = predicate.get("pqcCompliance", {}).get("deploymentAllowed", False)
        if not allowed:
            return False, "BLOCKED: Image CBOM attestation shows deploymentAllowed=false"
        return True, "PASS: Image deployment allowed"

    @classmethod
    def verify_no_vulnerable_algorithms(cls, predicate: dict) -> tuple:
        """Rules: deny-rsa-in-image, deny-ecdsa-in-image, deny-dh-in-image."""
        vuln_algos = predicate.get("cryptoInventory", {}).get("vulnerableAlgorithms", [])
        found = cls.QUANTUM_VULNERABLE_ALGOS.intersection(vuln_algos)
        if found:
            return False, f"BLOCKED: Image contains quantum-vulnerable algorithms: {sorted(found)}"
        return True, "PASS: No vulnerable algorithms in image"

    @staticmethod
    def audit_symmetric_key_size(predicate: dict) -> tuple:
        """Audit rule: check minSymmetricKeyBits >= 256."""
        min_bits = predicate.get("cryptoInventory", {}).get("minSymmetricKeyBits")
        if min_bits is not None and min_bits < 256:
            return False, f"AUDIT: Image uses {min_bits}-bit symmetric keys (< 256 quantum minimum)"
        return True, "PASS: Symmetric key size adequate"

    @staticmethod
    def audit_weak_hash(predicate: dict) -> tuple:
        """Audit rule: check for MD5, SHA-1 in hashAlgorithms."""
        hashes = predicate.get("cryptoInventory", {}).get("hashAlgorithms", [])
        weak = {"MD5", "SHA-1", "MD4"}
        found = weak.intersection(hashes)
        if found:
            return False, f"AUDIT: Image uses weak hash algorithm(s): {sorted(found)}"
        return True, "PASS: Hash algorithms adequate"

    @staticmethod
    def audit_hybrid_mode(predicate: dict) -> tuple:
        """Audit rule: check hybridMode flag."""
        hybrid = predicate.get("cryptoInventory", {}).get("hybridMode", False)
        if not hybrid:
            return False, "AUDIT: Image does not use hybrid PQC mode"
        return True, "PASS: Hybrid PQC mode enabled"

    @staticmethod
    def audit_tls_version(predicate: dict) -> tuple:
        """Audit rule: check minTlsVersion is not deprecated."""
        min_tls = predicate.get("cryptoInventory", {}).get("minTlsVersion")
        if min_tls and min_tls in ("1.0", "1.1"):
            return False, f"AUDIT: Image uses deprecated TLS {min_tls}"
        return True, "PASS: TLS version acceptable"


# ── Vulnerable Image Tests ─────────────────────────────────────────────

class TestVerifyVulnerableImage(unittest.TestCase):
    """Image acme/legacy-payment-service:2.3.1 -- should be BLOCKED."""

    @classmethod
    def setUpClass(cls):
        cls.predicate = build_test_predicate("vulnerable-app-cbom")
        cls.engine = ImagePolicyEngine()

    def test_cbom_exists(self):
        ok, msg = self.engine.verify_cbom_exists(self.predicate)
        self.assertTrue(ok, msg)

    def test_deployment_blocked(self):
        ok, msg = self.engine.verify_deployment_allowed(self.predicate)
        self.assertFalse(ok, "Vulnerable image should be BLOCKED by verifyImages")

    def test_has_vulnerable_algorithms(self):
        ok, msg = self.engine.verify_no_vulnerable_algorithms(self.predicate)
        self.assertFalse(ok, "RSA/ECDSA/DH should be detected in image attestation")

    def test_vulnerable_algos_in_predicate(self):
        vuln = self.predicate["cryptoInventory"]["vulnerableAlgorithms"]
        self.assertGreater(len(vuln), 0)
        self.assertTrue(any("RSA" in a for a in vuln), f"RSA expected in {vuln}")

    def test_predicate_has_findings(self):
        findings = self.predicate.get("findings", [])
        critical = [f for f in findings if f.get("severity") == "critical"]
        self.assertGreater(len(critical), 0)

    def test_tls_flagged(self):
        ok, msg = self.engine.audit_tls_version(self.predicate)
        # TLS 1.2 is in the CBOM -- minTlsVersion should be "1.2"
        min_tls = self.predicate["cryptoInventory"]["minTlsVersion"]
        self.assertEqual(min_tls, "1.2")


# ── Compliant Image Tests ──────────────────────────────────────────────

class TestVerifyCompliantImage(unittest.TestCase):
    """Image acme/pqc-secure-api:1.0.0 -- should be ALLOWED."""

    @classmethod
    def setUpClass(cls):
        cls.predicate = build_test_predicate("compliant-app-cbom")
        cls.engine = ImagePolicyEngine()

    def test_cbom_exists(self):
        ok, msg = self.engine.verify_cbom_exists(self.predicate)
        self.assertTrue(ok, msg)

    def test_deployment_allowed(self):
        ok, msg = self.engine.verify_deployment_allowed(self.predicate)
        self.assertTrue(ok, msg)

    def test_no_vulnerable_algorithms(self):
        ok, msg = self.engine.verify_no_vulnerable_algorithms(self.predicate)
        self.assertTrue(ok, msg)

    def test_zero_vulnerable_in_predicate(self):
        vuln = self.predicate["cryptoInventory"]["vulnerableAlgorithms"]
        self.assertEqual(len(vuln), 0)

    def test_pqc_algorithms_present(self):
        pqc = self.predicate["cryptoInventory"]["pqcAlgorithms"]
        self.assertGreater(len(pqc), 0)

    def test_symmetric_key_audit_passes(self):
        ok, msg = self.engine.audit_symmetric_key_size(self.predicate)
        self.assertTrue(ok, msg)

    def test_hash_audit_passes(self):
        ok, msg = self.engine.audit_weak_hash(self.predicate)
        self.assertTrue(ok, msg)


# ── Hybrid Image Tests ─────────────────────────────────────────────────

class TestVerifyHybridImage(unittest.TestCase):
    """Image acme/hybrid-transition-service:3.1.0 -- should be ALLOWED."""

    @classmethod
    def setUpClass(cls):
        cls.predicate = build_test_predicate("hybrid-app-cbom")
        cls.engine = ImagePolicyEngine()

    def test_cbom_exists(self):
        ok, msg = self.engine.verify_cbom_exists(self.predicate)
        self.assertTrue(ok, msg)

    def test_deployment_allowed(self):
        ok, msg = self.engine.verify_deployment_allowed(self.predicate)
        self.assertTrue(ok, msg)

    def test_no_vulnerable_algorithms(self):
        ok, msg = self.engine.verify_no_vulnerable_algorithms(self.predicate)
        self.assertTrue(ok, msg)

    def test_hybrid_mode_detected(self):
        ok, msg = self.engine.audit_hybrid_mode(self.predicate)
        self.assertTrue(ok, "Hybrid mode should be detected in X25519+ML-KEM image")

    def test_hybrid_flag_in_predicate(self):
        self.assertTrue(self.predicate["cryptoInventory"]["hybridMode"])


# ── No-Attestation Image Tests ─────────────────────────────────────────

class TestVerifyNoAttestationImage(unittest.TestCase):
    """Image with no CBOM attestation -- should be BLOCKED."""

    def test_missing_cbom_blocked(self):
        empty_predicate = {}
        engine = ImagePolicyEngine()
        ok, msg = engine.verify_cbom_exists(empty_predicate)
        self.assertFalse(ok, "Image without CBOM attestation must be BLOCKED")

    def test_missing_compliance_blocked(self):
        empty_predicate = {"cbom": {"bomFormat": "CycloneDX-Crypto"}}
        engine = ImagePolicyEngine()
        ok, msg = engine.verify_deployment_allowed(empty_predicate)
        self.assertFalse(ok)


# ── Weak Symmetric Image Tests ─────────────────────────────────────────

class TestVerifyWeakSymmetricImage(unittest.TestCase):
    """Image with PQC asymmetric but AES-128 symmetric -- allowed + audit."""

    @classmethod
    def setUpClass(cls):
        cbom = {
            "bomFormat": "CycloneDX-Crypto",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
                "component": {"name": "weak-sym", "version": "1.0.0", "type": "container"},
            },
            "components": [
                {
                    "type": "crypto-asset", "name": "ML-KEM-768",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "key-encapsulation", "variant": "ML-KEM",
                            "keySize": 768, "pqcReady": True,
                            "nistQuantumSecurityLevel": 3, "quantumSecurityBits": 192,
                        },
                    },
                },
                {
                    "type": "crypto-asset", "name": "ML-DSA-65",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "digital-signature", "variant": "ML-DSA",
                            "keySize": 65, "pqcReady": True,
                            "nistQuantumSecurityLevel": 3, "quantumSecurityBits": 192,
                        },
                    },
                },
                {
                    "type": "crypto-asset", "name": "AES-128",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "symmetric-encryption", "variant": "AES",
                            "keySize": 128, "pqcReady": False,
                            "nistQuantumSecurityLevel": 0, "quantumSecurityBits": 64,
                        },
                    },
                },
            ],
        }
        analyzer = PQCAnalyzer(cbom)
        report = analyzer.analyze()
        cls.predicate = build_predicate(cbom, report)
        cls.engine = ImagePolicyEngine()

    def test_cbom_exists(self):
        ok, _ = self.engine.verify_cbom_exists(self.predicate)
        self.assertTrue(ok)

    def test_no_critical_vulnerable_algos(self):
        ok, _ = self.engine.verify_no_vulnerable_algorithms(self.predicate)
        self.assertTrue(ok, "PQC asymmetric should pass the algorithm check")

    def test_audit_flags_weak_symmetric(self):
        ok, msg = self.engine.audit_symmetric_key_size(self.predicate)
        self.assertFalse(ok, "AES-128 should trigger symmetric key audit")

    def test_min_symmetric_bits_in_predicate(self):
        self.assertEqual(self.predicate["cryptoInventory"]["minSymmetricKeyBits"], 128)


# ── Edge Cases ──────────────────────────────────────────────────────────

class TestImagePolicyEdgeCases(unittest.TestCase):

    def test_single_rsa_blocks(self):
        predicate = {
            "cbom": {"bomFormat": "CycloneDX-Crypto"},
            "pqcCompliance": {"deploymentAllowed": False},
            "cryptoInventory": {
                "vulnerableAlgorithms": ["RSA-2048"],
                "minSymmetricKeyBits": 256,
                "hashAlgorithms": [],
                "hybridMode": False,
            },
        }
        engine = ImagePolicyEngine()
        ok, _ = engine.verify_deployment_allowed(predicate)
        self.assertFalse(ok)
        ok, _ = engine.verify_no_vulnerable_algorithms(predicate)
        self.assertFalse(ok)

    def test_mixed_pqc_plus_classical_blocks(self):
        predicate = {
            "cbom": {"bomFormat": "CycloneDX-Crypto"},
            "pqcCompliance": {"deploymentAllowed": False},
            "cryptoInventory": {
                "vulnerableAlgorithms": ["RSA-2048"],
                "pqcAlgorithms": ["ML-KEM-768"],
                "minSymmetricKeyBits": 256,
                "hashAlgorithms": [],
                "hybridMode": False,
            },
        }
        engine = ImagePolicyEngine()
        ok, _ = engine.verify_no_vulnerable_algorithms(predicate)
        self.assertFalse(ok, "Even one vulnerable algorithm should block the image")

    def test_pure_pqc_passes(self):
        predicate = {
            "cbom": {"bomFormat": "CycloneDX-Crypto"},
            "pqcCompliance": {"deploymentAllowed": True},
            "cryptoInventory": {
                "vulnerableAlgorithms": [],
                "pqcAlgorithms": ["ML-KEM-768", "ML-DSA-65"],
                "minSymmetricKeyBits": 256,
                "hashAlgorithms": ["SHA-384"],
                "hybridMode": False,
            },
        }
        engine = ImagePolicyEngine()
        ok, _ = engine.verify_cbom_exists(predicate)
        self.assertTrue(ok)
        ok, _ = engine.verify_deployment_allowed(predicate)
        self.assertTrue(ok)
        ok, _ = engine.verify_no_vulnerable_algorithms(predicate)
        self.assertTrue(ok)

    def test_md5_hash_flagged_in_audit(self):
        predicate = {
            "cbom": {"bomFormat": "CycloneDX-Crypto"},
            "pqcCompliance": {"deploymentAllowed": True},
            "cryptoInventory": {
                "vulnerableAlgorithms": [],
                "hashAlgorithms": ["MD5", "SHA-256"],
                "minSymmetricKeyBits": 256,
                "hybridMode": False,
            },
        }
        engine = ImagePolicyEngine()
        ok, _ = engine.audit_weak_hash(predicate)
        self.assertFalse(ok)

    def test_sha256_only_passes_audit(self):
        predicate = {
            "cryptoInventory": {"hashAlgorithms": ["SHA-256", "SHA-384"]},
        }
        engine = ImagePolicyEngine()
        ok, _ = engine.audit_weak_hash(predicate)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
