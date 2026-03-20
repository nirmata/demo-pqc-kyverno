#!/usr/bin/env python3
"""Tests for the CBOM Scanner module."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.cbom_scanner import CBOMScanner, CRYPTO_PATTERNS, TLS_PATTERNS


class TestCBOMScannerCryptoDetection(unittest.TestCase):
    """Test detection of various cryptographic algorithms in source code."""

    def _scan_content(self, content: str, ext: str = ".py") -> dict:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
            f.write(content)
            f.flush()
            scanner = CBOMScanner(f.name, "test-component", "1.0.0")
            cbom = scanner.scan()
        os.unlink(f.name)
        return cbom

    def _get_variants(self, cbom: dict) -> list:
        variants = []
        for c in cbom["components"]:
            props = c.get("cryptoProperties", {})
            algo = props.get("algorithmProperties", {})
            proto = props.get("protocolProperties", {})
            if algo.get("variant"):
                variants.append(algo["variant"])
            if proto.get("version"):
                variants.append(f"TLS-{proto['version']}")
        return variants

    # ── RSA Detection ──────────────────────────────────────────────
    def test_detect_rsa_python(self):
        code = """
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("RSA", variants)

    def test_detect_rsa_java(self):
        code = """
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(4096);
"""
        cbom = self._scan_content(code, ".java")
        variants = self._get_variants(cbom)
        self.assertIn("RSA", variants)

    def test_detect_rsa_openssl_c(self):
        code = """
RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
"""
        cbom = self._scan_content(code, ".c")
        variants = self._get_variants(cbom)
        self.assertIn("RSA", variants)

    # ── ECDSA Detection ────────────────────────────────────────────
    def test_detect_ecdsa_python(self):
        code = """
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key(ec.SECP256R1())
signature = private_key.sign(data, ECDSA(hashes.SHA256()))
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("ECDSA", variants)

    def test_detect_ecdsa_java(self):
        code = """
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
Signature sig = Signature.getInstance("SHA256withECDSA");
"""
        cbom = self._scan_content(code, ".java")
        variants = self._get_variants(cbom)
        self.assertIn("ECDSA", variants)

    # ── ECDH Detection ─────────────────────────────────────────────
    def test_detect_ecdh(self):
        code = """
shared_key = ECDH_compute_key(secret, secret_len, pub_key, priv_key, NULL);
"""
        cbom = self._scan_content(code, ".c")
        variants = self._get_variants(cbom)
        self.assertIn("ECDH", variants)

    # ── Diffie-Hellman Detection ───────────────────────────────────
    def test_detect_dh(self):
        code = """
DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);
"""
        cbom = self._scan_content(code, ".c")
        variants = self._get_variants(cbom)
        self.assertIn("DH", variants)

    def test_detect_diffie_hellman_java(self):
        code = """
KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
"""
        cbom = self._scan_content(code, ".java")
        variants = self._get_variants(cbom)
        self.assertIn("DH", variants)

    # ── PQC Algorithm Detection ────────────────────────────────────
    def test_detect_ml_kem(self):
        code = """
import oqs
kem = oqs.KeyEncapsulation("Kyber768")
ciphertext, shared_secret = kem.encap_secret(public_key)
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("ML-KEM", variants)

    def test_detect_ml_dsa(self):
        code = """
sig = oqs.Signature("Dilithium3")
signature = sig.sign(message)
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("ML-DSA", variants)

    def test_detect_slh_dsa(self):
        code = """
signer = oqs.Signature("SPHINCS+-SHA2-128s-simple")
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("SLH-DSA", variants)

    # ── Symmetric & Hash Detection ─────────────────────────────────
    def test_detect_aes_256(self):
        code = """
cipher = AES256(key, AES.MODE_GCM, nonce=nonce)
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("AES", variants)

    def test_detect_sha256(self):
        code = """
import hashlib
h = hashlib.sha256(data).hexdigest()
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("SHA-256", variants)

    def test_detect_md5(self):
        code = """
digest = hashlib.md5(data).hexdigest()
"""
        cbom = self._scan_content(code)
        variants = self._get_variants(cbom)
        self.assertIn("MD5", variants)

    # ── TLS Detection ──────────────────────────────────────────────
    def test_detect_tls_12(self):
        code = """
ssl_context.minimum_version = ssl.TLSv1.2
"""
        cbom = self._scan_content(code, ".py")
        variants = self._get_variants(cbom)
        self.assertIn("TLS-1.2", variants)

    def test_detect_tls_13(self):
        code = """
ssl_protocols TLSv1.3;
"""
        cbom = self._scan_content(code, ".conf")
        variants = self._get_variants(cbom)
        self.assertIn("TLS-1.3", variants)

    # ── Library Detection ──────────────────────────────────────────
    def test_detect_openssl_library(self):
        code = """
#include <openssl/evp.h>
RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
"""
        cbom = self._scan_content(code, ".c")
        has_deps = any(
            c.get("dependencies")
            for c in cbom["components"]
        )
        self.assertTrue(has_deps, "Should detect openssl dependency")

    def test_detect_pyca_cryptography(self):
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(65537, 2048)
"""
        cbom = self._scan_content(code)
        has_pyca = any(
            any(d.get("library") == "pyca/cryptography" for d in c.get("dependencies", []))
            for c in cbom["components"]
        )
        self.assertTrue(has_pyca)

    # ── CBOM Structure ─────────────────────────────────────────────
    def test_cbom_structure(self):
        code = "key = RSA.generate(2048)"
        cbom = self._scan_content(code)
        self.assertEqual(cbom["bomFormat"], "CycloneDX-Crypto")
        self.assertEqual(cbom["specVersion"], "1.6")
        self.assertIn("metadata", cbom)
        self.assertIn("components", cbom)
        self.assertIn("timestamp", cbom["metadata"])
        self.assertIn("tools", cbom["metadata"])

    def test_evidence_tracking(self):
        code = "key = RSA.generate(2048)"
        cbom = self._scan_content(code)
        for comp in cbom["components"]:
            evidence = comp.get("evidence", {})
            self.assertIn("source", evidence)
            self.assertIn("filePath", evidence)
            self.assertIn("lineNumber", evidence)
            self.assertIn("confidence", evidence)

    def test_empty_file_no_findings(self):
        cbom = self._scan_content("")
        self.assertEqual(len(cbom["components"]), 0)

    def test_pqc_ready_flag_vulnerable(self):
        code = "RSA_generate_key(2048, RSA_F4, NULL, NULL);"
        cbom = self._scan_content(code, ".c")
        for comp in cbom["components"]:
            algo = comp.get("cryptoProperties", {}).get("algorithmProperties", {})
            if algo.get("variant") == "RSA":
                self.assertFalse(algo["pqcReady"])
                self.assertEqual(algo["nistQuantumSecurityLevel"], 0)

    def test_pqc_ready_flag_compliant(self):
        code = 'kem = oqs.KeyEncapsulation("Kyber768")'
        cbom = self._scan_content(code)
        for comp in cbom["components"]:
            algo = comp.get("cryptoProperties", {}).get("algorithmProperties", {})
            if algo.get("variant") == "ML-KEM":
                self.assertTrue(algo["pqcReady"])
                self.assertGreater(algo["nistQuantumSecurityLevel"], 0)


class TestCBOMScannerDirectory(unittest.TestCase):
    """Test scanning entire directories."""

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "crypto_ops.py"
            py_file.write_text("""
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
""")
            conf_file = Path(tmpdir) / "tls.conf"
            conf_file.write_text("ssl_protocols TLSv1.2;")

            scanner = CBOMScanner(tmpdir, "test-app", "1.0.0")
            cbom = scanner.scan()
            self.assertGreater(len(cbom["components"]), 0)

    def test_scan_nonexistent_path(self):
        scanner = CBOMScanner("/nonexistent/path", "test", "1.0.0")
        with self.assertRaises(FileNotFoundError):
            scanner.scan()


if __name__ == "__main__":
    unittest.main()
