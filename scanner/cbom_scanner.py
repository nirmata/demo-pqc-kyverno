#!/usr/bin/env python3
"""
CBOM Scanner - Scans source code and binaries to generate a Cryptographic Bill of Materials.

Identifies cryptographic algorithm usage by analyzing:
  - Import statements and library calls
  - Configuration files (TLS, SSH, etc.)
  - Certificate files
  - Binary signatures (via regex heuristics)

Output: CycloneDX-Crypto CBOM JSON
"""

import json
import os
import re
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

CRYPTO_PATTERNS: Dict[str, Dict[str, Any]] = {
    "RSA": {
        "patterns": [
            r"\bRSA\b", r"\brsa_", r"RSA\.generate", r"rsa\.generate",
            r"PKCS1_v1_5", r"PKCS1_OAEP", r"RSA_generate_key", r"rsa_keygen",
            r"new\s+RSAKeyGenParameterSpec", r"KeyPairGenerator.*RSA",
        ],
        "primitive": "asymmetric-encryption",
        "variant": "RSA",
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 0,
    },
    "ECDSA": {
        "patterns": [
            r"\bECDSA\b", r"\becdsa\b", r"EC\.generate", r"ECDSA_sign",
            r"ec\.generate_private_key", r"SigningKey.*NIST",
            r"KeyPairGenerator.*EC\b",
        ],
        "primitive": "digital-signature",
        "variant": "ECDSA",
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 0,
    },
    "ECDH": {
        "patterns": [
            r"\bECDH\b", r"\becdh\b", r"ECDH_compute_key",
            r"derive.*ECDH", r"KeyAgreement.*ECDH",
        ],
        "primitive": "key-agreement",
        "variant": "ECDH",
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 0,
    },
    "DH": {
        "patterns": [
            r"\bDiffie.?Hellman\b", r"\bDH_generate", r"\bdh_",
            r"DHParameterSpec", r"KeyAgreement.*DiffieHellman",
        ],
        "primitive": "key-agreement",
        "variant": "DH",
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 0,
    },
    "DSA": {
        "patterns": [
            r"\bDSA\b(?!.*ML-DSA)", r"\bdsa_sign", r"DSA\.generate",
            r"KeyPairGenerator.*DSA\b",
        ],
        "primitive": "digital-signature",
        "variant": "DSA",
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 0,
    },
    "ML-KEM": {
        "patterns": [
            r"\bML.?KEM\b", r"\bCRYSTALS.?Kyber", r"\bKyber\d*\b",
            r"\bml_kem\b", r"\bkyber", r"OQS_KEM_kyber",
        ],
        "primitive": "key-encapsulation",
        "variant": "ML-KEM",
        "pqcReady": True,
        "nistQuantumSecurityLevel": 3,
        "quantumSecurityBits": 192,
    },
    "ML-DSA": {
        "patterns": [
            r"\bML.?DSA\b", r"\bCRYSTALS.?Dilithium", r"\bDilithium\d*\b",
            r"\bml_dsa\b", r"\bdilithium", r"OQS_SIG_dilithium",
        ],
        "primitive": "digital-signature",
        "variant": "ML-DSA",
        "pqcReady": True,
        "nistQuantumSecurityLevel": 3,
        "quantumSecurityBits": 192,
    },
    "SLH-DSA": {
        "patterns": [
            r"\bSLH.?DSA\b", r"\bSPHINCS\+?\b", r"\bslh_dsa\b",
            r"\bsphincs\b", r"OQS_SIG_sphincs",
        ],
        "primitive": "digital-signature",
        "variant": "SLH-DSA",
        "pqcReady": True,
        "nistQuantumSecurityLevel": 1,
        "quantumSecurityBits": 128,
    },
    "AES-128": {
        "patterns": [
            r"\bAES.?128\b", r"aes_128", r"AES/.*128",
        ],
        "primitive": "symmetric-encryption",
        "variant": "AES",
        "keySize": 128,
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 64,
        "classicalSecurityBits": 128,
    },
    "AES-256": {
        "patterns": [
            r"\bAES.?256\b", r"aes_256", r"AES/.*256",
        ],
        "primitive": "symmetric-encryption",
        "variant": "AES",
        "keySize": 256,
        "pqcReady": True,
        "nistQuantumSecurityLevel": 1,
        "quantumSecurityBits": 128,
        "classicalSecurityBits": 256,
    },
    "SHA-1": {
        "patterns": [
            r"\bSHA.?1\b", r"\bsha1\b", r"SHA1",
        ],
        "primitive": "hash",
        "variant": "SHA-1",
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 0,
        "classicalSecurityBits": 80,
    },
    "SHA-256": {
        "patterns": [
            r"\bSHA.?256\b", r"\bsha256\b",
        ],
        "primitive": "hash",
        "variant": "SHA-256",
        "pqcReady": True,
        "nistQuantumSecurityLevel": 1,
        "quantumSecurityBits": 128,
        "classicalSecurityBits": 256,
    },
    "SHA-384": {
        "patterns": [
            r"\bSHA.?384\b", r"\bsha384\b",
        ],
        "primitive": "hash",
        "variant": "SHA-384",
        "pqcReady": True,
        "nistQuantumSecurityLevel": 3,
        "quantumSecurityBits": 192,
        "classicalSecurityBits": 384,
    },
    "SHA-512": {
        "patterns": [
            r"\bSHA.?512\b", r"\bsha512\b",
        ],
        "primitive": "hash",
        "variant": "SHA-512",
        "pqcReady": True,
        "nistQuantumSecurityLevel": 5,
        "quantumSecurityBits": 256,
        "classicalSecurityBits": 512,
    },
    "MD5": {
        "patterns": [
            r"\bMD5\b", r"\bmd5\b",
        ],
        "primitive": "hash",
        "variant": "MD5",
        "pqcReady": False,
        "nistQuantumSecurityLevel": 0,
        "quantumSecurityBits": 0,
        "classicalSecurityBits": 64,
    },
}

TLS_PATTERNS = {
    "TLS 1.0": {
        "patterns": [r"TLSv1(?:\.0)?(?!\.\d)", r"ssl\.PROTOCOL_TLSv1\b(?!_)"],
        "version": "1.0",
        "pqcReady": False,
    },
    "TLS 1.1": {
        "patterns": [r"TLSv1\.1", r"ssl\.PROTOCOL_TLSv1_1"],
        "version": "1.1",
        "pqcReady": False,
    },
    "TLS 1.2": {
        "patterns": [r"TLSv1\.2", r"ssl\.PROTOCOL_TLSv1_2", r"TLS_ECDHE_RSA"],
        "version": "1.2",
        "pqcReady": False,
    },
    "TLS 1.3": {
        "patterns": [r"TLSv1\.3", r"ssl\.PROTOCOL_TLS", r"TLS_AES_256_GCM"],
        "version": "1.3",
        "pqcReady": True,
    },
}

LIBRARY_IDENTIFIERS = {
    "openssl": {
        "patterns": [r"\bopenssl\b", r"libssl", r"libcrypto"],
        "purl_prefix": "pkg:generic/openssl",
    },
    "pyca/cryptography": {
        "patterns": [r"from cryptography", r"import cryptography"],
        "purl_prefix": "pkg:pypi/cryptography",
    },
    "pycryptodome": {
        "patterns": [r"from Crypto\.", r"from Cryptodome\."],
        "purl_prefix": "pkg:pypi/pycryptodome",
    },
    "bouncy-castle": {
        "patterns": [r"org\.bouncycastle", r"BouncyCastleProvider"],
        "purl_prefix": "pkg:maven/org.bouncycastle",
    },
    "liboqs": {
        "patterns": [r"\bliboqs\b", r"oqs\.", r"OQS_"],
        "purl_prefix": "pkg:generic/liboqs",
    },
    "oqs-provider": {
        "patterns": [r"oqs.?provider", r"oqsprovider"],
        "purl_prefix": "pkg:generic/oqs-provider",
    },
}

SCAN_EXTENSIONS = {
    ".py", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".js", ".ts", ".rb", ".cs", ".swift", ".kt",
    ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".xml",
    ".pem", ".crt", ".cer", ".key",
}

KEY_SIZE_PATTERNS = [
    (r"(?:key.?(?:size|length|bits))\s*[:=]\s*(\d+)", None),
    (r"RSA.*?(\d{3,5})", "RSA"),
    (r"(\d{3,5}).*?(?:bit|RSA|DSA)", None),
]


class CBOMScanner:
    def __init__(self, target_path: str, component_name: str = "", component_version: str = "0.0.0"):
        self.target_path = Path(target_path)
        self.component_name = component_name or self.target_path.name
        self.component_version = component_version
        self.findings: List[dict] = []
        self.libraries_found: Dict[str, dict] = {}

    def scan(self) -> dict:
        if self.target_path.is_file():
            self._scan_file(self.target_path)
        elif self.target_path.is_dir():
            self._scan_directory(self.target_path)
        else:
            raise FileNotFoundError(f"Target not found: {self.target_path}")

        return self._build_cbom()

    def _scan_directory(self, directory: Path):
        for root, _dirs, files in os.walk(directory):
            _dirs[:] = [d for d in _dirs if d not in {
                ".git", "node_modules", "__pycache__", ".venv", "venv",
                ".tox", ".eggs", "dist", "build",
            }]
            for filename in files:
                filepath = Path(root) / filename
                if filepath.suffix in SCAN_EXTENSIONS:
                    self._scan_file(filepath)

    def _scan_file(self, filepath: Path):
        try:
            content = filepath.read_text(errors="ignore")
        except (PermissionError, OSError):
            return

        self._detect_libraries(content, filepath)

        for algo_name, algo_info in CRYPTO_PATTERNS.items():
            for pattern in algo_info["patterns"]:
                for match in re.finditer(pattern, content):
                    line_number = content[:match.start()].count("\n") + 1
                    key_size = self._extract_key_size(content, match, algo_info)

                    finding = {
                        "algo_name": algo_name,
                        "algo_info": algo_info,
                        "filepath": str(filepath),
                        "line_number": line_number,
                        "key_size": key_size,
                        "match_text": match.group(),
                    }

                    if not self._is_duplicate(finding):
                        self.findings.append(finding)

        for proto_name, proto_info in TLS_PATTERNS.items():
            for pattern in proto_info["patterns"]:
                for match in re.finditer(pattern, content):
                    line_number = content[:match.start()].count("\n") + 1
                    finding = {
                        "proto_name": proto_name,
                        "proto_info": proto_info,
                        "filepath": str(filepath),
                        "line_number": line_number,
                        "match_text": match.group(),
                    }
                    if not self._is_duplicate(finding):
                        self.findings.append(finding)

    def _detect_libraries(self, content: str, filepath: Path):
        for lib_name, lib_info in LIBRARY_IDENTIFIERS.items():
            for pattern in lib_info["patterns"]:
                if re.search(pattern, content):
                    if lib_name not in self.libraries_found:
                        self.libraries_found[lib_name] = {
                            "name": lib_name,
                            "purl_prefix": lib_info["purl_prefix"],
                            "first_seen": str(filepath),
                        }

    def _extract_key_size(self, content: str, match: re.Match, algo_info: dict) -> Optional[int]:
        if "keySize" in algo_info:
            return algo_info["keySize"]

        context_start = max(0, match.start() - 200)
        context_end = min(len(content), match.end() + 200)
        context = content[context_start:context_end]

        for pattern, algo_filter in KEY_SIZE_PATTERNS:
            if algo_filter and algo_filter not in algo_info.get("variant", ""):
                continue
            key_match = re.search(pattern, context)
            if key_match:
                try:
                    size = int(key_match.group(1))
                    if 128 <= size <= 16384:
                        return size
                except (ValueError, IndexError):
                    pass
        return None

    def _is_duplicate(self, finding: dict) -> bool:
        for existing in self.findings:
            if (existing.get("algo_name") == finding.get("algo_name")
                    and existing.get("proto_name") == finding.get("proto_name")
                    and existing["filepath"] == finding["filepath"]
                    and existing["line_number"] == finding["line_number"]):
                return True
        return False

    def _build_cbom(self) -> dict:
        components = []
        seen_refs = set()

        for finding in self.findings:
            if "algo_name" in finding:
                component = self._build_algo_component(finding)
            else:
                component = self._build_proto_component(finding)

            ref = component.get("bom-ref", "")
            if ref not in seen_refs:
                seen_refs.add(ref)
                components.append(component)

        return {
            "bomFormat": "CycloneDX-Crypto",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {
                    "name": self.component_name,
                    "version": self.component_version,
                    "type": "application",
                },
                "tools": [
                    {"name": "pqc-cbom-scanner", "version": "1.0.0"}
                ],
            },
            "components": components,
        }

    def _build_algo_component(self, finding: dict) -> dict:
        info = finding["algo_info"]
        key_size = finding.get("key_size")
        variant = info["variant"]
        ref_name = f"{variant}-{key_size}" if key_size else variant

        algo_props: Dict[str, Any] = {
            "primitive": info["primitive"],
            "variant": variant,
            "implementationLevel": "software",
            "nistQuantumSecurityLevel": info["nistQuantumSecurityLevel"],
            "pqcReady": info["pqcReady"],
            "quantumSecurityBits": info["quantumSecurityBits"],
        }
        if key_size:
            algo_props["keySize"] = key_size
        if "classicalSecurityBits" in info:
            algo_props["classicalSecurityBits"] = info["classicalSecurityBits"]

        component: Dict[str, Any] = {
            "type": "crypto-asset",
            "name": finding["algo_name"],
            "bom-ref": f"crypto-{ref_name.lower().replace(' ', '-')}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": algo_props,
            },
            "evidence": {
                "source": "source-code",
                "filePath": finding["filepath"],
                "lineNumber": finding["line_number"],
                "confidence": 0.85,
            },
        }

        deps = self._find_relevant_libraries(variant)
        if deps:
            component["dependencies"] = deps

        return component

    def _build_proto_component(self, finding: dict) -> dict:
        info = finding["proto_info"]
        return {
            "type": "crypto-asset",
            "name": finding["proto_name"],
            "bom-ref": f"proto-tls-{info['version'].replace('.', '')}",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": info["version"],
                    "cipherSuites": [],
                },
            },
            "evidence": {
                "source": "configuration",
                "filePath": finding["filepath"],
                "lineNumber": finding["line_number"],
                "confidence": 0.80,
            },
        }

    def _find_relevant_libraries(self, variant: str) -> List[dict]:
        deps = []
        for lib_name, lib_data in self.libraries_found.items():
            deps.append({
                "library": lib_name,
                "version": "detected",
                "purl": lib_data["purl_prefix"],
            })
        return deps


def main():
    if len(sys.argv) < 2:
        print("Usage: cbom_scanner.py <target_path> [component_name] [component_version]")
        print("  target_path: File or directory to scan")
        print("  component_name: Name for the CBOM component (default: directory name)")
        print("  component_version: Version string (default: 0.0.0)")
        sys.exit(1)

    target = sys.argv[1]
    name = sys.argv[2] if len(sys.argv) > 2 else ""
    version = sys.argv[3] if len(sys.argv) > 3 else "0.0.0"

    scanner = CBOMScanner(target, name, version)
    cbom = scanner.scan()

    output_file = f"cbom-{Path(target).name}.json"
    with open(output_file, "w") as f:
        json.dump(cbom, f, indent=2)

    print(f"CBOM generated: {output_file}")
    print(f"  Components found: {len(cbom['components'])}")

    vulnerable = [c for c in cbom["components"]
                  if c["cryptoProperties"].get("algorithmProperties", {}).get("pqcReady") is False
                  or c["cryptoProperties"].get("protocolProperties", {}).get("cipherSuites", [{}])
                  and not c["cryptoProperties"].get("algorithmProperties", {}).get("pqcReady", True)]
    print(f"  Quantum-vulnerable: {len(vulnerable)}")


if __name__ == "__main__":
    main()
