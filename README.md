# Post-Quantum Cryptography (PQC) Discovery & Enforcement via Attested CBOM + Kyverno Image Verification

A complete solution for discovering quantum-vulnerable cryptography using **Cryptographic Bills of Materials (CBOM)**, attesting CBOMs to OCI container images via **cosign/sigstore**, and enforcing post-quantum compliance in Kubernetes using **Kyverno `verifyImages`** policies.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CI/CD Pipeline                               │
│                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  Source   │───▶│ CBOM Scanner │───▶│ PQC Analyzer │              │
│  │  Code /   │    │              │    │              │              │
│  │  Binary   │    │ Generates    │    │ Produces     │              │
│  └──────────┘    │ CycloneDX-   │    │ compliance   │              │
│                  │ Crypto CBOM  │    │ report       │              │
│                  └──────┬───────┘    └──────┬───────┘              │
│                         │                   │                       │
│                         ▼                   ▼                       │
│                  ┌──────────────────────────────┐                   │
│                  │  Attestation Builder          │                   │
│                  │  Wraps CBOM + report in       │                   │
│                  │  in-toto predicate            │                   │
│                  └──────────────┬───────────────┘                   │
│                                │                                    │
│                                ▼                                    │
│                  ┌──────────────────────────────┐                   │
│                  │  cosign attest                │                   │
│                  │  Signs predicate and attaches │                   │
│                  │  to OCI image manifest        │                   │
│                  └──────────────┬───────────────┘                   │
│                                │                                    │
└────────────────────────────────┼────────────────────────────────────┘
                                 │
                    OCI Image with signed CBOM attestation
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                              │
│                                                                     │
│  ┌──────────────────────────────────────────────────────┐          │
│  │   Kyverno Admission Controller                       │          │
│  │                                                      │          │
│  │   verifyImages rules:                                │          │
│  │   1. Fetch attestation from image (cosign verify)    │          │
│  │   2. Verify signature (keyless or key-based)         │          │
│  │   3. Inspect CBOM predicate:                         │          │
│  │      • pqcCompliance.deploymentAllowed == true?      │          │
│  │      • cryptoInventory.vulnerableAlgorithms empty?   │          │
│  │      • No RSA, ECDSA, ECDH, DH, DSA?                │          │
│  │      • minSymmetricKeyBits >= 256?                   │          │
│  │      • No MD5/SHA-1 in hashAlgorithms?               │          │
│  │                                                      │          │
│  │   ┌────────────┐              ┌───────────────┐      │          │
│  │   │  ALLOW     │              │  BLOCK        │      │          │
│  │   │  PQC image │              │  Vulnerable   │      │          │
│  │   │  passes    │              │  image or no  │      │          │
│  │   │  all checks│              │  attestation  │      │          │
│  │   └────────────┘              └───────────────┘      │          │
│  └──────────────────────────────────────────────────────┘          │
│                                                                     │
│  No annotations needed on Deployments -- all validation             │
│  happens from the image's signed CBOM attestation.                  │
└────────────────────────────────────────────────────────────────────┘
```

### Why Image Attestation (not Deployment Annotations)?

| Aspect | Annotations (old) | Image Attestation (new) |
|--------|-------------------|------------------------|
| Tamper resistance | Annotations can be edited manually | Cryptographically signed, tamper-proof |
| Trust chain | No signature verification | cosign verifies via Sigstore/Rekor or keys |
| Deployment coupling | Annotations must be synced with image | Attestation travels with the image |
| Portability | Annotations are cluster-specific | Attestation is registry-native (OCI) |
| Audit trail | No provenance | Rekor transparency log |
| Kyverno integration | `validate` on metadata | `verifyImages` on image attestations |

## Project Structure

```
post-quantum-crypto/
├── attestation/
│   └── cbom_attestation.py            # In-toto attestation builder
├── cbom/
│   ├── schemas/
│   │   └── cbom-schema.json           # CycloneDX-Crypto JSON Schema
│   └── samples/
│       ├── vulnerable-app-cbom.json   # RSA/ECDSA/ECDH/DH image
│       ├── compliant-app-cbom.json    # ML-KEM/ML-DSA/SLH-DSA image
│       └── hybrid-app-cbom.json       # X25519+ML-KEM-768 hybrid image
├── scanner/
│   └── cbom_scanner.py                # Source code crypto scanner
├── analyzer/
│   └── pqc_analyzer.py                # PQC vulnerability analyzer
├── kyverno/
│   ├── policies/
│   │   ├── pqc-image-verification.yaml    # verifyImages enforce policies
│   │   ├── pqc-block-vulnerable-deployments.yaml  # Label gate
│   │   └── pqc-audit-warn-policies.yaml   # Audit policies (verifyImages)
│   └── tests/
│       └── kyverno-test.yaml
├── k8s/
│   ├── namespaces/
│   │   └── pqc-namespace.yaml
│   └── deployments/                   # Clean manifests, NO annotations
│       ├── vulnerable-deployment.yaml
│       ├── compliant-deployment.yaml
│       ├── hybrid-deployment.yaml
│       ├── no-scan-deployment.yaml
│       └── weak-symmetric-deployment.yaml
├── scripts/
│   ├── pipeline.sh                    # End-to-end pipeline
│   ├── cosign_attest_cbom.sh          # Attest CBOM to image via cosign
│   └── annotate_deployment.py         # Legacy annotation helper
├── tests/
│   ├── test_cbom_scanner.py           # 25 tests
│   ├── test_pqc_analyzer.py           # 31 tests
│   ├── test_attestation.py            # 22 tests (NEW)
│   ├── test_kyverno_policies.py       # 30 tests (image-based)
│   ├── test_integration.py            # 16 tests
│   └── test_all.py                    # Combined runner
├── requirements.txt
└── README.md
```

## Quick Start

### Prerequisites

- Python 3.8+
- PyYAML (`pip install pyyaml`)
- cosign (for image attestation): `brew install cosign` or [install guide](https://docs.sigstore.dev/cosign/installation/)
- Optional: Kyverno CLI for policy testing
- Optional: kubectl + cluster for live enforcement

### Run All Tests (134 tests)

```bash
python3 tests/test_all.py          # 118 core tests
python3 -m unittest discover tests # All 134 tests including integration
```

### Attest a CBOM to an Image

```bash
# Full pipeline: scan -> analyze -> attest
./scripts/cosign_attest_cbom.sh registry.io/myapp:v1 ./src

# Or step by step:

# 1. Scan source code
python3 scanner/cbom_scanner.py ./src my-app 1.0.0

# 2. Analyze for PQC vulnerabilities
python3 analyzer/pqc_analyzer.py cbom-src.json report.json

# 3. Build in-toto attestation
python3 attestation/cbom_attestation.py cbom-src.json report.json registry.io/myapp:v1

# 4. Attach to image (keyless via Sigstore)
cosign attest --predicate predicate.json --type https://pqc.security.io/cbom/v1 registry.io/myapp:v1

# 4b. Or attach with a key
cosign attest --key cosign.key --predicate predicate.json --type https://pqc.security.io/cbom/v1 registry.io/myapp:v1
```

## Components

### 1. CBOM Attestation (`attestation/cbom_attestation.py`)

Wraps CBOM + PQC report into an **in-toto Statement v1** with predicate type `https://pqc.security.io/cbom/v1`.

The predicate structure (this is what Kyverno inspects):

```json
{
  "cbom": { "bomFormat": "CycloneDX-Crypto", ... },
  "pqcCompliance": {
    "isCompliant": false,
    "deploymentAllowed": false,
    "complianceLevel": "quantum-vulnerable"
  },
  "cryptoInventory": {
    "algorithmsDetected": ["RSA-2048", "ECDSA-P256", "AES-256-GCM"],
    "vulnerableAlgorithms": ["RSA-2048", "ECDSA-P256"],
    "pqcAlgorithms": [],
    "hashAlgorithms": ["SHA-256"],
    "minSymmetricKeyBits": 256,
    "minTlsVersion": "1.2",
    "opensslVersion": "1.1.1w",
    "hybridMode": false
  },
  "severityCounts": { "critical": 4, "high": 3, ... },
  "findings": [ ... ]
}
```

### 2. Kyverno `verifyImages` Policies

The primary policy `pqc-verify-image-cbom` uses Kyverno's `verifyImages` to:
1. **Fetch** the `https://pqc.security.io/cbom/v1` attestation from the image
2. **Verify** the cosign signature (keyless or key-based)
3. **Inspect** the predicate fields inline

#### Enforce Policies (block admission)

| Rule | What It Checks in Attestation |
|------|------------------------------|
| `verify-cbom-attestation` | `cbom.bomFormat == "CycloneDX-Crypto"` |
| `block-quantum-vulnerable-images` | `pqcCompliance.deploymentAllowed == true` |
| `deny-rsa-in-image` | `"RSA*" AnyNotIn cryptoInventory.vulnerableAlgorithms` |
| `deny-ecdsa-in-image` | `"ECDSA*" AnyNotIn cryptoInventory.vulnerableAlgorithms` |
| `deny-dh-in-image` | `"DH*","ECDH*" AnyNotIn cryptoInventory.vulnerableAlgorithms` |

#### Audit Policies (warn but allow)

| Rule | What It Checks in Attestation |
|------|------------------------------|
| `audit-small-symmetric-keys` | `cryptoInventory.minSymmetricKeyBits >= 256` |
| `audit-weak-hash-algorithms` | `"MD5","SHA-1" AnyNotIn cryptoInventory.hashAlgorithms` |
| `audit-hybrid-mode` | `cryptoInventory.hybridMode == true` |
| `audit-deprecated-tls` | `"1.0","1.1" AnyNotIn cryptoInventory.minTlsVersion` |

### 3. Deployment Manifests

Deployments are **clean** -- no `pqc.security.io/*` annotations needed. Kyverno pulls all validation data from the image's attestation at admission time.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pqc-secure-api
  labels:
    pqc.security.io/cbom-attested: "true"  # Lightweight label gate
spec:
  template:
    spec:
      containers:
        - name: api
          image: acme/pqc-secure-api:1.0.0  # Kyverno verifies THIS image
```

### 4. Test Matrix

| Image | Attestation | Expected | Why |
|-------|-------------|----------|-----|
| `acme/legacy-payment-service:2.3.1` | Has CBOM: RSA, ECDSA, DH, TLS 1.2 | **BLOCKED** | Vulnerable algorithms in attestation |
| `acme/pqc-secure-api:1.0.0` | Has CBOM: ML-KEM, ML-DSA, SLH-DSA | **ALLOWED** | All PQC-compliant |
| `acme/hybrid-transition-service:3.1.0` | Has CBOM: X25519+ML-KEM, ML-DSA | **ALLOWED** | Hybrid PQC mode |
| `acme/unscanned-service:1.0.0` | No attestation | **BLOCKED** | No CBOM attestation on image |
| `acme/weak-symmetric-service:1.2.0` | Has CBOM: ML-KEM, AES-128 | **ALLOWED + AUDIT** | PQC asymmetric, weak symmetric |

## Deploying to a Live Cluster

### 1. Install Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

### 2. Apply PQC Image Verification Policies

```bash
kubectl apply -f k8s/namespaces/pqc-namespace.yaml
kubectl apply -f kyverno/policies/pqc-image-verification.yaml
kubectl apply -f kyverno/policies/pqc-audit-warn-policies.yaml
kubectl apply -f kyverno/policies/pqc-block-vulnerable-deployments.yaml
```

### 3. Attest Images in CI/CD

```bash
# In your CI pipeline, after docker build + push:
./scripts/cosign_attest_cbom.sh $IMAGE_REF ./src
```

### 4. Deploy

```bash
# Image with PQC attestation -- ALLOWED
kubectl apply -f k8s/deployments/compliant-deployment.yaml

# Image with vulnerable attestation -- BLOCKED by Kyverno
kubectl apply -f k8s/deployments/vulnerable-deployment.yaml
# Error from server: admission webhook denied the request:
#   Image acme/legacy-payment-service:2.3.1 BLOCKED:
#   CBOM attestation shows quantum-vulnerable algorithms

# Image with no attestation -- BLOCKED by Kyverno
kubectl apply -f k8s/deployments/no-scan-deployment.yaml
# Error: no attestation of type https://pqc.security.io/cbom/v1 found
```

### 5. CI/CD Integration (GitHub Actions)

```yaml
jobs:
  build-and-attest:
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3

      - name: Build and push image
        run: |
          docker build -t $REGISTRY/$IMAGE:$TAG .
          docker push $REGISTRY/$IMAGE:$TAG

      - name: Scan, analyze, and attest CBOM
        run: |
          python3 scanner/cbom_scanner.py ./src $IMAGE $TAG
          python3 analyzer/pqc_analyzer.py cbom-src.json report.json
          python3 attestation/cbom_attestation.py cbom-src.json report.json $REGISTRY/$IMAGE:$TAG
          cosign attest \
            --predicate predicate.json \
            --type https://pqc.security.io/cbom/v1 \
            $REGISTRY/$IMAGE:$TAG

      - name: Deploy (Kyverno verifies the image attestation)
        run: kubectl apply -f k8s/deployment.yaml
```

## Key Concepts

### CBOM vs SBOM

| Feature | SBOM | CBOM |
|---------|------|------|
| Lists software packages | Yes | Yes |
| Identifies crypto algorithms | No | **Yes** |
| Reports key sizes & curves | No | **Yes** |
| Maps to NIST PQC standards | No | **Yes** |
| Pinpoints crypto in source code | No | **Yes** |
| Assesses quantum readiness | No | **Yes** |

### Quantum Threat Model

- **Shor's Algorithm**: Breaks RSA, ECDSA, ECDH, DH, DSA -- provides **zero** quantum security bits
- **Grover's Algorithm**: Halves symmetric key security -- AES-128 becomes 64-bit, AES-256 becomes 128-bit
- **Harvest Now, Decrypt Later**: Makes PQC migration urgent even before quantum computers arrive

### NIST PQC Standards

| Algorithm | FIPS | Type | Replaces |
|-----------|------|------|----------|
| ML-KEM (Kyber) | FIPS 203 | Key Encapsulation | RSA, ECDH, DH |
| ML-DSA (Dilithium) | FIPS 204 | Digital Signature | RSA-sig, ECDSA, DSA |
| SLH-DSA (SPHINCS+) | FIPS 205 | Digital Signature | RSA-sig, ECDSA, DSA |
