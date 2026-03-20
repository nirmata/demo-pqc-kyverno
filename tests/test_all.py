#!/usr/bin/env python3
"""
Combined test runner - runs all test suites and provides a summary.
Can be run directly without pytest.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.test_cbom_scanner import (
    TestCBOMScannerCryptoDetection,
    TestCBOMScannerDirectory,
)
from tests.test_pqc_analyzer import (
    TestVulnerableAppAnalysis,
    TestCompliantAppAnalysis,
    TestHybridAppAnalysis,
    TestEdgeCases,
)
from tests.test_attestation import (
    TestAttestationStructure,
    TestVulnerableImagePredicate,
    TestCompliantImagePredicate,
    TestHybridImagePredicate,
    TestPredicateSerializability,
)
from tests.test_kyverno_policies import (
    TestVerifyVulnerableImage,
    TestVerifyCompliantImage,
    TestVerifyHybridImage,
    TestVerifyNoAttestationImage,
    TestVerifyWeakSymmetricImage,
    TestImagePolicyEdgeCases,
)


def run_all_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        # Scanner tests
        TestCBOMScannerCryptoDetection,
        TestCBOMScannerDirectory,
        # Analyzer tests
        TestVulnerableAppAnalysis,
        TestCompliantAppAnalysis,
        TestHybridAppAnalysis,
        TestEdgeCases,
        # Attestation tests
        TestAttestationStructure,
        TestVulnerableImagePredicate,
        TestCompliantImagePredicate,
        TestHybridImagePredicate,
        TestPredicateSerializability,
        # Kyverno image policy simulation tests
        TestVerifyVulnerableImage,
        TestVerifyCompliantImage,
        TestVerifyHybridImage,
        TestVerifyNoAttestationImage,
        TestVerifyWeakSymmetricImage,
        TestImagePolicyEdgeCases,
    ]

    for test_class in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(test_class))

    print("=" * 70)
    print("PQC Discovery & Enforcement - Complete Test Suite")
    print("  Architecture: Image Attestation + Kyverno verifyImages")
    print("=" * 70)
    print()

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures:  {len(result.failures)}")
    print(f"Errors:    {len(result.errors)}")
    print(f"Skipped:   {len(result.skipped)}")
    print("=" * 70)

    if result.wasSuccessful():
        print("RESULT: ALL TESTS PASSED")
        return 0
    else:
        print("RESULT: SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
