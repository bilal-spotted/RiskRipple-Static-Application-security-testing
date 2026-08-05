"""
Tests for the canonical severity model (core.severity).

Ensures CRITICAL, HIGH, MEDIUM, LOW are consistent across the codebase.
"""

import unittest

from core.severity import (
    DEFAULT_SEVERITY,
    SEVERITY_LEVELS,
    SEVERITY_WEIGHTS,
    normalize_severity,
    severity_sort_key,
)


class TestSeverityLevels(unittest.TestCase):
    """Canonical severity levels and weights."""

    def test_severity_levels_are_four(self):
        self.assertEqual(len(SEVERITY_LEVELS), 4)
        self.assertEqual(SEVERITY_LEVELS, ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    def test_weights_defined_for_all_levels(self):
        for level in SEVERITY_LEVELS:
            self.assertIn(level, SEVERITY_WEIGHTS)
        self.assertEqual(SEVERITY_WEIGHTS["CRITICAL"], 10)
        self.assertEqual(SEVERITY_WEIGHTS["HIGH"], 6)
        self.assertEqual(SEVERITY_WEIGHTS["MEDIUM"], 3)
        self.assertEqual(SEVERITY_WEIGHTS["LOW"], 1)

    def test_sort_order_descending(self):
        self.assertGreater(severity_sort_key("CRITICAL"), severity_sort_key("HIGH"))
        self.assertGreater(severity_sort_key("HIGH"), severity_sort_key("MEDIUM"))
        self.assertGreater(severity_sort_key("MEDIUM"), severity_sort_key("LOW"))


class TestNormalizeSeverity(unittest.TestCase):
    """normalize_severity returns canonical level."""

    def test_returns_canonical_uppercase(self):
        self.assertEqual(normalize_severity("critical"), "CRITICAL")
        self.assertEqual(normalize_severity("HIGH"), "HIGH")
        self.assertEqual(normalize_severity("medium"), "MEDIUM")
        self.assertEqual(normalize_severity("low"), "LOW")

    def test_unknown_maps_to_low(self):
        self.assertEqual(normalize_severity("UNKNOWN"), DEFAULT_SEVERITY)
        self.assertEqual(normalize_severity(""), DEFAULT_SEVERITY)
        self.assertEqual(normalize_severity(None), DEFAULT_SEVERITY)

    def test_whitespace_stripped(self):
        self.assertEqual(normalize_severity("  HIGH  "), "HIGH")
