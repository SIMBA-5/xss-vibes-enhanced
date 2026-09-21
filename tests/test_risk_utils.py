import unittest

from risk_utils import classify_risk


class TestRiskClassification(unittest.TestCase):
    def test_browser_verified_is_high(self):
        result = classify_risk(True, 5, "high", True, True)

        self.assertEqual(result["risk_level"], "High")
        self.assertIn("Chromium confirmed", result["risk_reason"])

    def test_strong_candidate_is_medium(self):
        result = classify_risk(False, 5, "high", True, True)

        self.assertEqual(result["risk_level"], "Medium")

    def test_weak_reflection_is_low(self):
        result = classify_risk(False, 2, "low", False, False)

        self.assertEqual(result["risk_level"], "Low")


if __name__ == "__main__":
    unittest.main()
