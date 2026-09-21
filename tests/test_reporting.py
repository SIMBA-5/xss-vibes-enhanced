import unittest

from reporting import dedupe_findings


class TestFindingDeduplication(unittest.TestCase):
    def test_duplicate_payloads_are_collapsed(self):
        findings = [
            {
                "url": "http://lab/?q=x",
                "parameter": "q",
                "payload": "A",
                "context": "html-text",
                "markup_context": "raw-markup",
                "confidence": "high",
                "score": 4,
                "browser_verified": False,
            },
            {
                "url": "http://lab/?q=x",
                "parameter": "q",
                "payload": "A",
                "context": "html-text",
                "markup_context": "raw-markup",
                "confidence": "high",
                "score": 4,
                "browser_verified": False,
            },
        ]

        result = dedupe_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["payload_count"], 1)

    def test_payloads_are_grouped(self):
        findings = [
            {
                "url": "http://lab/?q=x",
                "parameter": "q",
                "payload": "A",
                "context": "html-text",
                "markup_context": "raw-markup",
                "confidence": "high",
                "score": 4,
                "browser_verified": False,
            },
            {
                "url": "http://lab/?q=x",
                "parameter": "q",
                "payload": "B",
                "context": "html-text",
                "markup_context": "raw-markup",
                "confidence": "high",
                "score": 5,
                "browser_verified": True,
            },
        ]

        result = dedupe_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["payload_count"], 2)
        self.assertEqual(result[0]["browser_verified_count"], 1)
        self.assertTrue(result[0]["browser_verified"])
        self.assertEqual(result[0]["verification_level"], "browser-verified")
        self.assertEqual(result[0]["payloads"], ["A", "B"])

    def test_different_contexts_remain_separate(self):
        findings = [
            {
                "url": "http://lab/?q=x",
                "parameter": "q",
                "payload": "A",
                "context": "html-text",
                "markup_context": "raw-markup",
                "confidence": "high",
                "score": 4,
                "browser_verified": False,
            },
            {
                "url": "http://lab/?q=x",
                "parameter": "q",
                "payload": "A",
                "context": "attribute",
                "markup_context": "raw-markup",
                "confidence": "high",
                "score": 4,
                "browser_verified": False,
            },
        ]

        result = dedupe_findings(findings)

        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
