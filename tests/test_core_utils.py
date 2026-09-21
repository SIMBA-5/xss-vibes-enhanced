import unittest

from core_utils import create_session, get_parameters, replace_parameter


class TestCoreUtils(unittest.TestCase):
    def test_get_parameters_preserves_order_and_removes_duplicates(self):
        url = "http://example.test/?b=2&a=1&b=3&empty="
        self.assertEqual(
            get_parameters(url),
            ["b", "a", "empty"],
        )

    def test_replace_parameter_preserves_other_parameters(self):
        url = "http://example.test/search?a=1&q=hello&b=2"
        result = replace_parameter(url, "q", "x y")

        self.assertEqual(
            result,
            "http://example.test/search?a=1&q=x+y&b=2",
        )

    def test_replace_parameter_only_changes_first_match(self):
        url = "http://example.test/?q=one&q=two"
        result = replace_parameter(url, "q", "changed")

        self.assertEqual(
            result,
            "http://example.test/?q=changed&q=two",
        )

    def test_create_session_applies_headers(self):
        session = create_session({"X-Test": "xss-vibes"})
        try:
            self.assertEqual(
                session.headers.get("X-Test"),
                "xss-vibes",
            )
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
