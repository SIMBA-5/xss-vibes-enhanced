import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from browser_verify import browser_verify


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/alert":
            body = b"""
            <!doctype html>
            <html>
            <body>
            <script>alert('test-dialog')</script>
            </body>
            </html>
            """
        else:
            body = b"""
            <!doctype html>
            <html>
            <body>
            <h1>No JavaScript dialog</h1>
            </body>
            </html>
            """

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestBrowserVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), LabHandler)
        cls.port = cls.server.server_port
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_alert_is_browser_verified(self):
        result = browser_verify(
            f"http://127.0.0.1:{self.port}/alert"
        )

        self.assertTrue(result["browser_started"])
        self.assertTrue(result["page_loaded"])
        self.assertTrue(result["dialog_detected"])
        self.assertTrue(result["browser_verified"])
        self.assertEqual(result["dialog_type"], "alert")
        self.assertEqual(result["dialog_message"], "test-dialog")

    def test_page_without_dialog_is_not_verified(self):
        result = browser_verify(
            f"http://127.0.0.1:{self.port}/plain"
        )

        self.assertTrue(result["browser_started"])
        self.assertTrue(result["page_loaded"])
        self.assertFalse(result["dialog_detected"])
        self.assertFalse(result["browser_verified"])
        self.assertIsNone(result["dialog_type"])


if __name__ == "__main__":
    unittest.main()
