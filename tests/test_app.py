import json
import threading
import unittest
from http.client import HTTPConnection

from app import create_server


class ApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.host, cls.port = cls.server.server_address

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path):
        connection = HTTPConnection(self.host, self.port)
        connection.request("GET", path)
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        return response.status, body

    def test_health_endpoint(self):
        self.assertEqual(self.request("/health"), (200, {"status": "ok"}))

    def test_greeting_accepts_valid_name(self):
        self.assertEqual(self.request("/hello?name=Alice"), (200, {"message": "Hello, Alice!"}))

    def test_greeting_rejects_missing_name(self):
        status, body = self.request("/hello")
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_greeting_rejects_invalid_name(self):
        status, body = self.request("/hello?name=%3Cscript%3E")
        self.assertEqual(status, 400)
        self.assertIn("safe characters", body["error"])

    def test_greeting_rejects_oversized_name(self):
        status, body = self.request("/hello?name=" + ("a" * 51))
        self.assertEqual(status, 400)
        self.assertIn("safe characters", body["error"])

    def test_unknown_route(self):
        self.assertEqual(self.request("/unknown"), (404, {"error": "not found"}))


if __name__ == "__main__":
    unittest.main()
