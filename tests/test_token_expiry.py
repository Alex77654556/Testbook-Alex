import base64
import json
import time
import unittest
from datetime import datetime, timedelta, timezone

from app import get_token, sign_token, validate_jwt


def _jwt(payload):
    def b64(data):
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    return f"{b64(b'{\"alg\":\"none\"}')}.{b64(json.dumps(payload).encode())}.test"


class TokenExpiryTests(unittest.TestCase):
    def test_accepts_future_iso8601_exp(self):
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        self.assertTrue(validate_jwt(_jwt({"sub": "user-1", "exp": exp}))[0])

    def test_rejects_expired_iso8601_exp(self):
        exp = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        self.assertFalse(validate_jwt(_jwt({"sub": "user-1", "exp": exp}))[0])

    def test_accepts_future_numeric_exp(self):
        self.assertTrue(validate_jwt(_jwt({"sub": "user-1", "exp": time.time() + 3600}))[0])

    def test_rejects_invalid_exp_format(self):
        self.assertFalse(validate_jwt(_jwt({"sub": "user-1", "exp": "not-a-date"}))[0])

    def test_signed_cookie_is_rejected_after_jwt_expiry(self):
        exp = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        self.assertIsNone(get_token(sign_token(_jwt({"sub": "user-1", "exp": exp}))))


if __name__ == "__main__":
    unittest.main()
