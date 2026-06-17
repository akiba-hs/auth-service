import hashlib
import hmac
import importlib
import os
import sys
import time
from http.cookies import SimpleCookie
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from telebot.apihelper import ApiTelegramException


BOT_TOKEN = "123456:test-token"
CHAT_ID = "-1001234567890"
DOMAIN = "akiba.space"


def _private_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _load_app():
    os.environ["BOT_TOKEN"] = BOT_TOKEN
    os.environ["CHAT_ID"] = CHAT_ID
    os.environ["DOMAIN"] = DOMAIN
    os.environ["JWT_KEY"] = _private_key_pem()

    sys.path.insert(0, os.path.abspath("src"))
    sys.modules.pop("app", None)
    app_module = importlib.import_module("app")
    app_module.app.config["TESTING"] = True
    return app_module


def _telegram_login_query(**overrides):
    args = {
        "id": "42424242",
        "first_name": "Alice",
        "last_name": "Example",
        "username": "alice",
        "auth_date": str(int(time.time())),
    }
    args.update(overrides)
    args_string = "\n".join(sorted([f"{k}={v}" for k, v in args.items()]))
    args["hash"] = hmac.new(
        hashlib.sha256(BOT_TOKEN.encode()).digest(),
        args_string.encode(),
        hashlib.sha256,
    ).hexdigest()
    return args


def _decode_token_from_response(app_module, response):
    cookie = SimpleCookie()
    cookie.load(response.headers["Set-Cookie"])
    token = cookie["token"].value
    return jwt.decode(
        token,
        app_module.private_key.public_key(),
        algorithms=["RS256"],
    )


class LoginTest(TestCase):
    def test_login_marks_chat_member_as_resident(self):
        app_module = _load_app()
        app_module.bot.get_chat_member = Mock(
            return_value=SimpleNamespace(
                status="member",
                user=SimpleNamespace(username="alice"),
            )
        )

        response = app_module.app.test_client().get("/login", query_string=_telegram_login_query())

        self.assertEqual(response.status_code, 303)
        payload = _decode_token_from_response(app_module, response)
        self.assertTrue(payload["is_resident"])
        app_module.bot.get_chat_member.assert_called_once_with(int(CHAT_ID), 42424242)

    def test_login_allows_non_resident_when_telegram_cannot_find_participant(self):
        app_module = _load_app()
        telegram_error = ApiTelegramException(
            "getChatMember",
            object(),
            {
                "ok": False,
                "error_code": 400,
                "description": "Bad Request: PARTICIPANT_ID_INVALID",
            },
        )
        app_module.bot.get_chat_member = Mock(side_effect=telegram_error)

        response = app_module.app.test_client().get("/login", query_string=_telegram_login_query())

        self.assertEqual(response.status_code, 303)
        payload = _decode_token_from_response(app_module, response)
        self.assertFalse(payload["is_resident"])

    def test_login_does_not_swallow_unexpected_telegram_api_errors(self):
        app_module = _load_app()
        app_module.app.config["TESTING"] = False
        telegram_error = ApiTelegramException(
            "getChatMember",
            object(),
            {
                "ok": False,
                "error_code": 400,
                "description": "Bad Request: chat not found",
            },
        )
        app_module.bot.get_chat_member = Mock(side_effect=telegram_error)

        response = app_module.app.test_client().get("/login", query_string=_telegram_login_query())

        self.assertEqual(response.status_code, 502)
        self.assertNotIn("Set-Cookie", response.headers)
