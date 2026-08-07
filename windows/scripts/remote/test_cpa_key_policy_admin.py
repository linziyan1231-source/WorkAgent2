from __future__ import annotations

import contextlib
import copy
import datetime
import base64
import importlib.util
import io
import json
import os
import tempfile
import urllib.error
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock


HELPER_PATH = Path(__file__).with_name("cpa-key-policy-admin.py")
SPEC = importlib.util.spec_from_file_location("cpa_key_policy_admin", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load cpa-key-policy-admin.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


class FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200, headers: dict[str, str] | None = None):
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.read_sizes: list[int] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.body[:size]


class FakeOpener:
    def __init__(self, result):
        self.result = result
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def usage_window(total: str, *, cache: bool = False) -> dict:
    result = {
        "call_count": 3,
        "input_tokens": 1200,
        "output_tokens": 300,
        "total_usd": Decimal(total),
        "window_start": "2026-07-14T00:00:00Z",
    }
    if cache:
        result["cache_read_tokens"] = 200
        result["cache_cost_usd"] = Decimal("0.000035")
    return result


def usage_alias(name: str, provider: str, daily: str, weekly: str, *, in_config: bool, cache: bool = False) -> dict:
    result = {
        "alias": name,
        "daily": usage_window(daily, cache=cache),
        "in_config": in_config,
        "weekly": usage_window(weekly, cache=cache),
    }
    if in_config:
        result.update({"billing_mode": "tokens", "provider": provider, "target_model": name + "-target"})
    return result


def usage_response(key_id: str, provider: str) -> dict:
    return {
        "aliases": [
            usage_alias(provider + "-primary", provider, "1.10", "2.20", in_config=True, cache=True),
            usage_alias(provider + "-historical", provider, "0.15", "0.30", in_config=False),
        ],
        "daily_limit_usd": Decimal("20.00") if provider == "codex" else Decimal("5.00"),
        "key_id": key_id,
        "key_name": provider + " employee policy",
        "weekly_limit_usd": Decimal("40.00") if provider == "codex" else Decimal("10.00"),
    }


def usage_summary(key_id: str, provider: str, *, daily: str = "1.25", weekly: str = "2.50") -> dict:
    daily_limit = Decimal("20.00") if provider == "codex" else Decimal("5.00")
    weekly_limit = Decimal("40.00") if provider == "codex" else Decimal("10.00")
    return {
        "aliases": [{"alias": provider + "-primary"}],
        "id": key_id,
        "daily_limit_usd": daily_limit,
        "weekly_limit_usd": weekly_limit,
        "usage": {
            "daily_usd": Decimal(daily),
            "weekly_usd": Decimal(weekly),
            "daily_limit_usd": daily_limit,
            "weekly_limit_usd": weekly_limit,
            "daily_reset_at": "2026-07-15T00:00:00Z",
            "weekly_reset_at": "2026-07-20T18:30:00Z",
        },
        "models": [{"alias": provider + "-primary", "provider": provider}],
    }


class ManagedAliasTests(unittest.TestCase):
    def test_k3_uses_its_own_official_api_price_and_physical_target(self):
        aliases = {item["alias"]: item for item in HELPER.MANAGED_ALIASES}

        self.assertEqual(
            HELPER.comparable_alias(aliases["kimi-k3"]),
            ("kimi-k3", (("kimi", "kimi-k3", ""),), "priority", "tokens", 3.0, 15.0, 0.3, 0.0),
        )
        self.assertNotEqual(
            HELPER.comparable_alias(aliases["kimi-k3"])[4:7],
            HELPER.comparable_alias(aliases["kimi-for-coding"])[4:7],
        )

    def test_managed_alias_verification_rejects_k3_with_k27_price(self):
        catalog = {item["alias"].lower(): copy.deepcopy(item) for item in HELPER.MANAGED_ALIASES}
        catalog["kimi-k3"]["input_price_per_million"] = 0.95

        with self.assertRaisesRegex(HELPER.UserError, "managed alias verification failed: kimi-k3"):
            HELPER.verify_managed_aliases(catalog)


class UsageRequestTests(unittest.TestCase):
    def read(self, value: object) -> dict:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        with mock.patch.object(HELPER.sys, "stdin", FakeStdin(raw)):
            return HELPER.read_usage_request()

    def test_accepts_exact_two_provider_key_mapping(self):
        request = {
            "version": 1,
            "keys": [
                {"kind": "kimi", "key_id": "employee.kimi-1"},
                {"kind": "chatgpt", "key_id": "employee.codex-1"},
            ],
        }
        self.assertEqual(self.read(request), request)

    def test_rejects_invalid_and_duplicated_inputs(self):
        valid = {
            "version": 1,
            "keys": [
                {"kind": "chatgpt", "key_id": "employee-codex"},
                {"kind": "kimi", "key_id": "employee-kimi"},
            ],
        }
        cases = []
        value = copy.deepcopy(valid)
        value["extra"] = True
        cases.append(value)
        value = copy.deepcopy(valid)
        value["version"] = True
        cases.append(value)
        value = copy.deepcopy(valid)
        value["keys"] = value["keys"][:1]
        cases.append(value)
        value = copy.deepcopy(valid)
        value["keys"][1]["kind"] = "chatgpt"
        cases.append(value)
        value = copy.deepcopy(valid)
        value["keys"][1]["key_id"] = value["keys"][0]["key_id"]
        cases.append(value)
        value = copy.deepcopy(valid)
        value["keys"][0]["key_id"] = "Invalid/Key"
        cases.append(value)
        value = copy.deepcopy(valid)
        value["keys"][0]["extra"] = True
        cases.append(value)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(HELPER.UserError):
                self.read(case)

    def test_rejects_nonfinite_and_oversized_stdin(self):
        with mock.patch.object(HELPER.sys, "stdin", FakeStdin(b'{"version":NaN,"keys":[]}')):
            with self.assertRaisesRegex(HELPER.UserError, "invalid JSON"):
                HELPER.read_usage_request()
        with mock.patch.object(HELPER.sys, "stdin", FakeStdin(b" " * (HELPER.MAX_STDIN + 1))):
            with self.assertRaisesRegex(HELPER.UserError, "exceeded 64 KiB"):
                HELPER.read_usage_request()


class UsageHTTPTests(unittest.TestCase):
    def call_with(self, result):
        opener = FakeOpener(result)
        with mock.patch.object(HELPER.urllib.request, "build_opener", return_value=opener) as build_opener:
            response = HELPER.usage_api_request("employee.codex-1", "M" * 40)
        return response, opener, build_opener

    def test_uses_loopback_no_proxy_timeout_size_bound_and_decimal_parser(self):
        body = b'{"amount":1.25}'
        response = FakeResponse(body, headers={"Content-Length": str(len(body))})
        parsed, opener, build_opener = self.call_with(response)
        self.assertEqual(parsed, {"amount": Decimal("1.25")})
        self.assertEqual(opener.timeout, HELPER.USAGE_TIMEOUT_SECONDS)
        self.assertLessEqual(opener.timeout, 10)
        self.assertEqual(response.read_sizes, [HELPER.USAGE_MAX_RESPONSE + 1])
        self.assertTrue(opener.request.full_url.startswith(HELPER.BASE_URL + "/keys/usage?id="))
        self.assertEqual(opener.request.get_method(), "GET")
        handler = build_opener.call_args.args[0]
        self.assertIsInstance(handler, HELPER.urllib.request.ProxyHandler)
        self.assertEqual(handler.proxies, {})
        self.assertIsInstance(build_opener.call_args.args[1], HELPER.NoRedirectHandler)

    def test_rejects_oversized_truncated_trailing_and_nonfinite_responses(self):
        cases = [
            FakeResponse(b"x" * (HELPER.USAGE_MAX_RESPONSE + 1)),
            FakeResponse(b"{}", headers={"Content-Length": "3"}),
            FakeResponse(b"{} trailing"),
            FakeResponse(b'{"amount":NaN}'),
        ]
        for response in cases:
            with self.subTest(body_length=len(response.body)):
                opener = FakeOpener(response)
                with mock.patch.object(HELPER.urllib.request, "build_opener", return_value=opener):
                    with self.assertRaises(HELPER.UserError):
                        HELPER.usage_api_request("employee.codex-1", "M" * 40)

    def test_http_failure_is_generic_and_does_not_echo_response_or_key_id(self):
        key_id = "employee.codex-private"
        error = urllib.error.HTTPError(
            HELPER.BASE_URL + "/keys/usage?id=" + key_id,
            502,
            "upstream response named a private user",
            {},
            io.BytesIO(b'{"message":"private user data"}'),
        )
        opener = FakeOpener(error)
        with mock.patch.object(HELPER.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(HELPER.UserError) as raised:
                HELPER.usage_api_request(key_id, "M" * 40)
        message = str(raised.exception)
        self.assertEqual(message, "usage API returned HTTP 502")
        self.assertNotIn(key_id, message)
        self.assertNotIn("private user", message)

    def test_connection_failure_is_generic(self):
        opener = FakeOpener(urllib.error.URLError(TimeoutError("timed out with private details")))
        with mock.patch.object(HELPER.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(HELPER.UserError) as raised:
                HELPER.usage_api_request("employee.codex-private", "M" * 40)
        self.assertEqual(str(raised.exception), "usage API connection failed")


class UsageResponseTests(unittest.TestCase):
    def test_allows_omitted_zero_counters_for_unused_alias_windows(self):
        response = usage_response("employee-codex", "codex")
        for window in (response["aliases"][0]["daily"], response["aliases"][0]["weekly"]):
            window["total_usd"] = 0
            del window["call_count"]
            del window["input_tokens"]
            del window["output_tokens"]
        summary = HELPER.key_usage_summaries(
            {"keys": [usage_summary("employee-codex", "codex")]},
            {"employee-codex"},
        )["employee-codex"]

        result = HELPER.summarize_usage("chatgpt", "employee-codex", response, summary)

        self.assertEqual(result["kind"], "chatgpt")

    def test_rejects_invalid_present_usage_counter(self):
        response = usage_response("employee-codex", "codex")
        response["aliases"][0]["daily"]["call_count"] = -1
        summary = HELPER.key_usage_summaries(
            {"keys": [usage_summary("employee-codex", "codex")]},
            {"employee-codex"},
        )["employee-codex"]

        with self.assertRaisesRegex(HELPER.UserError, "call_count is invalid"):
            HELPER.summarize_usage("chatgpt", "employee-codex", response, summary)

    def test_uses_authoritative_key_totals_and_allows_cache_fields(self):
        summary = HELPER.key_usage_summaries({"keys": [usage_summary("employee-codex", "codex")]}, {"employee-codex"})
        result = HELPER.summarize_usage("chatgpt", "employee-codex", usage_response("employee-codex", "codex"), summary["employee-codex"])
        self.assertEqual(
            result,
            {
                "kind": "chatgpt",
                "daily": {"limit_usd": "20.00", "used_usd": "1.25", "reset_at": "2026-07-15T00:00:00Z"},
                "weekly": {"limit_usd": "40.00", "used_usd": "2.50", "reset_at": "2026-07-20T18:30:00Z"},
            },
        )

    def test_alias_windows_do_not_override_key_reset_time(self):
        value = usage_response("employee-codex", "codex")
        value["aliases"][1]["daily"]["window_start"] = "2026-07-14T01:00:00Z"
        value["aliases"][1]["weekly"]["window_start"] = "2026-07-14T02:00:00Z"
        summary = HELPER.key_usage_summaries({"keys": [usage_summary("employee-codex", "codex")]}, {"employee-codex"})
        result = HELPER.summarize_usage("chatgpt", "employee-codex", value, summary["employee-codex"])
        self.assertEqual(result["daily"]["reset_at"], "2026-07-15T00:00:00Z")
        self.assertEqual(result["weekly"]["reset_at"], "2026-07-20T18:30:00Z")

    def test_unused_weekly_window_without_an_authoritative_reset_is_rejected(self):
        item = usage_summary("employee-codex", "codex", daily="0", weekly="0")
        del item["usage"]["weekly_reset_at"]
        with self.assertRaisesRegex(HELPER.UserError, "weekly reset time is missing"):
            HELPER.key_usage_summaries({"keys": [item]}, {"employee-codex"})

    def test_decimal_text_never_uses_exponent_notation(self):
        self.assertEqual(HELPER.decimal_text(Decimal("1E+3")), "1000")
        self.assertEqual(HELPER.decimal_text(Decimal("1E-12")), "0.000000000001")
        self.assertEqual(HELPER.decimal_text(Decimal("-0")), "0")

    def test_rejects_unknown_fields_at_every_response_level(self):
        cases = []
        value = usage_response("employee-codex", "codex")
        value["unknown"] = 1
        cases.append(value)
        value = usage_response("employee-codex", "codex")
        value["aliases"][0]["unknown"] = 1
        cases.append(value)
        value = usage_response("employee-codex", "codex")
        value["aliases"][0]["daily"]["unknown"] = 1
        cases.append(value)
        for response in cases:
            with self.subTest(fields=response.keys()), self.assertRaises(HELPER.UserError):
                HELPER.summarize_usage("chatgpt", "employee-codex", response, HELPER.key_usage_summaries({"keys": [usage_summary("employee-codex", "codex")]}, {"employee-codex"})["employee-codex"])

    def test_rejects_mismatched_key_provider_duplicate_alias_and_bad_amounts(self):
        cases = []
        value = usage_response("different-key", "codex")
        cases.append(value)
        value = usage_response("employee-codex", "codex")
        value["aliases"][0]["provider"] = "kimi"
        cases.append(value)
        value = usage_response("employee-codex", "codex")
        value["aliases"][1] = copy.deepcopy(value["aliases"][0])
        cases.append(value)
        for bad_amount in (True, Decimal("-0.01"), Decimal("NaN")):
            value = usage_response("employee-codex", "codex")
            value["aliases"][0]["daily"]["total_usd"] = bad_amount
            cases.append(value)
        for response in cases:
            with self.subTest(), self.assertRaises(HELPER.UserError):
                HELPER.summarize_usage("chatgpt", "employee-codex", response, HELPER.key_usage_summaries({"keys": [usage_summary("employee-codex", "codex")]}, {"employee-codex"})["employee-codex"])

    def test_rejects_key_authorization_for_another_provider(self):
        item = usage_summary("employee-codex", "codex")
        item["models"][0]["provider"] = "kimi"
        summary = HELPER.key_usage_summaries({"keys": [item]}, {"employee-codex"})["employee-codex"]
        with self.assertRaisesRegex(HELPER.UserError, "provider does not match"):
            HELPER.summarize_usage("chatgpt", "employee-codex", usage_response("employee-codex", "codex"), summary)

    def test_rejects_usage_aliases_that_do_not_match_current_key_authorization(self):
        response = usage_response("employee-codex", "codex")
        response["aliases"][0]["alias"] = "codex-other"
        summary = HELPER.key_usage_summaries({"keys": [usage_summary("employee-codex", "codex")]}, {"employee-codex"})["employee-codex"]
        with self.assertRaisesRegex(HELPER.UserError, "configured aliases do not match"):
            HELPER.summarize_usage("chatgpt", "employee-codex", response, summary)

    def test_usage_output_is_ordered_trimmed_and_contains_no_internal_identity(self):
        request = {
            "version": 1,
            "keys": [
                {"kind": "kimi", "key_id": "internal-kimi-id"},
                {"kind": "chatgpt", "key_id": "internal-codex-id"},
            ],
        }
        responses = {
            "internal-kimi-id": usage_response("internal-kimi-id", "kimi"),
            "internal-codex-id": usage_response("internal-codex-id", "codex"),
        }
        summaries = {"keys": [usage_summary("internal-kimi-id", "kimi"), usage_summary("internal-codex-id", "codex")]}
        config_path = mock.Mock()
        config_path.read_text.return_value = "remote-management:\n  allow-remote: false\n"

        def fetch(key_id, management_key):
            self.assertEqual(management_key, "M" * 40)
            return responses[key_id]

        stdout = io.StringIO()
        with (
            mock.patch.object(HELPER, "CONFIG_PATH", config_path),
            mock.patch.object(HELPER, "private_root_file"),
            mock.patch.object(HELPER, "require_remote_management_disabled"),
            mock.patch.object(HELPER, "read_usage_request", return_value=request),
            mock.patch.object(HELPER, "read_management_key", return_value="M" * 40),
            mock.patch.object(HELPER, "api_request", return_value=summaries),
            mock.patch.object(HELPER, "usage_api_request", side_effect=fetch),
            contextlib.redirect_stdout(stdout),
        ):
            HELPER.usage()

        raw = stdout.getvalue().strip()
        result = json.loads(raw)
        self.assertEqual(set(result), {"version", "as_of", "providers"})
        self.assertEqual(result["version"], 1)
        self.assertEqual([item["kind"] for item in result["providers"]], ["chatgpt", "kimi"])
        self.assertEqual(set(result["providers"][0]), {"kind", "daily", "weekly"})
        parsed_time = datetime.datetime.fromisoformat(result["as_of"].replace("Z", "+00:00"))
        self.assertIsNotNone(parsed_time.tzinfo)
        for forbidden in (
            "internal-kimi-id",
            "internal-codex-id",
            "employee policy",
            "codex-primary",
            "kimi-primary",
            "aliases",
            "key_name",
        ):
            self.assertNotIn(forbidden, raw)


class UsageAuthorizedKeyTests(unittest.TestCase):
    @staticmethod
    def public_key(fill: int = 7) -> str:
        algorithm = b"ssh-ed25519"
        blob = len(algorithm).to_bytes(4, "big") + algorithm + (32).to_bytes(4, "big") + bytes([fill]) * 32
        return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " aionui-portal-usage"

    def test_accepts_only_exact_ed25519_request(self):
        public_key = self.public_key()
        raw = json.dumps({"version": 1, "public_key": public_key}).encode("utf-8")
        with mock.patch.object(HELPER.sys, "stdin", FakeStdin(raw)):
            self.assertEqual(HELPER.read_usage_public_key_request(), public_key)
        invalid = [
            {"version": 1, "public_key": public_key, "extra": True},
            {"version": True, "public_key": public_key},
            {"version": 1, "public_key": public_key.replace("ssh-ed25519", "ssh-rsa", 1)},
            {"version": 1, "public_key": "ssh-ed25519 AAAA aionui-portal-usage"},
            {"version": 1, "public_key": public_key.replace("aionui-portal-usage", "other")},
        ]
        for value in invalid:
            with self.subTest(value=value), mock.patch.object(HELPER.sys, "stdin", FakeStdin(json.dumps(value).encode("utf-8"))):
                with self.assertRaises(HELPER.UserError):
                    HELPER.read_usage_public_key_request()

    def test_installs_one_forced_restricted_key_and_preserves_unmanaged_lines(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        ssh_root = root / ".ssh"
        ssh_root.mkdir(mode=0o700)
        authorized = ssh_root / "authorized_keys"
        old_managed = f'restrict,command="/old/helper usage" {self.public_key(3)}'
        unmanaged = "ssh-ed25519 AAAA existing-admin"
        authorized.write_text(unmanaged + "\n" + old_managed + "\n", encoding="utf-8")
        authorized.chmod(0o600)
        public_key = self.public_key(9)
        with (
            mock.patch.object(HELPER, "AUTHORIZED_KEYS_PATH", authorized),
            mock.patch.object(HELPER, "ROOT", Path("/root/cliproxyapi")),
            mock.patch.object(HELPER, "read_usage_public_key_request", return_value=public_key),
            mock.patch.object(HELPER, "private_root_directory"),
            mock.patch.object(HELPER, "private_root_file"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            HELPER.install_usage_key()
            HELPER.install_usage_key()
        lines = authorized.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], unmanaged)
        self.assertEqual(
            lines[1],
            'restrict,command="/root/cliproxyapi/cpa-key-policy-admin.py usage" ' + public_key,
        )
        self.assertEqual(len(lines), 2)
        if os.name != "nt":
            self.assertEqual(authorized.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
