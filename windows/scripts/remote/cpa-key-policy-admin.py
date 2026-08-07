#!/usr/bin/env python3
"""Loopback-only administration helper for cpa-plugin-key-policy.

The helper is intended to be installed as root on the CLIProxyAPI host.  It
keeps the management credential on that host and emits employee plain keys
only for the one SSH request that created or rotated them.
"""

from __future__ import annotations

import datetime
import base64
import binascii
import http.client
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal
from pathlib import Path


ROOT = Path("/root/cliproxyapi")
CONFIG_PATH = ROOT / "config.yaml"
MANAGEMENT_KEY_PATH = ROOT / ".management-key"
BASE_URL = "http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy"
SERVICE = "cliproxyapi.service"
MAX_STDIN = 64 * 1024
USAGE_MAX_RESPONSE = 64 * 1024
USAGE_TIMEOUT_SECONDS = 10
AUTHORIZED_KEYS_PATH = Path("/root/.ssh/authorized_keys")
AUTHORIZED_KEYS_MAX_SIZE = 1024 * 1024
USAGE_KEY_COMMENT = "aionui-portal-usage"
USAGE_KEY_RE = re.compile(r"^ssh-ed25519 ([A-Za-z0-9+/]+={0,2}) aionui-portal-usage$")
MANAGED_USAGE_KEY_RE = re.compile(r"^(?:.* )?ssh-ed25519 [A-Za-z0-9+/]+={0,2} aionui-portal-usage$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{40,256}$")
CPA_KEY_RE = re.compile(r"^cpa_[A-Za-z0-9_-]{20,256}$")
USAGE_PROVIDERS = {"chatgpt": "codex", "kimi": "kimi"}
USAGE_RESPONSE_FIELDS = {"aliases", "daily_limit_usd", "key_id", "key_name", "weekly_limit_usd"}
USAGE_ALIAS_FIELDS = {"alias", "daily", "in_config", "weekly"}
USAGE_CONFIGURED_ALIAS_FIELDS = USAGE_ALIAS_FIELDS | {"billing_mode", "provider", "target_model"}
USAGE_WINDOW_REQUIRED_FIELDS = {"total_usd", "window_start"}
USAGE_WINDOW_OPTIONAL_FIELDS = {"call_count", "input_tokens", "output_tokens", "cache_cost_usd", "cache_read_tokens"}
USAGE_SUMMARY_REQUIRED_FIELDS = {"daily_limit_usd", "daily_reset_at", "daily_usd", "weekly_limit_usd", "weekly_usd"}


def token_alias(alias: str, provider: str, target_model: str, input_price: float, output_price: float, cache_price: float) -> dict:
    return {
        "alias": alias,
        "targets": [{"provider": provider, "target_model": target_model}],
        "dispatch": "priority",
        "billing_mode": "tokens",
        "input_price_per_million": input_price,
        "output_price_per_million": output_price,
        "cache_read_price_per_million": cache_price,
    }


MANAGED_ALIASES = (
    token_alias("codex-auto-review", "codex", "codex-auto-review", 1.75, 14, 0.175),
    token_alias("gpt-5.3-codex-spark", "codex", "gpt-5.3-codex-spark", 1.75, 14, 0.175),
    token_alias("gpt-5.4", "codex", "gpt-5.4", 2.5, 15, 0.25),
    token_alias("gpt-5.4-mini", "codex", "gpt-5.4-mini", 0.75, 4.5, 0.075),
    token_alias("gpt-5.5", "codex", "gpt-5.5", 5, 30, 0.5),
    token_alias("gpt-5.6-luna", "codex", "gpt-5.6-luna", 1, 6, 0.1),
    token_alias("gpt-5.6-sol", "codex", "gpt-5.6-sol", 5, 30, 0.5),
    token_alias("gpt-5.6-terra", "codex", "gpt-5.6-terra", 2.5, 15, 0.25),
    token_alias("kimi-for-coding", "kimi", "kimi-k2.7-code", 0.95, 4, 0.19),
    token_alias("kimi-for-coding-highspeed", "kimi", "kimi-k2.7-code-highspeed", 1.9, 8, 0.38),
    token_alias("kimi-k3", "kimi", "kimi-k3", 3, 15, 0.3),
    token_alias("kimi-k2.5", "kimi", "kimi-k2.5", 0.6, 3, 0.1),
    token_alias("kimi-k2.6", "kimi", "kimi-k2.6", 0.95, 4, 0.16),
    token_alias("kimi-k2.7", "kimi", "kimi-k2.7-code", 0.95, 4, 0.19),
    token_alias("kimi-k2.7-code", "kimi", "kimi-k2.7-code", 0.95, 4, 0.19),
    token_alias("kimi-k2.7-code-highspeed", "kimi", "kimi-k2.7-code-highspeed", 1.9, 8, 0.38),
)


class UserError(RuntimeError):
    pass


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def require_root() -> None:
    if os.geteuid() != 0:
        raise UserError("this helper must run as root")


def regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise UserError(f"cannot inspect required file {path}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise UserError(f"required path is not a regular non-symlink file: {path}")
    return info


def private_root_file(path: Path) -> os.stat_result:
    info = regular_file(path)
    if info.st_uid != 0 or info.st_gid != 0:
        raise UserError(f"required file is not owned by root:root: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise UserError(f"required file permissions are broader than 0600: {path}")
    return info


def private_root_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise UserError(f"cannot inspect required directory {path}: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise UserError(f"required path is not a directory: {path}")
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise UserError(f"required directory is not protected root:root 0700: {path}")
    return info


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def parse_scalar(value: str) -> str:
    value = value.strip()
    if value in ("", "''", '""'):
        return ""
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise UserError("remote-management.secret-key has invalid quoting") from exc
        if not isinstance(decoded, str):
            raise UserError("remote-management.secret-key is not a string")
        return decoded
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return value.split(" #", 1)[0].strip()


def management_secret_line(lines: list[str]) -> tuple[int, str]:
    in_block = False
    matches: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if re.match(r"^remote-management:\s*(?:#.*)?$", line):
            in_block = True
            continue
        if in_block and line and not line[0].isspace() and not line.lstrip().startswith("#"):
            in_block = False
        if in_block:
            match = re.match(r"^  secret-key:\s*(.*?)\s*$", line)
            if match:
                matches.append((index, parse_scalar(match.group(1))))
    if len(matches) != 1:
        raise UserError("config.yaml must contain exactly one remote-management.secret-key field")
    return matches[0]


def require_remote_management_disabled(lines: list[str]) -> None:
    in_block = False
    matches: list[str] = []
    for line in lines:
        if re.match(r"^remote-management:\s*(?:#.*)?$", line):
            in_block = True
            continue
        if in_block and line and not line[0].isspace() and not line.lstrip().startswith("#"):
            in_block = False
        if in_block:
            match = re.match(r"^  allow-remote:\s*(.*?)\s*$", line)
            if match:
                matches.append(parse_scalar(match.group(1)).lower())
    if matches != ["false"]:
        raise UserError("config.yaml must contain exactly one remote-management.allow-remote: false field")


def read_management_key() -> str:
    private_root_file(MANAGEMENT_KEY_PATH)
    value = MANAGEMENT_KEY_PATH.read_text(encoding="utf-8").strip()
    if not SECRET_RE.fullmatch(value):
        raise UserError("management key file has invalid content")
    return value


def comparable_alias(alias: object) -> tuple | None:
    if not isinstance(alias, dict) or not isinstance(alias.get("targets"), list):
        return None
    targets = []
    for target in alias["targets"]:
        if not isinstance(target, dict):
            return None
        targets.append((target.get("provider"), target.get("target_model"), target.get("group", "")))
    return (
        alias.get("alias"), tuple(targets), alias.get("dispatch", "priority"), alias.get("billing_mode", "tokens"),
        float(alias.get("input_price_per_million", 0)), float(alias.get("output_price_per_million", 0)),
        float(alias.get("cache_read_price_per_million", 0)), float(alias.get("per_call_usd", 0) or 0),
    )


def managed_alias_catalog() -> dict[str, dict]:
    response = api_request("/aliases", "GET", None)
    aliases = response.get("aliases") if isinstance(response, dict) else None
    if not isinstance(aliases, list):
        raise UserError("alias catalog response is invalid")
    return {str(alias.get("alias", "")).lower(): alias for alias in aliases if isinstance(alias, dict) and alias.get("alias")}


def verify_managed_aliases(catalog: dict[str, dict]) -> None:
    for desired in MANAGED_ALIASES:
        actual = catalog.get(desired["alias"].lower())
        if comparable_alias(actual) != comparable_alias(desired):
            raise UserError(f"managed alias verification failed: {desired['alias']}")


def ensure_managed_aliases(key: str) -> int:
    catalog = managed_alias_catalog()
    for desired in MANAGED_ALIASES:
        if comparable_alias(catalog.get(desired["alias"].lower())) != comparable_alias(desired):
            api_request("/aliases", "POST", desired, key)
    catalog = managed_alias_catalog()
    verify_managed_aliases(catalog)
    return len(catalog)


def bootstrap() -> None:
    private_root_file(CONFIG_PATH)
    original = CONFIG_PATH.read_text(encoding="utf-8")
    lines = original.splitlines()
    require_remote_management_disabled(lines)
    index, configured = management_secret_line(lines)

    if MANAGEMENT_KEY_PATH.exists():
        key = read_management_key()
    else:
        if configured.startswith("$2"):
            raise UserError("config contains a hashed management key but the protected plaintext key file is missing")
        key = configured or secrets.token_urlsafe(48)
        if not SECRET_RE.fullmatch(key):
            raise UserError("existing plaintext management key is outside the supported format")
        atomic_write(MANAGEMENT_KEY_PATH, (key + "\n").encode("utf-8"), 0o600)

    if configured and configured != key and not configured.startswith("$2"):
        raise UserError("config management key does not match the protected management key file")
    if not configured:
        backup = CONFIG_PATH.with_name(f"config.yaml.pre-management-api.{int(time.time())}.bak")
        if backup.exists():
            raise UserError(f"refusing to overwrite backup {backup}")
        atomic_write(backup, original.encode("utf-8"), 0o600)
        lines[index] = "  secret-key: " + json.dumps(key)
        atomic_write(CONFIG_PATH, ("\n".join(lines) + "\n").encode("utf-8"), 0o600)

    subprocess.run(["systemctl", "restart", SERVICE], check=True, timeout=30)
    deadline = time.monotonic() + 30
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            api_request("/keys", "GET", None, key)
            alias_count = ensure_managed_aliases(key)
            print(json.dumps({"status": "ready", "management_remote": False, "alias_count": alias_count}, separators=(",", ":")))
            return
        except Exception as exc:  # bounded readiness retry
            last_error = exc
            time.sleep(0.5)
    raise UserError(f"management API did not become ready: {safe_message(last_error)}")


def safe_message(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = re.sub(r"cpa_[A-Za-z0-9_-]+", "<redacted-key>", text)
    text = re.sub(r"Bearer\s+\S+", "Bearer <redacted>", text, flags=re.IGNORECASE)
    return text[:500]


def api_request(path: str, method: str, body: object | None, key: str | None = None) -> object:
    secret = key or read_management_key()
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise UserError("management response exceeded 2 MiB")
    except urllib.error.HTTPError as exc:
        raw = exc.read(16 * 1024)
        message = f"HTTP {exc.code}"
        try:
            parsed = json.loads(raw)
            candidate = parsed.get("error", {}).get("message") if isinstance(parsed.get("error"), dict) else parsed.get("message")
            if isinstance(candidate, str) and candidate:
                message += ": " + safe_message(candidate)
        except Exception:
            pass
        raise UserError(message) from exc
    except urllib.error.URLError as exc:
        raise UserError("management API connection failed") from exc
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UserError("management API returned invalid JSON") from exc


def reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def usage_api_request(key_id: str, key: str) -> object:
    query = urllib.parse.urlencode({"id": key_id})
    request = urllib.request.Request(
        BASE_URL + "/keys/usage?" + query,
        method="GET",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())
    try:
        with opener.open(request, timeout=USAGE_TIMEOUT_SECONDS) as response:
            status_code = getattr(response, "status", 200)
            if type(status_code) is not int or status_code < 200 or status_code >= 300:
                raise UserError("usage API returned an unsuccessful status")
            declared_length: int | None = None
            length_value = response.headers.get("Content-Length")
            if length_value is not None:
                length_value = length_value.strip()
                if not re.fullmatch(r"[0-9]+", length_value):
                    raise UserError("usage API returned an invalid Content-Length")
                declared_length = int(length_value)
                if declared_length > USAGE_MAX_RESPONSE:
                    raise UserError("usage API response exceeded 64 KiB")
            raw = response.read(USAGE_MAX_RESPONSE + 1)
            if len(raw) > USAGE_MAX_RESPONSE:
                raise UserError("usage API response exceeded 64 KiB")
            if declared_length is not None and len(raw) != declared_length:
                raise UserError("usage API response was truncated")
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        exc.close()
        raise UserError(f"usage API returned HTTP {status_code}") from exc
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException, OSError) as exc:
        raise UserError("usage API connection failed") from exc
    try:
        return json.loads(raw, parse_float=Decimal, parse_constant=reject_nonfinite_json)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise UserError("usage API returned invalid JSON") from exc


def read_usage_request() -> dict:
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(raw) > MAX_STDIN:
        raise UserError("usage request exceeded 64 KiB")
    try:
        request = json.loads(raw, parse_constant=reject_nonfinite_json)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise UserError("usage request is invalid JSON") from exc
    if not isinstance(request, dict) or set(request) != {"version", "keys"}:
        raise UserError("usage request has an unsupported shape")
    if type(request["version"]) is not int or request["version"] != 1:
        raise UserError("usage request has an unsupported version")
    keys = request["keys"]
    if not isinstance(keys, list) or len(keys) != 2:
        raise UserError("usage request must contain exactly two keys")
    seen_kinds: set[str] = set()
    seen_ids: set[str] = set()
    for item in keys:
        if not isinstance(item, dict) or set(item) != {"kind", "key_id"}:
            raise UserError("usage request key has an unsupported shape")
        kind = item["kind"]
        key_id = item["key_id"]
        if not isinstance(kind, str) or kind not in USAGE_PROVIDERS or kind in seen_kinds:
            raise UserError("usage request kind is invalid or duplicated")
        if not isinstance(key_id, str) or not ID_RE.fullmatch(key_id) or key_id in seen_ids:
            raise UserError("usage request key id is invalid or duplicated")
        seen_kinds.add(kind)
        seen_ids.add(key_id)
    if seen_kinds != set(USAGE_PROVIDERS):
        raise UserError("usage request must contain ChatGPT and Kimi keys")
    return request


def usage_decimal(value: object, field: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise UserError(f"usage response {field} is not a decimal number")
    result = value if isinstance(value, Decimal) else Decimal(str(value))
    if not result.is_finite() or result < 0:
        raise UserError(f"usage response {field} is invalid")
    return result


def require_usage_timestamp(value: object) -> None:
    if not isinstance(value, str) or len(value) > 64 or "T" not in value:
        raise UserError("usage response window_start is invalid")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UserError("usage response window_start is invalid") from exc
    if parsed.tzinfo is None:
        raise UserError("usage response window_start is invalid")


def validate_usage_window(value: object) -> tuple[Decimal, datetime.datetime]:
    if not isinstance(value, dict):
        raise UserError("usage response window is invalid")
    fields = set(value)
    allowed = USAGE_WINDOW_REQUIRED_FIELDS | USAGE_WINDOW_OPTIONAL_FIELDS
    if not USAGE_WINDOW_REQUIRED_FIELDS.issubset(fields) or not fields.issubset(allowed):
        raise UserError("usage response window has unsupported fields")
    for field in ("call_count", "input_tokens", "output_tokens"):
        if field in value and (type(value[field]) is not int or value[field] < 0):
            raise UserError(f"usage response {field} is invalid")
    if "cache_read_tokens" in value and (type(value["cache_read_tokens"]) is not int or value["cache_read_tokens"] < 0):
        raise UserError("usage response cache_read_tokens is invalid")
    if "cache_cost_usd" in value:
        usage_decimal(value["cache_cost_usd"], "cache_cost_usd")
    require_usage_timestamp(value["window_start"])
    window_start = datetime.datetime.fromisoformat(value["window_start"].replace("Z", "+00:00"))
    return usage_decimal(value["total_usd"], "total_usd"), window_start


def key_usage_summaries(response: object, expected_ids: set[str]) -> dict[str, dict]:
    if not isinstance(response, dict) or set(response) != {"keys"} or not isinstance(response["keys"], list):
        raise UserError("key usage summary response is invalid")
    result: dict[str, dict] = {}
    for item in response["keys"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise UserError("key usage summary entry is invalid")
        key_id = item["id"]
        if key_id not in expected_ids:
            continue
        if key_id in result:
            raise UserError("key usage summary is duplicated")
        aliases = item.get("aliases")
        models = item.get("models")
        if not isinstance(aliases, list) or not aliases or not isinstance(models, list) or not models:
            raise UserError("key usage authorization is invalid")
        configured_aliases: set[str] = set()
        model_aliases: set[str] = set()
        model_providers: set[str] = set()
        for alias in aliases:
            if not isinstance(alias, dict) or set(alias) != {"alias"} or not isinstance(alias["alias"], str) or not ALIAS_RE.fullmatch(alias["alias"]):
                raise UserError("key usage aliases are invalid")
            configured_aliases.add(alias["alias"])
        for model in models:
            if not isinstance(model, dict) or not isinstance(model.get("alias"), str) or not isinstance(model.get("provider"), str):
                raise UserError("key usage models are invalid")
            model_aliases.add(model["alias"])
            model_providers.add(model["provider"])
        if len(configured_aliases) != len(aliases) or len(model_aliases) != len(models) or model_aliases != configured_aliases or len(model_providers) != 1:
            raise UserError("key usage authorization is inconsistent")
        summary = item.get("usage")
        if not isinstance(summary, dict) or not USAGE_SUMMARY_REQUIRED_FIELDS.issubset(summary):
            raise UserError("key usage summary is invalid")
        daily_limit = usage_decimal(summary["daily_limit_usd"], "daily_limit_usd")
        weekly_limit = usage_decimal(summary["weekly_limit_usd"], "weekly_limit_usd")
        if daily_limit != usage_decimal(item.get("daily_limit_usd"), "daily_limit_usd") or weekly_limit != usage_decimal(item.get("weekly_limit_usd"), "weekly_limit_usd"):
            raise UserError("key usage summary limits do not match the key")
        daily_used = usage_decimal(summary["daily_usd"], "daily_usd")
        weekly_used = usage_decimal(summary["weekly_usd"], "weekly_usd")
        require_usage_timestamp(summary["daily_reset_at"])
        weekly_reset = summary.get("weekly_reset_at")
        if not weekly_reset:
            raise UserError("key usage weekly reset time is missing")
        require_usage_timestamp(weekly_reset)
        result[key_id] = {
            "daily_limit": daily_limit,
            "weekly_limit": weekly_limit,
            "daily_used": daily_used,
            "weekly_used": weekly_used,
            "daily_reset": summary["daily_reset_at"],
            "weekly_reset": weekly_reset,
            "aliases": configured_aliases,
            "providers": model_providers,
        }
    if set(result) != expected_ids:
        raise UserError("key usage summary is missing")
    return result


def decimal_text(value: Decimal) -> str:
    return "0" if value == 0 else format(value, "f")


def validate_ed25519_public_key(value: object) -> str:
    if not isinstance(value, str):
        raise UserError("usage public key is invalid")
    match = USAGE_KEY_RE.fullmatch(value)
    if match is None:
        raise UserError("usage public key is invalid")
    try:
        blob = base64.b64decode(match.group(1), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UserError("usage public key is invalid") from exc
    algorithm = b"ssh-ed25519"
    expected = len(algorithm).to_bytes(4, "big") + algorithm + (32).to_bytes(4, "big")
    if len(blob) != len(expected) + 32 or not blob.startswith(expected):
        raise UserError("usage public key is invalid")
    return value


def read_usage_public_key_request() -> str:
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(raw) > MAX_STDIN:
        raise UserError("usage public key request exceeded 64 KiB")
    try:
        request = json.loads(raw, parse_constant=reject_nonfinite_json)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise UserError("usage public key request is invalid JSON") from exc
    if not isinstance(request, dict) or set(request) != {"version", "public_key"} or type(request["version"]) is not int or request["version"] != 1:
        raise UserError("usage public key request has an unsupported shape")
    return validate_ed25519_public_key(request["public_key"])


def install_usage_key() -> None:
    public_key = read_usage_public_key_request()
    ssh_root = AUTHORIZED_KEYS_PATH.parent
    private_root_directory(ssh_root)
    if AUTHORIZED_KEYS_PATH.exists():
        private_root_file(AUTHORIZED_KEYS_PATH)
        raw = AUTHORIZED_KEYS_PATH.read_bytes()
        if len(raw) > AUTHORIZED_KEYS_MAX_SIZE:
            raise UserError("authorized_keys exceeded 1 MiB")
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise UserError("authorized_keys is not valid UTF-8") from exc
    else:
        lines = []
    preserved = [line for line in lines if not MANAGED_USAGE_KEY_RE.fullmatch(line)]
    helper_path = (ROOT / "cpa-key-policy-admin.py").as_posix()
    forced = f'restrict,command="{helper_path} usage" {public_key}'
    atomic_write(AUTHORIZED_KEYS_PATH, ("\n".join(preserved + [forced]) + "\n").encode("utf-8"), 0o600)
    private_root_file(AUTHORIZED_KEYS_PATH)
    installed = AUTHORIZED_KEYS_PATH.read_text(encoding="utf-8").splitlines()
    if installed.count(forced) != 1 or sum(1 for line in installed if MANAGED_USAGE_KEY_RE.fullmatch(line)) != 1:
        raise UserError("usage public key verification failed")
    print(json.dumps({"status": "ready", "usage_key": "installed"}, separators=(",", ":")))


def summarize_usage(kind: str, key_id: str, response: object, summary: dict) -> dict:
    if not isinstance(response, dict) or set(response) != USAGE_RESPONSE_FIELDS:
        raise UserError("usage API response has unsupported fields")
    if response["key_id"] != key_id:
        raise UserError("usage API returned a different key")
    if not isinstance(response["key_name"], str):
        raise UserError("usage API key name is invalid")
    daily_limit = usage_decimal(response["daily_limit_usd"], "daily_limit_usd")
    weekly_limit = usage_decimal(response["weekly_limit_usd"], "weekly_limit_usd")
    if daily_limit != summary["daily_limit"] or weekly_limit != summary["weekly_limit"]:
        raise UserError("usage API limits do not match the key summary")
    aliases = response["aliases"]
    if not isinstance(aliases, list) or not aliases:
        raise UserError("usage API aliases are invalid")
    expected_provider = USAGE_PROVIDERS[kind]
    if summary["providers"] != {expected_provider}:
        raise UserError("key usage provider does not match requested kind")
    seen_aliases: set[str] = set()
    configured_aliases: set[str] = set()
    for alias in aliases:
        if not isinstance(alias, dict) or type(alias.get("in_config")) is not bool:
            raise UserError("usage API alias has unsupported fields")
        expected_fields = USAGE_CONFIGURED_ALIAS_FIELDS if alias["in_config"] else USAGE_ALIAS_FIELDS
        if set(alias) != expected_fields:
            raise UserError("usage API alias has unsupported fields")
        if not isinstance(alias["alias"], str) or not ALIAS_RE.fullmatch(alias["alias"]):
            raise UserError("usage API alias is invalid")
        if alias["alias"] in seen_aliases:
            raise UserError("usage API returned a duplicated alias")
        seen_aliases.add(alias["alias"])
        if alias["in_config"]:
            for field in ("billing_mode", "provider", "target_model"):
                if not isinstance(alias[field], str) or not alias[field]:
                    raise UserError(f"usage API alias {field} is invalid")
            if alias["provider"] != expected_provider:
                raise UserError("usage API provider does not match requested kind")
            configured_aliases.add(alias["alias"])
        validate_usage_window(alias["daily"])
        validate_usage_window(alias["weekly"])
    if configured_aliases != summary["aliases"]:
        raise UserError("usage API configured aliases do not match the key")
    return {
        "kind": kind,
        "daily": {
            "limit_usd": decimal_text(daily_limit),
            "used_usd": decimal_text(summary["daily_used"]),
            "reset_at": summary["daily_reset"],
        },
        "weekly": {
            "limit_usd": decimal_text(weekly_limit),
            "used_usd": decimal_text(summary["weekly_used"]),
            "reset_at": summary["weekly_reset"],
        },
    }


def read_provision_request() -> dict:
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(raw) > MAX_STDIN:
        raise UserError("provision request exceeded 64 KiB")
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UserError("provision request is invalid JSON") from exc
    if not isinstance(request, dict) or set(request) != {"version", "keys"} or request["version"] != 1:
        raise UserError("provision request has an unsupported shape or version")
    keys = request["keys"]
    if not isinstance(keys, list) or len(keys) != 2:
        raise UserError("provision request must contain exactly two keys")
    seen: set[str] = set()
    for item in keys:
        required = {"id", "name", "enabled", "rpm", "aliases", "daily_limit_usd", "weekly_limit_usd", "allow_models_endpoint"}
        if not isinstance(item, dict) or set(item) != required:
            raise UserError("provision key has an unsupported shape")
        if not isinstance(item["id"], str) or not ID_RE.fullmatch(item["id"]) or item["id"] in seen:
            raise UserError("provision key id is invalid or duplicated")
        seen.add(item["id"])
        if not isinstance(item["name"], str) or not item["name"].strip() or len(item["name"]) > 128 or any(ord(c) < 32 for c in item["name"]):
            raise UserError("provision key name is invalid")
        if item["enabled"] is not True or item["allow_models_endpoint"] is not True:
            raise UserError("employee keys must be enabled with the per-key models endpoint")
        if type(item["rpm"]) is not int or item["rpm"] < 0 or item["rpm"] > 100000:
            raise UserError("provision key rpm is invalid")
        for field in ("daily_limit_usd", "weekly_limit_usd"):
            if type(item[field]) not in (int, float) or item[field] <= 0 or item[field] > 100000:
                raise UserError(f"provision key {field} is invalid")
        if item["daily_limit_usd"] * 2 != item["weekly_limit_usd"]:
            raise UserError("daily limit must be exactly half the weekly limit")
        aliases = item["aliases"]
        if not isinstance(aliases, list) or not aliases or len(aliases) > 64 or any(not isinstance(a, str) or not ALIAS_RE.fullmatch(a) for a in aliases):
            raise UserError("provision key aliases are invalid")
        if len({a.lower() for a in aliases}) != len(aliases):
            raise UserError("provision key aliases are duplicated")
    return request


def key_models(alias_names: list[str], catalog: dict[str, dict]) -> list[dict]:
    models: list[dict] = []
    for requested in alias_names:
        alias = catalog.get(requested.lower())
        if alias is None:
            raise UserError(f"requested alias is not configured: {requested}")
        targets = alias.get("targets")
        if not isinstance(targets, list) or not targets:
            raise UserError(f"configured alias has no targets: {requested}")
        for target in targets:
            if not isinstance(target, dict) or not isinstance(target.get("provider"), str) or not isinstance(target.get("target_model"), str):
                raise UserError(f"configured alias has an invalid target: {requested}")
            model = {
                "alias": alias["alias"],
                "provider": target["provider"],
                "target_model": target["target_model"],
                "billing_mode": alias.get("billing_mode", "tokens"),
                "input_price_per_million": alias.get("input_price_per_million", 0),
                "output_price_per_million": alias.get("output_price_per_million", 0),
                "cache_read_price_per_million": alias.get("cache_read_price_per_million", 0),
                "per_call_usd": alias.get("per_call_usd", 0) or 0,
            }
            if target.get("group"):
                model["group"] = target["group"]
            models.append(model)
    return models


def comparable_models(models: object) -> set[tuple[str, str, str, str]]:
    if not isinstance(models, list):
        return set()
    result = set()
    for model in models:
        if not isinstance(model, dict):
            return set()
        result.add((str(model.get("alias", "")).lower(), str(model.get("provider", "")).lower(), str(model.get("target_model", "")).lower(), str(model.get("group", "")).lower()))
    return result


def verify_key(actual: dict, desired: dict) -> None:
    for field in ("id", "name", "enabled", "rpm"):
        if actual.get(field) != desired.get(field):
            raise UserError(f"key verification failed for {desired['id']}: {field}")
    if bool(actual.get("allow_models_endpoint", False)) != desired["allow_models_endpoint"]:
        raise UserError(f"key verification failed for {desired['id']}: allow_models_endpoint")
    for field in ("daily_limit_usd", "weekly_limit_usd"):
        if float(actual.get(field, 0)) != float(desired[field]):
            raise UserError(f"key verification failed for {desired['id']}: {field}")
    if comparable_models(actual.get("models")) != comparable_models(desired.get("models")):
        raise UserError(f"key verification failed for {desired['id']}: models")


def provision() -> None:
    private_root_file(CONFIG_PATH)
    require_remote_management_disabled(CONFIG_PATH.read_text(encoding="utf-8").splitlines())
    request = read_provision_request()
    aliases_response = api_request("/aliases", "GET", None)
    aliases = aliases_response.get("aliases") if isinstance(aliases_response, dict) else None
    if not isinstance(aliases, list):
        raise UserError("alias catalog response is invalid")
    catalog = {str(alias.get("alias", "")).lower(): alias for alias in aliases if isinstance(alias, dict) and alias.get("alias")}

    listed = api_request("/keys", "GET", None)
    existing_list = listed.get("keys") if isinstance(listed, dict) else None
    if not isinstance(existing_list, list):
        raise UserError("key list response is invalid")
    existing = {str(item.get("id", "")): item for item in existing_list if isinstance(item, dict)}
    results: list[dict] = []
    desired_by_id: dict[str, dict] = {}
    for item in request["keys"]:
        desired = {key: value for key, value in item.items() if key != "aliases"}
        desired["models"] = key_models(item["aliases"], catalog)
        desired_by_id[desired["id"]] = desired
        if desired["id"] in existing:
            api_request("/keys", "PATCH", desired)
            rotated = api_request("/keys/rotate", "POST", {"id": desired["id"]})
            action = "rotated"
            response = rotated
        else:
            response = api_request("/keys", "POST", desired)
            action = "created"
        plain_key = response.get("plain_key") if isinstance(response, dict) else None
        if not isinstance(plain_key, str) or not CPA_KEY_RE.fullmatch(plain_key):
            raise UserError(f"management API did not return a valid one-time key for {desired['id']}")
        results.append({"id": desired["id"], "plain_key": plain_key, "action": action})

    verified_response = api_request("/keys", "GET", None)
    verified_list = verified_response.get("keys") if isinstance(verified_response, dict) else None
    if not isinstance(verified_list, list):
        raise UserError("post-provision key list response is invalid")
    verified = {str(item.get("id", "")): item for item in verified_list if isinstance(item, dict)}
    for key_id, desired in desired_by_id.items():
        if key_id not in verified:
            raise UserError(f"provisioned key is missing during verification: {key_id}")
        verify_key(verified[key_id], desired)
    print(json.dumps({"version": 1, "keys": results}, separators=(",", ":")))


def usage() -> None:
    private_root_file(CONFIG_PATH)
    require_remote_management_disabled(CONFIG_PATH.read_text(encoding="utf-8").splitlines())
    request = read_usage_request()
    key = read_management_key()
    summaries = key_usage_summaries(api_request("/keys", "GET", None, key), {item["key_id"] for item in request["keys"]})
    providers: dict[str, dict] = {}
    for item in request["keys"]:
        response = usage_api_request(item["key_id"], key)
        providers[item["kind"]] = summarize_usage(item["kind"], item["key_id"], response, summaries[item["key_id"]])
    as_of = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    output = {
        "version": 1,
        "as_of": as_of,
        "providers": [providers["chatgpt"], providers["kimi"]],
    }
    print(json.dumps(output, separators=(",", ":")))


def status() -> None:
    private_root_file(CONFIG_PATH)
    require_remote_management_disabled(CONFIG_PATH.read_text(encoding="utf-8").splitlines())
    keys = api_request("/keys", "GET", None)
    aliases = api_request("/aliases", "GET", None)
    key_count = len(keys.get("keys", [])) if isinstance(keys, dict) and isinstance(keys.get("keys"), list) else -1
    alias_count = len(aliases.get("aliases", [])) if isinstance(aliases, dict) and isinstance(aliases.get("aliases"), list) else -1
    if key_count < 0 or alias_count < 0:
        raise UserError("management status response is invalid")
    catalog = {str(alias.get("alias", "")).lower(): alias for alias in aliases["aliases"] if isinstance(alias, dict) and alias.get("alias")}
    verify_managed_aliases(catalog)
    print(json.dumps({"status": "ready", "key_count": key_count, "alias_count": alias_count}, separators=(",", ":")))


def main() -> int:
    try:
        require_root()
        if len(sys.argv) != 2 or sys.argv[1] not in {"bootstrap", "install-usage-key", "provision", "status", "usage"}:
            raise UserError("usage: cpa-key-policy-admin.py <bootstrap|install-usage-key|provision|status|usage>")
        {"bootstrap": bootstrap, "install-usage-key": install_usage_key, "provision": provision, "status": status, "usage": usage}[sys.argv[1]]()
        return 0
    except (UserError, OSError, subprocess.SubprocessError) as exc:
        print("FAILED: " + safe_message(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
