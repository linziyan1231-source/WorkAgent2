#!/usr/bin/env bash
set -euo pipefail

umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runtime_root="${1:-$repo_root/.tools/artifacts/workagent-runtime-linux-x64}"
evidence_file="${RUNTIME_SMOKE_EVIDENCE:-$repo_root/.tools/logs/workagent-runtime-integrated-smoke.log}"
smoke_root=""
web_pid=""
backend_pid=""
filter_pid=""

fail() {
  printf 'smoke-runtime-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

cleanup() {
  if [[ -n "$web_pid" ]] && kill -0 "$web_pid" 2>/dev/null; then
    kill -TERM "$web_pid" 2>/dev/null || true
    for _ in {1..50}; do
      kill -0 "$web_pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$web_pid" 2>/dev/null || true
    wait "$web_pid" 2>/dev/null || true
  fi
  if [[ -n "$backend_pid" ]] && kill -0 "$backend_pid" 2>/dev/null; then
    kill -KILL "$backend_pid" 2>/dev/null || true
  fi
  if [[ -n "$filter_pid" ]] && kill -0 "$filter_pid" 2>/dev/null; then
    kill -TERM "$filter_pid" 2>/dev/null || true
    wait "$filter_pid" 2>/dev/null || true
  fi
  if [[ -n "$smoke_root" ]]; then
    case "$smoke_root" in
      /tmp/workagent-runtime-smoke.*) [[ ! -e "$smoke_root" ]] || rm -rf -- "$smoke_root" ;;
      *) printf 'smoke-runtime-linux: refusing unsafe cleanup path: %s\n' "$smoke_root" >&2 ;;
    esac
  fi
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'smoke target must be Linux x86_64'
for command in chmod curl cut env find grep install kill mkdir mkfifo mktemp pgrep readlink realpath rm sed sha256sum sleep tail; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ "$runtime_root" == /* && -d "$runtime_root" && ! -L "$runtime_root" ]] || fail 'runtime root must be an absolute real directory'
[[ "$(realpath -m -- "$runtime_root")" == "$runtime_root" ]] || fail 'runtime root must be canonical'
[[ "$evidence_file" == /* && "$evidence_file" == "$(realpath -m -- "$evidence_file")" ]] || fail 'evidence path must be absolute and canonical'
[[ ! -e "$evidence_file" && ! -L "$evidence_file" ]] || fail "evidence file already exists: $evidence_file"
for required in bin/aionui-web bin/aioncore share/workagent-components/runtime/SHA256SUMS; do
  [[ -f "$runtime_root/$required" && ! -L "$runtime_root/$required" ]] || fail "runtime file is missing: $required"
done
(cd "$runtime_root" && sha256sum --strict --check share/workagent-components/runtime/SHA256SUMS) >/dev/null || fail 'runtime checksums failed'

smoke_root="$(mktemp -d /tmp/workagent-runtime-smoke.XXXXXX)"
trap cleanup EXIT INT TERM
mkdir -m 0700 -- "$smoke_root/home" "$smoke_root/home/.codex" "$smoke_root/data" "$smoke_root/logs" "$smoke_root/work"
raw_pipe="$smoke_root/aionui.pipe"
sanitized_log="$smoke_root/aionui.sanitized.log"
mkfifo -m 0600 -- "$raw_pipe"

# The first launch creates an admin password. Sanitize it before any byte is
# written to disk; only this redacted stream may become retained evidence.
sed -u -E \
  -e 's#(Generated initial admin password:).*#\1 [REDACTED]#' \
  -e 's#(\[aionui-web\] new password:).*#\1 [REDACTED]#' \
  < "$raw_pipe" > "$sanitized_log" &
filter_pid=$!

env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
  HOME="$smoke_root/home" CODEX_HOME="$smoke_root/home/.codex" \
  XDG_CACHE_HOME="$smoke_root/home/.cache" XDG_CONFIG_HOME="$smoke_root/home/.config" \
  AIONUI_OPEN_BROWSER=0 AIONUI_LOG_LEVEL=info \
  "$runtime_root/bin/aionui-web" start --port 0 --no-open \
  --data-dir "$smoke_root/data" --log-dir "$smoke_root/logs" --work-dir "$smoke_root/work" \
  --static-dir "$runtime_root/static" --backend-bin "$runtime_root/bin/aioncore" \
  > "$raw_pipe" 2>&1 &
web_pid=$!

ready=0
for _ in {1..600}; do
  if grep -F 'AionUi WebUI is ready' "$sanitized_log" >/dev/null 2>&1; then
    ready=1
    break
  fi
  kill -0 "$web_pid" 2>/dev/null || break
  sleep 0.1
done
if [[ "$ready" != 1 ]]; then
  grep -v -E 'password:' "$sanitized_log" | tail -n 120 >&2 || true
  fail 'AionUi integrated startup did not become ready'
fi

frontend_port="$(sed -n 's#^  Local  : http://127\.0\.0\.1:\([0-9][0-9]*\)/\?$#\1#p' "$sanitized_log" | tail -n 1)"
backend_port="$(sed -n 's#^\[aioncore\] AIONCORE_LISTENING {"host":"127\.0\.0\.1","port":\([0-9][0-9]*\)}.*$#\1#p' "$sanitized_log" | tail -n 1)"
[[ "$frontend_port" =~ ^[1-9][0-9]*$ && "$frontend_port" -le 65535 ]] || fail 'frontend port evidence is invalid'
[[ "$backend_port" =~ ^[1-9][0-9]*$ && "$backend_port" -le 65535 ]] || fail 'backend port evidence is invalid'

backend_pids=()
while IFS= read -r candidate_pid; do
  if [[ -n "$candidate_pid" && "$(readlink -f "/proc/$candidate_pid/exe" 2>/dev/null || true)" == "$runtime_root/bin/aioncore" ]]; then
    backend_pids+=("$candidate_pid")
  fi
done < <(pgrep -P "$web_pid" || true)
[[ "${#backend_pids[@]}" == 1 ]] || fail "expected one AionCore child, found ${#backend_pids[@]}"
backend_pid="${backend_pids[0]}"
[[ "$(readlink -f "/proc/$backend_pid/exe")" == "$runtime_root/bin/aioncore" ]] || fail 'AionCore child executable path mismatch'
[[ "$(hash_of "/proc/$backend_pid/exe")" == "$(hash_of "$runtime_root/bin/aioncore")" ]] || fail 'AionCore child executable checksum mismatch'

frontend_status="$(curl --noproxy '*' --silent --show-error --max-time 10 -o "$smoke_root/frontend-health" -w '%{http_code}' "http://127.0.0.1:$frontend_port/healthz")"
[[ "$frontend_status" == 200 ]] || fail "frontend readiness returned HTTP $frontend_status"
grep -E -i '<!doctype html>|<html' "$smoke_root/frontend-health" >/dev/null || fail 'frontend /healthz is not the expected SPA fallback'

auth_status="$(curl --noproxy '*' --silent --show-error --max-time 10 -o "$smoke_root/auth-status.json" -w '%{http_code}' "http://127.0.0.1:$frontend_port/api/auth/status")"
[[ "$auth_status" == 200 ]] || fail "proxied auth status returned HTTP $auth_status"
managed_node="$runtime_root/bin/managed-resources/node/node-v24.11.0-linux-x64/bin/node"
"$managed_node" -e 'const fs=require("fs");const v=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(v===null||typeof v!=="object"||Array.isArray(v))process.exit(1)' \
  "$smoke_root/auth-status.json" || fail 'proxied auth status is not a JSON object'

health_json="$(curl --noproxy '*' --fail --silent --show-error --max-time 10 "http://127.0.0.1:$backend_port/health")"
[[ "$health_json" == '{"status":"ok","version":"0.1.42-editfork.15","build_time":"1785418200"}' ]] || fail "backend health response mismatch: $health_json"

kill -TERM "$web_pid"
web_status=0
wait "$web_pid" || web_status=$?
web_pid=""
[[ "$web_status" == 0 ]] || fail "AionUi exited with status $web_status after SIGTERM"
wait "$filter_pid"
filter_pid=""
for _ in {1..100}; do
  kill -0 "$backend_pid" 2>/dev/null || break
  sleep 0.1
done
kill -0 "$backend_pid" 2>/dev/null && fail 'AionCore child survived AionUi shutdown'
backend_pid=""
grep -F '[aionui-web] received SIGTERM, stopping...' "$sanitized_log" >/dev/null || fail 'AionUi graceful shutdown evidence is missing'
grep -F 'Server shut down gracefully' "$sanitized_log" >/dev/null || fail 'AionCore graceful shutdown evidence is missing'
if grep -F 'Generated initial admin password:' "$sanitized_log" | \
  grep -vF 'Generated initial admin password: [REDACTED]' >/dev/null; then
  fail 'unsanitized generated password reached evidence'
fi
if grep -F '[aionui-web] new password:' "$sanitized_log" | \
  grep -vF '[aionui-web] new password: [REDACTED]' >/dev/null; then
  fail 'unsanitized reset password reached evidence'
fi

mkdir -p -- "$(dirname "$evidence_file")"
install -m 0600 -- "$sanitized_log" "$evidence_file"
printf 'WorkAgent runtime integrated smoke: PASS\n'
printf 'Frontend readiness: HTTP 200 SPA fallback\n'
printf 'Backend proxy auth status: HTTP 200 JSON object\n'
printf 'Backend health: %s\n' "$health_json"
printf 'Process identity and graceful parent/child shutdown: PASS\n'
printf 'Sanitized evidence: %s\n' "$evidence_file"
