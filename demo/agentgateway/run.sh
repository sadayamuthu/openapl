#!/usr/bin/env bash
# demo/agentgateway/run.sh: run the full OpenAPL x agentgateway demo. Needs docker compose v2 and a
# Python env with the SDK, sidecar and demo requirements (default: sidecar/.venv, else python3).
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if [ -x ../../sidecar/.venv/bin/python ]; then PY=../../sidecar/.venv/bin/python; else PY=python3; fi
fi

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
# On failure, keep the container logs in out/ (uploaded by CI) before teardown.
on_exit() {
  rc=$?
  if [ "$rc" -ne 0 ] && [ -d out ]; then docker compose logs --no-color > out/compose.log 2>&1 || true; fi
  cleanup
  exit "$rc"
}
trap on_exit EXIT

# 0. tear down anything left by a killed run (port 3000, stale mounts)
cleanup

# 1. recreate out/ (0777: the sidecar runs as uid 10001). Containers on Linux may leave root-owned
#    files in it, so fall back to deleting it from a throwaway container.
if [ -e out ]; then
  rm -rf out 2>/dev/null || docker run --rm -v "$PWD:/w" python:3.11.11-slim rm -rf /w/out
fi
mkdir out
chmod 0777 out

# 2. keys
"$PY" issuer.py keys out/

# 3. stack
docker compose up -d --build --wait

# 4. scenarios (the runner exits non-zero on any mismatch)
"$PY" run_scenarios.py --base-url http://127.0.0.1:3000/mcp --out out/ --scenarios scenarios.yaml
