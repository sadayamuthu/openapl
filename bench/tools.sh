#!/bin/sh
# bench/tools.sh
# Builds (Cedar) or pulls (OPA) the pinned engine images used by bench/bin/{cedar,opa},
# prints their versions, and records versions and image digests under `tools` in
# bench/results/env.json (other top-level keys are kept). Images are never pushed.
set -eu
cd "$(dirname "$0")/.."
CEDAR_IMAGE=openapl-bench/cedar:4.15.0
OPA_IMAGE=openpolicyagent/opa:1.22.4-static
OPA_PINNED=openpolicyagent/opa@sha256:12cecac5a174368f7d3f09d3a19d040ebe0c91d576e520335ae7a985a26e39d3

docker build -q -f bench/tools/cedar.Dockerfile -t "$CEDAR_IMAGE" bench/tools >/dev/null
docker pull -q "$OPA_PINNED" >/dev/null
docker tag "$OPA_PINNED" "$OPA_IMAGE"

CEDAR_VERSION=$(bench/bin/cedar --version)
OPA_VERSION=$(bench/bin/opa version | sed -n 's/^Version: //p')
CEDAR_ID=$(docker image inspect --format '{{.Id}}' "$CEDAR_IMAGE")
OPA_ID=$(docker image inspect --format '{{.Id}}' "$OPA_IMAGE")
OPA_DIGEST=$(docker image inspect --format '{{index .RepoDigests 0}}' "$OPA_IMAGE")
BASES=$(sed -n 's/^FROM \([^ ]*\).*/\1/p' bench/tools/cedar.Dockerfile | paste -sd, -)
echo "cedar: $CEDAR_VERSION ($CEDAR_IMAGE $CEDAR_ID, bases $BASES)"
echo "opa:   $OPA_VERSION ($OPA_DIGEST $OPA_ID)"

CEDAR_VERSION="$CEDAR_VERSION" OPA_VERSION="$OPA_VERSION" CEDAR_IMAGE="$CEDAR_IMAGE" \
CEDAR_ID="$CEDAR_ID" OPA_IMAGE="$OPA_IMAGE" OPA_ID="$OPA_ID" OPA_DIGEST="$OPA_DIGEST" \
BASES="$BASES" python3 - <<'PY'
import json, os
from pathlib import Path
path = Path("bench/results/env.json")
env = json.loads(path.read_text()) if path.is_file() else {}
e = os.environ
env["tools"] = {
    "command": "sh bench/tools.sh",
    "cedar": {"version": e["CEDAR_VERSION"], "image": e["CEDAR_IMAGE"],
              "image_id": e["CEDAR_ID"], "build": "bench/tools/cedar.Dockerfile",
              "base_images": e["BASES"].split(","),
              "install": "cargo install cedar-policy-cli --version 4.15.0 --locked"},
    "opa": {"version": e["OPA_VERSION"], "image": e["OPA_IMAGE"], "image_id": e["OPA_ID"],
            "repo_digest": e["OPA_DIGEST"], "wrapper_image": e["OPA_DIGEST"]},
}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(env, indent=2) + "\n")
PY
