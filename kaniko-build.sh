#!/bin/bash
# Build dynamic-pac image in-cluster via Kaniko and push to zot.
# Tags the image with the short commit SHA and also as :latest.
#
# Usage: ./kaniko-build.sh [sha]
#   If sha is omitted, uses the current HEAD's short SHA.
#
# Prerequisites:
#   - kubectl context points to the K3s cluster
#   - The repo is pushed to Soft Serve (origin remote) and is up to date
#   - kaniko-project/executor:latest is cached in zot (under library/)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Determine SHA
if [ "$#" -ge 1 ]; then
  SHORT_SHA="$1"
else
  SHORT_SHA="$(git rev-parse --short HEAD)"
fi

echo "==> Building skyline/dynamic-pac:${SHORT_SHA} (also :latest)"

# Push HEAD to Soft Serve so the initContainer can clone it
echo "==> Pushing to Soft Serve..."
git push origin HEAD:master

# Build the Job YAML with SHA substituted
JOB_NAME="kaniko-build-dynamic-pac-${SHORT_SHA}"
TMPFILE="$(mktemp)"

sed "s/SHORT_SHA/${SHORT_SHA}/g" kaniko-build.yaml > "$TMPFILE"

echo "==> Applying Kaniko Job: ${JOB_NAME}"
kubectl apply -f "$TMPFILE" --namespace=dynamic-pac
rm -f "$TMPFILE"

# Wait for pod to appear
echo "==> Waiting for pod..."
for i in $(seq 1 30); do
  POD_NAME="$(kubectl get pods -n dynamic-pac -l job-name="${JOB_NAME}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -n "$POD_NAME" ]; then
    break
  fi
  sleep 2
done

if [ -z "$POD_NAME" ]; then
  echo "ERROR: pod didn't start within 60s"
  kubectl describe job -n dynamic-pac "${JOB_NAME}"
  exit 1
fi

# Wait for init container to finish, then wait for kaniko container to start
echo "==> Waiting for init container (clone) to finish..."
kubectl wait -n dynamic-pac --for=condition=Initialized "pod/${POD_NAME}" --timeout=120s

echo "==> Waiting for kaniko container to start..."
kubectl wait -n dynamic-pac --for=condition=ContainersReady "pod/${POD_NAME}" --timeout=300s

echo "==> Build logs:"
kubectl logs -n dynamic-pac "$POD_NAME" -c kaniko --follow || true

# Wait for job to settle and check status
echo ""
sleep 3
JOB_STATUS="$(kubectl get job -n dynamic-pac "${JOB_NAME}" -o jsonpath='{.status.conditions[0].type}' 2>/dev/null || echo 'Unknown')"
echo "==> Job status: ${JOB_STATUS}"

if echo "${JOB_STATUS}" | grep -qiE "Complete|Success"; then
  echo "==> Verifying image in zot:"
  curl -sI "http://192.168.1.206:5000/v2/skyline/dynamic-pac/manifests/${SHORT_SHA}" | head -3
  echo ""
  echo "==> ✅ Build complete: skyline/dynamic-pac:${SHORT_SHA}"
  echo "    (Job auto-deletes in 10 min via ttlSecondsAfterFinished)"
else
  echo "==> ❌ Build failed — check logs above"
  exit 1
fi
