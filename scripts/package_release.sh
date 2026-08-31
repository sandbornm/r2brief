#!/usr/bin/env bash
# Build GitHub Release artifacts into dist/.
#   ./scripts/package_release.sh
#   SKIP_FRONTEND=1 ./scripts/package_release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"

VERSION="$(uv run --python 3.11 python - <<'PY'
import pathlib, tomllib
print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])
PY
)"
TAG="v${VERSION}"

mkdir -p dist
# Keep previously built wheels only from this run.
find dist -maxdepth 1 -type f -delete

echo "[*] frontend bundle for wheel"
(cd web/frontend && npm ci && npm run build)

echo "[*] uv build ${TAG}"
uv build

if [[ "$SKIP_FRONTEND" != "1" ]]; then
  echo "[*] standalone frontend archive"
  tar -czf "dist/r2b-frontend-${TAG}.tar.gz" -C web/frontend dist
fi

echo "[*] contracts + installer"
tar -czf "dist/r2b-contracts-${TAG}.tar.gz" \
  schemas \
  docs/REPORTING.md \
  docs/HARNESS.md \
  docs/install.md \
  LICENSE \
  NOTICE.md
cp scripts/install.sh "dist/install.sh"
cp LICENSE "dist/LICENSE"
cp NOTICE.md "dist/NOTICE.md"

(
  cd dist
  sha256sum -- * > SHA256SUMS
)

echo "[*] dist/"
ls -l dist
echo "version ${VERSION}"
