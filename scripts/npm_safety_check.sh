#!/usr/bin/env bash
set -euo pipefail

echo "CamAudit npm safety check"
echo "This project should not need npm unless a frontend is later added."

if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found. OK for this Python project."
  exit 0
fi

echo "npm version: $(npm --version)"
echo "Global npm packages:"
npm ls -g --depth=0 || true

echo "ignore-scripts setting:"
npm config get ignore-scripts || true

echo "If you are inside a Node project, run manually:"
echo "  npm audit"
echo "  npm audit signatures"
echo "  npm ci --ignore-scripts"
