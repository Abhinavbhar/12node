#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
npm install --omit=dev --no-audit --no-fund
