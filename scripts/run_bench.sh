#!/usr/bin/env bash
set -euo pipefail

SCEN=${1:-basic_mixed}
DUR=${2:-60}
WRK=${3:-16}

python -m bench.runner --scenario "$SCEN" --duration "$DUR" --workers "$WRK"
