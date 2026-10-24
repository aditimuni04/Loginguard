#!/usr/bin/env bash
# Build, analyse the bundled sample log and open the dashboard on http://127.0.0.1:8080
set -euo pipefail
cd "$(dirname "$0")"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/loginguard run --logs data/sample_logs.csv --db loginguard.db
