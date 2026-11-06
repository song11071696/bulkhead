#!/usr/bin/env bash
# Re-record every Clocked response used by the tests and the offline demo.
# Needs CLOCKED_API_KEY. Costs ~100 credits (every response header reports its own credits).
set -euo pipefail
cd "$(dirname "$0")/.."
rm -f fixtures/clocked/*.json
BULKHEAD_DATA=.bulkhead/record bulkhead --mode record demo all
python scripts/record_api_fixtures.py
