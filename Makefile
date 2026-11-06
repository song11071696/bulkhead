.PHONY: install test demo serve replay record static scan

install:            ## create .venv and install with dev extras
	python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

test:               ## offline test suite (recorded Clocked responses)
	BULKHEAD_MODE=replay .venv/bin/pytest -q

demo:               ## print every decision of every scenario in the terminal
	BULKHEAD_MODE=replay .venv/bin/bulkhead demo all

replay:             ## dashboard on :8787 without an API key
	BULKHEAD_MODE=replay .venv/bin/bulkhead serve

serve:              ## dashboard + hook endpoint, live Clocked calls (needs CLOCKED_API_KEY)
	.venv/bin/bulkhead serve

record:             ## re-record fixtures from the live API (~120 credits)
	PATH=.venv/bin:$$PATH ./scripts/record_fixtures.sh

static:             ## rebuild the GitHub Pages demo in docs/
	.venv/bin/python scripts/export_static.py

scan:               ## secret scan of tracked files
	./scripts/secret_scan.sh
