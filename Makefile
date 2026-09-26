.PHONY: test lint index demo eval ui check-independence spec-detection spec-prevention

test:
	python -m pytest tests/ -q

# The two defense modules must stay independent; neither may call the other.
check-independence:
	python scripts/check_independence.py

# Each defense's requirements as tests: they fail against the starter stub and
# pass when that teammate's defense is done. Skipped by `make test`.
spec-detection:
	python -m pytest tests/spec/test_detection_spec.py --spec -q

spec-prevention:
	python -m pytest tests/spec/test_prevention_spec.py --spec -q

index:
	python cli.py index

# The two-tab web UI: Mailbox (live playground) and Lab (research view).
ui:
	python interface/app.py

# PI-101 (ride_along_cc), not a naive_standalone payload: that family is
# deliberately 0% ASR, so demoing it shows a defense blocking an attack that
# never lands anyway.
demo:
	python cli.py demo PI-101

# caffeinate -i: a sweep is tens of minutes; idle sleep kills the run.
eval:
	caffeinate -i python cli.py eval --split test
