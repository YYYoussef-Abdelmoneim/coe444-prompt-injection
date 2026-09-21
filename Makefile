.PHONY: test lint index demo eval check-independence

test:
	python -m pytest tests/ -q

# The two defense modules must stay independent; neither may call the other.
check-independence:
	python scripts/check_independence.py

index:
	python cli.py index

demo:
	python cli.py demo PI-001

# caffeinate -i: a sweep is tens of minutes; idle sleep kills the run.
eval:
	caffeinate -i python cli.py eval --split test
