# Entry points for building, running, and analysing the benchmark.
# Targets marked TODO are stubs and fail until they are implemented.

IMAGE := pqc-bench
# The analysis runs on the host with the pinned packages from requirements.txt
# (python3 -m venv .venv && .venv/bin/pip install -r requirements.txt).
PYTHON ?= python3
DOCKER_RUN := docker run --rm -v "$(CURDIR):/work" -w /work $(IMAGE)

.PHONY: all image smoke inputs env bench interop figures

all: image smoke inputs env bench interop figures

image:
	docker build -t $(IMAGE) -f docker/Dockerfile .

smoke:
	$(DOCKER_RUN) sh docker/smoke_test.sh

# Creates data/in_*.bin and results/inputs.sha256; afterwards only verifies them.
inputs:
	$(DOCKER_RUN) sh measure/make_inputs.sh

# Runs on the host (it starts containers itself). Always captures a fresh env.json.
env:
	python3 measure/capture_env.py --force

bench:
	@echo "TODO: bench/run_all.py (Person A). Full runs are started by a human." && false

interop:
	$(DOCKER_RUN) python3 interop/run_matrix.py --repeat 3
	$(DOCKER_RUN) python3 interop/diagnose.py
	$(DOCKER_RUN) python3 interop/make_table.py

# Sanity checks first: no figure is made from incomplete or invalid data.
figures:
	$(PYTHON) analysis/sanity.py --phase full
	$(PYTHON) analysis/figures.py --phase full
	$(PYTHON) analysis/tables.py --phase full
	@test -f interop/make_table.py || { echo "error: interop/make_table.py (Person B) is missing" >&2; exit 1; }
	$(DOCKER_RUN) python3 interop/make_table.py
