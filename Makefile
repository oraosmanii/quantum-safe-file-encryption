# Entry points for building, running, and analysing the benchmark.
# Targets marked TODO are stubs and fail until they are implemented.

IMAGE := pqc-bench
DOCKER_RUN := docker run --rm -v "$(CURDIR):/work" -w /work $(IMAGE)

.PHONY: all image smoke inputs bench interop figures

all: image smoke inputs bench interop figures

image:
	docker build -t $(IMAGE) -f docker/Dockerfile .

smoke:
	$(DOCKER_RUN) sh docker/smoke_test.sh

inputs:
	@echo "TODO: measure/make_inputs.sh (Person C)" && false

bench:
	@echo "TODO: bench/run_all.py (Person A). Full runs are started by a human." && false

interop:
	@echo "TODO: interop/run_matrix.py (Person B)" && false

figures:
	@echo "TODO: analysis pipeline and interop/make_table.py (Persons C and B)" && false
