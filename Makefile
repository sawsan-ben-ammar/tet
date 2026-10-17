.PHONY: help install synth-data train-synth lab-up lab-net lab-down capture scenario process \
        dataset-report train compare phase6 plots correlate test demo api clean

PY ?= python3
VENV ?= /home/claude/.venv/bin/python
WINDOWS_REAL ?= data/windows/real-*

help:
	@echo "Lab (Phase 2):   lab-up / lab-net / lab-down"
	@echo "Capture (3-5):   scenario SCN=lab/scenarios/http_flood.yaml   (authorized attack)"
	@echo "                 process CAP=data/captures/<id>               (raw -> windows)"
	@echo "Dataset (5):     dataset-report"
	@echo "Models (6):      train (real) / train-synth / compare / phase6 / plots"
	@echo "Correlation(7):  correlate CAP=data/captures/<id>"
	@echo "Serve (8):       api / demo"
	@echo "Tests:           test"

install:
	$(PY) -m pip install -r requirements.txt

# ---- synthetic dev data (clearly separate from real) ----
synth-data:
	$(PY) -m data_prep.generate_dataset --scenarios 150 --out data/windows/synth
train-synth:
	$(PY) -m model.train --windows data/windows/synth --epochs 25 --out model/artifacts_synth

# ---- lab (Phase 2) ----
lab-up:
	bash lab/scripts/up.sh --check
lab-net:
	kubectl apply -f lab/k8s/network-policies.yaml
lab-down:
	bash lab/scripts/down.sh

# ---- capture + process (Phases 3-5) ----
scenario:
	$(PY) lab/scenario_runner.py $(SCN)
process:
	$(PY) -m collect.run_capture $(CAP)
dataset-report:
	$(PY) -m data_prep.dataset_report "$(WINDOWS_REAL)" --out reports/dataset_real.json

# ---- models (Phase 6): train on REAL captures ----
train:
	$(PY) -m model.train --windows "$(WINDOWS_REAL)" --epochs 40 --out model/artifacts
compare:
	$(PY) -m model.compare --windows "$(WINDOWS_REAL)" --epochs 25
phase6:
	$(PY) -m model.phase6 --real "$(WINDOWS_REAL)" --synth data/windows/synth --epochs 20 --seeds 0 1 2 --out reports/phase6
plots:
	$(PY) -m model.plots --report reports/phase6/phase6.json --out reports/phase6

# ---- correlation (Phase 7) ----
correlate:
	$(PY) -m correlate.run $(CAP)

# ---- serve (Phase 8) ----
api:
	uvicorn deploy.api:app --host 0.0.0.0 --port 8000
demo:
	streamlit run demo/app.py

test:
	$(PY) -m pytest -q

clean:
	rm -rf .pytest_cache; find . -name __pycache__ -type d -prune -exec rm -rf {} +
	@echo "NOTE: data/captures, data/windows and model/artifacts are preserved on purpose."
