.PHONY: reproduce ingest extract train ablation

reproduce:
	python -m crateshield ingest-rustsec --out data/dataset.json
	python -m crateshield extract-dataset --dataset data/dataset.json
	python -m crateshield train --dataset data/dataset.json
	python -m crateshield ablation --dataset data/dataset.json --out data/results/ablation.json
	python -m crateshield.evaluation.report

ingest:
	python -m crateshield ingest-rustsec --out data/dataset.json

extract:
	python -m crateshield extract-dataset --dataset data/dataset.json

train:
	python -m crateshield train --dataset data/dataset.json

ablation:
	python -m crateshield ablation --dataset data/dataset.json --out data/results/ablation.json
	python -m crateshield.evaluation.report
