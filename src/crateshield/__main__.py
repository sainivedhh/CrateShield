from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from crateshield.config import ROOT, WORK_DIR, ensure_dirs


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(prog="crateshield")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("extract", help="signals only")
    e.add_argument("--name", required=True)
    e.add_argument("--version", required=True)

    a = sub.add_parser("analyze", help="signals + GPT-4o")
    a.add_argument("--name", required=True)
    a.add_argument("--version", required=True)

    r = sub.add_parser("ingest-rustsec", help="pull malicious and benign crates into dataset")
    r.add_argument("--out", default=str(WORK_DIR / "dataset.json"))

    x = sub.add_parser("extract-dataset", help="run signal extraction for every crate in a dataset.json (required before train)")
    x.add_argument("--dataset", default=str(WORK_DIR / "dataset.json"))

    s = sub.add_parser("severity-dataset", help="build a tabular CSV dataset with severity labels")
    s.add_argument("--dataset", default=str(WORK_DIR / "dataset.json"))

    t = sub.add_parser("train", help="train local ML models")
    t.add_argument("--dataset", default=str(WORK_DIR / "dataset.json"))
    t.add_argument("--model", choices=["rf", "xgboost", "both"], default="rf", help="which model to train")
    t.add_argument("--target", choices=["binary", "severity"], default="binary", help="train binary (malicious/benign) or multiclass severity")

    p2 = sub.add_parser("predict", help="predict if a crate is malicious using an ML model")
    p2.add_argument("--name", required=True)
    p2.add_argument("--version", required=True)
    p2.add_argument("--model", choices=["rf", "xgboost", "both"], default="rf", help="which model to predict with")
    p2.add_argument("--target", choices=["binary", "severity"], default="binary", help="predict binary (malicious/benign) or multiclass severity")

    ab = sub.add_parser("ablation", help="A/B/C evaluation")
    ab.add_argument("--dataset", required=True)
    ab.add_argument("--out", default=str(WORK_DIR / "results" / "ablation.json"))

    args = p.parse_args()
    ensure_dirs()

    if args.cmd == "extract":
        from crateshield.pipeline import extract_only
        print(json.dumps(extract_only(args.name, args.version), indent=2))
    elif args.cmd == "analyze":
        from crateshield.pipeline import analyze_crate
        print(json.dumps(analyze_crate(args.name, args.version), indent=2))
    elif args.cmd == "ingest-rustsec":
        from crateshield.ingestion.rustsec import build_full_dataset
        ds = build_full_dataset(Path(args.out))
        print(f"Wrote {ds['total_crates']} crates ({ds['label_counts']['MALICIOUS']} Malicious, {ds['label_counts']['BENIGN']} Benign) to {args.out}")
    elif args.cmd == "extract-dataset":
        from crateshield.pipeline import extract_only
        dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
        ok, skipped, failed = 0, 0, 0
        for crate in dataset.get("crates", []):
            name, version = crate["name"], crate.get("version")
            if not version or version == "yanked":
                skipped += 1
                continue
            try:
                extract_only(name, version)
                ok += 1
            except Exception as exc:
                failed += 1
                print(f"  skip {name}@{version}: {exc}")
        print(f"\nDone. {ok} extracted, {skipped} skipped (no resolvable version), {failed} failed downloads/parses.")
    elif args.cmd == "severity-dataset":
        from crateshield.evaluation.train import build_severity_dataset
        from crateshield.config import SIGNALS_DIR
        build_severity_dataset(Path(args.dataset), SIGNALS_DIR)
    elif args.cmd == "train":
        from crateshield.evaluation.train import train_and_evaluate, train_and_evaluate_xgb, compare_models, train_severity_xgb
        from crateshield.config import SIGNALS_DIR
        dataset_path = Path(args.dataset)
        if args.target == "severity":
            if args.model in ["rf", "both"]:
                print("Note: Severity multiclass training is currently implemented for XGBoost only.")
            train_severity_xgb(dataset_path, SIGNALS_DIR)
        else:
            if args.model == "rf":
                train_and_evaluate(dataset_path, SIGNALS_DIR)
            elif args.model == "xgboost":
                train_and_evaluate_xgb(dataset_path, SIGNALS_DIR)
            elif args.model == "both":
                compare_models(dataset_path, SIGNALS_DIR)
            
    elif args.cmd == "predict":
        from crateshield.evaluation.train import predict_crate, predict_crate_xgb, predict_severity
        if args.target == "severity":
            if args.model in ["rf", "both"]:
                print("Note: Severity multiclass prediction is currently implemented for XGBoost only.")
            predict_severity(args.name, args.version)
        else:
            if args.model in ("rf", "both"):
                predict_crate(args.name, args.version)
            if args.model in ("xgboost", "both"):
                predict_crate_xgb(args.name, args.version)
            
    elif args.cmd == "ablation":
        from crateshield.evaluation.ablation import run_ablation
        result = run_ablation(Path(args.dataset), ROOT)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
