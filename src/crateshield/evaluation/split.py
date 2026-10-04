import json
import logging
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def split_dataset(
    dataset_path: Path,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
):
    """
    Deduplicates crates and splits the dataset into train, val, and test splits by crate NAME.
    This ensures that different versions of the same crate do not appear in different splits.
    Modifies dataset.json to include a 'split' field for each crate.
    """
    if not dataset_path.exists():
        logger.error(f"Cannot find {dataset_path}")
        return

    random.seed(seed)

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    crates = dataset.get("crates", [])

    # Deduplicate by name and version
    seen = set()
    deduped = []
    for c in crates:
        key = (c.get("name"), c.get("version"))
        if key not in seen:
            seen.add(key)
            deduped.append(c)

    # Group by crate NAME
    groups: dict[str, list[Any]] = defaultdict(list)
    for c in deduped:
        groups[c.get("name")].append(c)

    # Group names and stratify by majority label of the group to preserve label distribution
    group_majority_label = {}
    for name, items in groups.items():
        labels = [c.get("label") for c in items]
        majority = max(set(labels), key=labels.count)
        group_majority_label[name] = majority

    strata: dict[str, list[str]] = defaultdict(list)
    for name, label in group_majority_label.items():
        strata[label].append(name)

    for name, items in groups.items():
        # sort by publish date if available, here we just sort by version string
        items.sort(key=lambda x: x.get("version", ""))

    train_names, val_names, test_names = set(), set(), set()

    for label, names in strata.items():
        random.shuffle(names)
        n = len(names)
        n_test = int(n * test_ratio)
        n_val = int(n * val_ratio)

        test_names.update(names[:n_test])
        val_names.update(names[n_test : n_test + n_val])
        train_names.update(names[n_test + n_val :])

    for c in deduped:
        name = c.get("name")
        if name in test_names:
            c["split"] = "test"
        elif name in val_names:
            c["split"] = "val"
        else:
            c["split"] = "train"

    dataset["crates"] = deduped

    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    logger.info(
        f"Split complete. Train: {len(train_names)} groups, Val: {len(val_names)} groups, Test: {len(test_names)} groups."
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from crateshield.config import WORK_DIR

    split_dataset(WORK_DIR / "dataset.json")
