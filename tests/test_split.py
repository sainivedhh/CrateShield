import json
from pathlib import Path
from crateshield.config import WORK_DIR


def test_split_no_leakage():
    dataset_path = WORK_DIR / "dataset.json"
    if not dataset_path.exists():
        dataset_path = WORK_DIR / "dataset_mini.json"

    if not dataset_path.exists():
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    train_names = set()
    val_names = set()
    test_names = set()

    for crate in dataset.get("crates", []):
        name = crate.get("name")
        split = crate.get("split")

        if split == "train":
            train_names.add(name)
        elif split == "val":
            val_names.add(name)
        elif split == "test":
            test_names.add(name)

    # Check for intersections
    assert len(train_names.intersection(val_names)) == 0, (
        "Leakage between train and val!"
    )
    assert len(train_names.intersection(test_names)) == 0, (
        "Leakage between train and test!"
    )
    assert len(val_names.intersection(test_names)) == 0, "Leakage between val and test!"
