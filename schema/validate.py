"""Validate a window file against the schema and the referential rules.

    python schema/validate.py data/windows/labo/*.json
"""
import json
import sys
import glob

from jsonschema import validate as js_validate

_HERE = __import__("os").path.dirname(__file__)
with open(__import__("os").path.join(_HERE, "window.schema.json")) as fh:
    SCHEMA = json.load(fh)


def check(window: dict) -> None:
    """Raise AssertionError / ValidationError if the window is not well formed."""
    js_validate(window, SCHEMA)
    ids = {n["id"] for n in window["noeuds"]}
    assert len(ids) == len(window["noeuds"]), "duplicate node id"
    for e in window["aretes"]:
        assert e["src"] in ids, f"edge from unknown node {e['src']}"
        assert e["dst"] in ids, f"edge to unknown node {e['dst']}"
    labels = window["labels"]
    for key in ("cibles", "sources", "impactes"):
        for node_id in labels.get(key, []):
            assert node_id in ids, f"label {key} refers to unknown node {node_id}"
    if labels["verdict"] == "attaque":
        assert labels["type"] != "none", "attack window must have a type"
    else:
        assert labels["type"] == "none", "non-attack window must have type none"


def check_file(path: str) -> None:
    with open(path) as fh:
        check(json.load(fh))


def main(argv) -> int:
    paths = []
    for pattern in argv:
        paths.extend(sorted(glob.glob(pattern)))
    if not paths:
        print("no files matched", file=sys.stderr)
        return 2
    bad = 0
    for path in paths:
        try:
            check_file(path)
        except Exception as exc:  # noqa: BLE001 - report and continue
            bad += 1
            print(f"FAIL {path}: {exc}")
    print(f"{len(paths) - bad}/{len(paths)} windows valid")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
