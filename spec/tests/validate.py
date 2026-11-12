#!/usr/bin/env python3
"""统一节点模型 v1 校验脚本（Step 5 实测用）。

用法：python3 spec/tests/validate.py
依赖：python3 + jsonschema（4.x，支持 draft 2020-12）。
行为：校验 schema 本身（check_schema）；正例（examples/）逐个按目标模型
校验须全部通过；反例（tests/invalid/，清单见 invalid-manifest.json）
须全部被拒。任一不符退出码非 0。
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SPEC = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((SPEC / "unified-node-model.schema.json").read_text(encoding="utf-8"))


def validator_for(target: str) -> Draft202012Validator:
    subschema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": SCHEMA["$defs"],
        "$ref": f"#/$defs/{target}",
    }
    return Draft202012Validator(subschema)


def errors_of(target: str, instance) -> list:
    return sorted(validator_for(target).iter_errors(instance), key=lambda e: list(e.path))


def main() -> int:
    Draft202012Validator.check_schema(SCHEMA)
    print("schema check_schema: OK")

    positives = []
    nodes_dir = SPEC / "examples" / "nodes"
    for p in sorted(nodes_dir.glob("*.json")):
        positives.append((p, "Node"))
    for name, target in [("group", "Group"), ("source", "Source"), ("subscription", "Subscription")]:
        positives.append((SPEC / "examples" / f"{name}.json", target))

    pos_pass = 0
    for path, target in positives:
        instance = json.loads(path.read_text(encoding="utf-8"))
        errs = errors_of(target, instance)
        if errs:
            print(f"POSITIVE FAIL {path.name} ({target}):")
            for e in errs:
                print(f"  - {list(e.path)}: {e.message}")
        else:
            pos_pass += 1
            print(f"positive OK  {path.name} ({target})")
    print(f"positives: {pos_pass}/{len(positives)} passed")

    manifest = json.loads((SPEC / "tests" / "invalid-manifest.json").read_text(encoding="utf-8"))
    neg_rejected = 0
    for case in manifest:
        path = SPEC / "tests" / "invalid" / case["file"]
        instance = json.loads(path.read_text(encoding="utf-8"))
        errs = errors_of(case["target"], instance)
        if errs:
            neg_rejected += 1
            first = errs[0]
            print(f"negative REJECTED {case['file']}: {case['reason']} | 首个错误: {first.message[:100]}")
        else:
            print(f"negative NOT-REJECTED {case['file']}: {case['reason']}")
    print(f"negatives: {neg_rejected}/{len(manifest)} rejected")

    ok = pos_pass == len(positives) and neg_rejected == len(manifest)
    print("RESULT:", "ALL OK" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
