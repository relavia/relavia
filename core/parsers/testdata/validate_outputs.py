#!/usr/bin/env python3
"""校验 parsers 包测试产出是否符合 spec 统一节点模型 schema。

用法：python3 validate_outputs.py <schema.json 路径> <产出目录>
产出目录中的文件按名前缀决定校验目标：
  node-*.json -> Node，group-*.json -> Group，
  sub-*.json -> Subscription，source-*.json -> Source
依赖缺失（jsonschema 未安装）时打印 SKIP 并以退出码 3 结束，
供 Go 测试据此跳过；任一文件校验失败退出码 1。
"""
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("SKIP: python jsonschema not available")
    sys.exit(3)

TARGETS = {"node": "Node", "group": "Group", "sub": "Subscription", "source": "Source"}


def main() -> int:
    schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    outdir = Path(sys.argv[2])

    def validator_for(target: str) -> Draft202012Validator:
        sub = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"],
            "$ref": f"#/$defs/{target}",
        }
        return Draft202012Validator(sub)

    files = sorted(outdir.glob("*.json"))
    if not files:
        print("FAIL: no output files")
        return 1
    failed = 0
    for f in files:
        kind = f.name.split("-", 1)[0]
        target = TARGETS.get(kind)
        if target is None:
            print(f"FAIL {f.name}: unknown prefix")
            failed += 1
            continue
        instance = json.loads(f.read_text(encoding="utf-8"))
        errs = sorted(validator_for(target).iter_errors(instance), key=lambda e: list(e.path))
        if errs:
            failed += 1
            print(f"FAIL {f.name} ({target}):")
            for e in errs:
                print(f"  - {list(e.path)}: {e.message}")
        else:
            print(f"OK   {f.name} ({target})")
    print(f"validated {len(files)} files, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
