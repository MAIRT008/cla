#!/usr/bin/env python3
"""Validate this document package only. Never inspect or modify live app/network data."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "DOCS" / "index"
EXPECTED = {
    "FD-01": {"F": 28, "A": 22, "R": 14},
    "FD-02": {"N": 34, "A": 28, "R": 18},
    "FD-03": {"F": 40, "A": 34, "R": 22},
    "FD-04": {"F": 44, "A": 42, "R": 26},
}
ROOT_DOCS = ["README.md", "AGENTS.md", "ARCHITECTURE.md", "PROJECT_OVERVIEW.md"]
PACKAGE_NAME = "Claude_环境管理_方案与开发计划_v1.3.zip"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return path.read_text(encoding="utf-8-sig")

def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def canonical_docs():
    return [ROOT / p for p in ROOT_DOCS] + sorted((ROOT / "DOCS").glob("*.md"))

def fd_files():
    result = {}
    for p in (ROOT / "DOCS").glob("0[1-4]_*.md"):
        result["FD-" + p.name[:2]] = p
    if set(result) != set(EXPECTED):
        raise ValueError("Expected one current file for each FD-01..04")
    return result

def current_spec():
    entries = []
    for module, path in sorted(fd_files().items()):
        for line, value in enumerate(read(path).splitlines(), 1):
            m = re.match(r"^\|\s*([FNAR]\d{2})\s*\|\s*(.*?)\s*\|", value)
            if m:
                entries.append({"module": module, "id": m.group(1), "key": module + "/" + m.group(1),
                                "kind": {"F": "function", "N": "function", "A": "acceptance", "R": "rule"}[m.group(1)[0]],
                                "title": m.group(2), "path": path.relative_to(ROOT).as_posix(),
                                "line": line, "source_sha256": sha(path)})
    return {"version": "1.3", "entries": entries}

def phase(module, number):
    if module == "FD-01":
        return "P2"
    if module == "FD-02":
        return "P5"
    if module == "FD-03":
        if number <= 12 or 29 <= number <= 36:
            return "P4"
        if 13 <= number <= 28:
            return "P3"
        return "P7"
    if number <= 5:
        return "P6"
    if number <= 8:
        return "P4"
    if 9 <= number <= 20 or 22 <= number <= 24:
        return "P3"
    return "P6"

def current_coverage(spec):
    functions = [x for x in spec["entries"] if x["kind"] == "function"]
    cases = [x for x in spec["entries"] if x["kind"] == "acceptance"]
    return {"version": "1.3", "status": "NOT_STARTED",
            "note": "Phase ownership is planning coverage, not product implementation or test evidence.",
            "functions": [{"requirement": x["key"], "primary_phase": phase(x["module"], int(x["id"][1:])),
                           "plan": "DOCS/IMPLEMENTATION_PLAN.md", "status": "NOT_STARTED",
                           "module_acceptance_set": [a["key"] for a in cases if a["module"] == x["module"]]}
                          for x in functions],
            "acceptance": [{"case": x["key"], "status": "UNVERIFIED", "evidence": None} for x in cases]}

def diagrams():
    return re.findall(r"<!-- diagram:([^>]+) -->\s*\x60\x60\x60mermaid\n(.*?)\n\x60\x60\x60\s*<!-- /diagram:\1 -->",
                      read(ROOT / "ARCHITECTURE.md"), re.S)

def source_paths():
    return canonical_docs() + sorted((ROOT / "DOCS" / "diagrams").glob("*.mmd")) + [Path(__file__).resolve()]

def refresh():
    INDEX.mkdir(parents=True, exist_ok=True)
    target = ROOT / "DOCS" / "diagrams"
    target.mkdir(parents=True, exist_ok=True)
    for name, body in diagrams():
        (target / name).write_text(body.rstrip() + "\n", encoding="utf-8")
    spec = current_spec()
    dump(INDEX / "spec-index.json", spec)
    dump(INDEX / "implementation-coverage.json", current_coverage(spec))
    baseline = ROOT / "history" / "pre-v1.2-20260912" / "manifest.json"
    before = json.loads(read(baseline)) if baseline.exists() else []
    manifest = {"version": "1.3", "current": [{"path": p.relative_to(ROOT).as_posix(), "sha256": sha(p)}
                                           for p in source_paths()],
                "pre_revision_markdown": before,
                "note": "Historical hashes are provenance only. Runtime product status is UNVERIFIED."}
    dump(INDEX / "source-manifest.json", manifest)
    if not (INDEX / "document-validation.json").exists():
        dump(INDEX / "document-validation.json", {"status": "PENDING_VALIDATION"})

def validate():
    errors = []
    checks = {}
    spec = current_spec()
    for module, expected in EXPECTED.items():
        for prefix, count in expected.items():
            actual = [x["id"] for x in spec["entries"] if x["module"] == module and x["id"].startswith(prefix)]
            desired = [prefix + str(i).zfill(2) for i in range(1, count + 1)]
            if actual != desired:
                errors.append(f"{module}/{prefix}: expected exact ordered IDs 1..{count}, got {actual}")
    checks["requirements"] = {"functions": sum(x["kind"] == "function" for x in spec["entries"]),
                              "acceptance": sum(x["kind"] == "acceptance" for x in spec["entries"]),
                              "rules": sum(x["kind"] == "rule" for x in spec["entries"])}
    expected_json = {"spec-index.json": spec, "implementation-coverage.json": current_coverage(spec)}
    for name, expected in expected_json.items():
        path = INDEX / name
        if not path.exists() or json.loads(read(path)) != expected:
            errors.append(f"{name}: missing or stale; explicitly use --refresh after reviewing source changes")
    expected_phases = {f"P{i}" for i in range(8)}
    plan = read(ROOT / "DOCS" / "IMPLEMENTATION_PLAN.md")
    for phase_id in expected_phases:
        if phase_id not in plan:
            errors.append(f"Missing plan phase {phase_id}")
    xids = re.findall(r"^\|\s*(X\d{2})\s*\|", read(ROOT / "DOCS" / "ACCEPTANCE.md"), re.M)
    if xids != [f"X{i:02d}" for i in range(1, 21)]:
        errors.append("Expected X01..X20 once in acceptance document")
    checks["cross_module_scenarios"] = len(xids)
    local_links = 0
    for path in canonical_docs():
        content = re.sub(r"\x60\x60\x60.*?\x60\x60\x60", "", read(path), flags=re.S)
        for target in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", content):
            target = target.strip().strip("<>")
            if urlsplit(target).scheme or target.startswith("#"):
                continue
            raw = unquote(target.split("#", 1)[0])
            if not raw:
                continue
            local_links += 1
            dest = (path.parent / raw).resolve()
            if not dest.is_relative_to(ROOT):
                errors.append(f"{path.name}: local link outside package: {raw}")
                continue
            if not dest.exists():
                errors.append(f"{path.relative_to(ROOT)}: broken local link: {raw}")
            if dest.exists():
                cur = ROOT
                for part in dest.relative_to(ROOT).parts:
                    names = [p.name for p in cur.iterdir()]
                    if part not in names:
                        errors.append(f"{path.name}: case mismatch in local link: {raw}")
                        break
                    cur /= part
    checks["local_links"] = local_links
    ds = diagrams()
    if len(ds) != 4:
        errors.append(f"Expected 4 diagrams, found {len(ds)}")
    for name, body in ds:
        p = ROOT / "DOCS" / "diagrams" / name
        if not p.exists() or read(p).rstrip() != body.rstrip():
            errors.append(f"Diagram mismatch: {name}")
    checks["mermaid_source_pairs"] = len(ds)
    manifest_path = INDEX / "source-manifest.json"
    if not manifest_path.exists():
        errors.append("Missing source-manifest.json")
    else:
        manifest = json.loads(read(manifest_path))
        expected = [{"path": p.relative_to(ROOT).as_posix(), "sha256": sha(p)} for p in source_paths()]
        if manifest.get("current") != expected:
            errors.append("Current source hashes do not match manifest")
        checks["source_hashes"] = len(expected)
        baseline_dir = ROOT / "history" / "pre-v1.2-20260912"
        if baseline_dir.exists():
            for item in manifest.get("pre_revision_markdown", []):
                p = baseline_dir / item["path"]
                if not p.exists() or sha(p) != item["sha256"]:
                    errors.append("Historical snapshot hash mismatch: " + item["path"])
            checks["historical_markdown_preserved"] = len(manifest.get("pre_revision_markdown", []))
    checks["scope"] = "Current canonical Markdown, indexes, diagram sources and verifier only; not historical Word/audits or product runtime."
    return {"version": "1.3", "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": "PASS" if not errors else "FAIL", "product_status": "UNVERIFIED",
            "checks": checks, "errors": errors}

def package():
    dest = ROOT / "dist" / PACKAGE_NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    paths = source_paths() + [INDEX / p for p in ["spec-index.json", "implementation-coverage.json",
                                              "source-manifest.json", "document-validation.json"]]
    # Report outside ZIP: avoids self-referential archive hashes. Its link is validated separately.
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for path in paths:
            z.write(path, path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(dest) as z:
        bad = z.testzip()
        names = z.namelist()
        mismatches = [p.relative_to(ROOT).as_posix() for p in paths
                      if hashlib.sha256(z.read(p.relative_to(ROOT).as_posix())).hexdigest() != sha(p)]
    result = {"version": "1.3", "status": "PASS" if bad is None and not mismatches else "FAIL",
              "archive": dest.relative_to(ROOT).as_posix(), "bytes": dest.stat().st_size, "sha256": sha(dest),
              "members": names, "crc_error_member": bad, "source_mismatches": mismatches,
              "note": "Local delivery only. Not published. Product remains UNVERIFIED."}
    dump(INDEX / "package-validation.json", result)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="Regenerate documentation indexes and diagram sources")
    parser.add_argument("--package", action="store_true", help="Create current document ZIP after validation")
    args = parser.parse_args()
    if args.refresh:
        refresh()
    result = validate()
    dump(INDEX / "document-validation.json", result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["errors"]:
        return 1
    if args.package:
        packed = package()
        print(json.dumps({k: v for k, v in packed.items() if k != "members"}, ensure_ascii=False, indent=2))
        return 0 if packed["status"] == "PASS" else 1
    return 0

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
