#!/usr/bin/env python3
"""Measure clean contract and local coverage; historical fixtures never contribute."""

import argparse
from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess
import shlex
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs/coverage-baseline.json"
EXCLUDE = r".*(?:_contract_test\.[ch]|_test_driver\.[ch])$"


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def compiler_outputs(commands, build):
    objects = [(Path(c["directory"]) / c["output"]).resolve() for c in commands]
    if any(not obj.is_relative_to(build.resolve()) for obj in objects):
        raise RuntimeError("Compiler outputs must stay inside the coverage build directory")
    return objects


def check_compiled_sources(commands, objects, files):
    import re
    missing = set()
    for command, obj in zip(commands, objects):
        source = Path(command["file"])
        if not source.is_relative_to(ROOT / "src") or re.fullmatch(EXCLUDE, str(source)):
            continue
        filename = str(source.relative_to(ROOT))
        if filename in files:
            continue
        # Data-only translation units have gcno metadata but no executable lines.
        metadata = json.loads(run("gcov", "--json-format", "--stdout",
                                  str(obj.with_suffix(".gcno")),
                                  capture_output=True, text=True).stdout)
        if any(entry["lines"] for entry in metadata["files"]):
            missing.add(filename)
    if missing:
        raise RuntimeError(f"Missing compiled production sources: {sorted(missing)}")


def subsystem(filename):
    parts = Path(filename).parts
    return "/".join(parts[1:3]) if parts[1] == "backend" else parts[1]


def summarize(data):
    groups = {"total": {"line_total": 0, "line_covered": 0,
                        "branch_total": 0, "branch_covered": 0}}
    for entry in data["files"]:
        group = groups.setdefault(subsystem(entry["filename"]), dict.fromkeys(groups["total"], 0))
        for key in group:
            group[key] += entry[key]
            groups["total"][key] += entry[key]
    for group in groups.values():
        for metric in ("line", "branch"):
            count = group[f"{metric}_total"]
            group[f"{metric}_percent"] = round(100 * group[f"{metric}_covered"] / count, 4) if count else 100
    return groups


def check(current, baseline):
    errors = []
    for suite, old in baseline.items():
        new = current[suite]
        missing = set(old["files"]) - set(new["files"])
        if missing:
            errors.append(f"{suite}: production files disappeared: {sorted(missing)}; review the baseline")
        for name, group in old["groups"].items():
            for metric in ("line", "branch"):
                key = f"{metric}_percent"
                actual = new["groups"].get(name, {}).get(key, 0)
                if actual + 0.01 < group[key]:
                    errors.append(f"{suite}/{name}: {metric} {actual:.2f}% < baseline {group[key]:.2f}%")
    if errors:
        raise RuntimeError("Coverage regression:\n" + "\n".join(errors))


def measure(build, output, profile, selected_suite=None, stage="all"):
    if version("gcovr") != "8.4":
        raise RuntimeError("Install the pinned tools/coverage-requirements.txt first")
    if not (build / "compile_commands.json").exists():
        raise RuntimeError("Configure and build the GCC coverage preset first")
    commands = read_json(build / "compile_commands.json")
    if any(not all(flag in shlex.split(c["command"]) for flag in ("--coverage", "-fprofile-abs-path", "-g")) for c in commands):
        raise RuntimeError("Every compiled target must use the Debug coverage flags")
    if not all(any(f"backend/{backend}/" in c["file"] for c in commands) for backend in ("unicorn", "kvm")):
        raise RuntimeError("These baselines require the dual-backend build")
    objects = compiler_outputs(commands, build)
    if any(not obj.with_suffix(".gcno").exists() for obj in objects):
        raise RuntimeError("Coverage metadata missing: build all targets first")
    if profile == "kvm" and stage != "report":
        import fcntl
        with open("/dev/kvm", "rb", buffering=0) as device:
            if fcntl.ioctl(device, 0xAE00, 0) != 12:
                raise RuntimeError("Unsupported KVM API")
            os.close(fcntl.ioctl(device, 0xAE01, 0))

    discovered = json.loads(run("ctest", "--test-dir", str(build), "--show-only=json-v1",
                                capture_output=True, text=True).stdout)["tests"]
    suites = {}
    for suite, label in (("contracts", "contract"), ("local", "local")):
        if selected_suite and suite != selected_suite:
            continue
        report = output / suite
        report.mkdir(parents=True, exist_ok=True)
        selection = ["-L", f"^{label}$"]
        if profile == "portable":
            selection += ["-LE", "^requires-kvm$"]
        selected, omitted = [], []
        for test in discovered:
            labels = next((p["value"] for p in test["properties"] if p["name"] == "LABELS"), [])
            if label in labels:
                (omitted if profile == "portable" and "requires-kvm" in labels else selected).append(test["name"])
        if not selected:
            raise RuntimeError(f"No {suite} tests registered")
        junit = report / "tests.xml"
        if stage != "report":
            if suite == "contracts":
                for name in ("summary.json", "metadata.json"):
                    (output / name).unlink(missing_ok=True)
            for name in ("files.json", "subsystems.json", "selection.json", "tests.xml", "coverage.xml"):
                (report / name).unlink(missing_ok=True)
            # gcno metadata stays intact so never-executed sources remain in the report.
            for obj in objects:
                obj.with_suffix(".gcda").unlink(missing_ok=True)
            run("ctest", "--test-dir", str(build), *selection, "-j1", "--output-on-failure",
                "--no-tests=error", "--output-junit", str(junit))
        cases = list(ET.parse(junit).iter("testcase"))
        if (sorted(c.get("name") for c in cases) != sorted(selected) or
                any(c.find("skipped") is not None for c in cases)):
            raise RuntimeError(f"{suite}: missing or skipped tests are a validation failure")
        if stage != "report":
            inputs = [obj.with_suffix(".gcda") if obj.with_suffix(".gcda").exists()
                      else obj.with_suffix(".gcno") for obj in objects]
            config = [f"root = {ROOT}", f"filter = {ROOT}/src/", f"exclude = {EXCLUDE}",
                      "no-markers = yes", f"json-summary = {report / 'files.json'}",
                      f"html-details = {report / 'index.html'}", f"txt = {report / 'coverage.txt'}",
                      f"cobertura = {report / 'coverage.xml'}"]
            config += [f"search-path = {path}" for path in inputs]
            (report / "gcovr.cfg").write_text("\n".join(config) + "\n")
            write_json(report / "selection.json", {"selected": selected, "omitted": omitted})
        if stage == "prepare":
            continue
        if stage == "all":
            run(sys.executable, "-m", "gcovr", "--config", str(report / "gcovr.cfg"))
        data = read_json(report / "files.json")
        # The compiler database supplies an independent denominator check.
        files = sorted(f["filename"] for f in data["files"])
        check_compiled_sources(commands, objects, set(files))
        groups = summarize(data)
        suites[suite] = {"groups": groups, "files": files}
        write_json(report / "subsystems.json", groups)
        for name, stats in groups.items():
            print(f"{profile}/{suite}/{name}: lines {stats['line_percent']:.2f}%, branches {stats['branch_percent']:.2f}%", flush=True)
    if stage == "prepare":
        return suites
    summary = output / "summary.json"
    combined = read_json(summary) if selected_suite and summary.exists() else {}
    combined.update(suites)
    write_json(summary, combined)
    write_json(output / "metadata.json", {
        "profile": profile, "build": str(build),
        "revision": run("git", "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip(),
        "worktree": run("git", "status", "--short", capture_output=True, text=True).stdout,
        "compiler": run(shlex.split(commands[0]["command"])[0], "--version", capture_output=True, text=True).stdout.splitlines()[0],
        "gcovr": run(sys.executable, "-m", "gcovr", "--version", capture_output=True, text=True).stdout.strip(),
        "hardware": "KVM API 12 and VM creation succeeded" if profile == "kvm" else "KVM execution deliberately omitted; compiled KVM sources retained",
        "source_filter": "src/", "source_exclude": EXCLUDE, "flags": "--coverage -fprofile-abs-path (Debug)",
    })
    return suites


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/coverage")
    parser.add_argument("--profile", choices=("kvm", "portable"), default="kvm")
    parser.add_argument("--record-baseline", action="store_true", help="Explicitly replace this profile's reviewed baseline")
    parser.add_argument("--check-only", action="store_true", help="Check the existing summary without rerunning tests")
    parser.add_argument("--suite", choices=("contracts", "local"), help="Operate on one suite")
    parser.add_argument("--stage", choices=("all", "prepare", "report"), default="all",
                        help="Prepare tests/config, check action-generated reports, or run both locally")
    args = parser.parse_args()
    if args.stage != "all" and (not args.suite or args.check_only or args.record_baseline):
        parser.error("Split stages require --suite and cannot check-only or record a baseline")
    if args.record_baseline and args.suite:
        parser.error("Record baselines only after measuring both suites")
    build = args.build_dir.resolve()
    if not build.is_relative_to(ROOT / "build"):
        parser.error("Coverage build must be under this repository's build/ directory")
    output = build / "reports" / args.profile
    current = (read_json(output / "summary.json") if args.check_only else
               measure(build, output, args.profile, args.suite, args.stage))
    if args.stage == "prepare":
        print(f"Coverage prepared: {args.profile}/{args.suite}")
        return
    baseline = read_json(BASELINE) if BASELINE.exists() else {}
    if args.record_baseline:
        baseline[args.profile] = current
        write_json(BASELINE, baseline)
    else:
        if args.profile not in baseline:
            raise RuntimeError(f"No reviewed {args.profile} baseline")
        reviewed = baseline[args.profile]
        if args.suite:
            current = {args.suite: current[args.suite]}
            reviewed = {args.suite: reviewed[args.suite]}
        check(current, reviewed)
    print(f"Coverage baseline {'recorded' if args.record_baseline else 'passed'}: {args.profile}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
