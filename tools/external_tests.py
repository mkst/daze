#!/usr/bin/env python3
"""Prepare the pinned corpus and enforce complete, unskipped CTest runs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "tools/daze-tests.json"
CORPUS_PATHS = ["daze_tests.py", "fixtures.yaml", "required.yaml", "requirements.txt", "cases", "golden", "sources"]


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def clean_environment():
    return {k: v for k, v in os.environ.items()
            if not k.startswith("DAZE_FIXTURE_") and k != "DAZE_TEST_INVOCATION_DIR"}


def probe_kvm(args):
    import fcntl
    with open("/dev/kvm", "rb", buffering=0) as device:
        if fcntl.ioctl(device, 0xAE00, 0) != 12:
            raise RuntimeError("Unsupported KVM API")
        os.close(fcntl.ioctl(device, 0xAE01, 0))
    print("KVM API 12; VM creation succeeded")


def check_corpus(corpus, revision):
    actual = run(["git", "-C", str(corpus), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if actual != revision:
        raise RuntimeError(f"Corpus revision {actual} differs from pin {revision}")
    dirty = run(["git", "-C", str(corpus), "status", "--porcelain", "--", *CORPUS_PATHS], capture_output=True, text=True).stdout
    if dirty:
        raise RuntimeError(f"Pinned corpus test contents are dirty:\n{dirty}")


def prepare(args):
    pin = json.loads(PIN.read_text())
    corpus = Path(args.corpus).resolve()
    venv = Path(args.venv).resolve()
    if corpus.exists() or venv.exists():
        raise RuntimeError("Use new corpus and virtualenv directories; existing files are preserved")
    run(["git", "clone", "--no-checkout", pin["repository"], str(corpus)])
    run(["git", "-C", str(corpus), "checkout", "--detach", pin["revision"]])
    run([sys.executable, "-m", "venv", str(venv)])
    run([str(venv / "bin/python"), "-m", "pip", "install", "-r", str(corpus / "requirements.txt")])
    print(f"Corpus: {corpus}\nPython3_EXECUTABLE: {venv / 'bin/python'}")


def generate(args):
    pin = json.loads(PIN.read_text())
    corpus = Path(args.corpus).resolve()
    check_corpus(corpus, pin["revision"])
    manifest = Path(args.manifest)
    command = [sys.executable, str(corpus / "daze_tests.py"), "emit-ctest", "--group", "required",
               "--manifest", str(manifest), "--evidence-dir", args.evidence_dir,
               "--hermetic-fixtures"]
    for backend in args.backends:
        command += ["--backend", backend]
    cmake = run(command, capture_output=True, text=True).stdout
    metadata = json.loads(manifest.read_text())
    if metadata.get("schema_version") != 1 or not metadata.get("pairs") or not metadata.get("tests"):
        raise RuntimeError("Corpus emitter returned an unsupported or empty selection manifest")
    metadata.update(**pin, corpus=str(corpus))
    manifest.write_text(json.dumps(metadata, indent=2) + "\n")
    Path(args.output).write_text(cmake)
    print(f"Registered {len(metadata['pairs'])} required pairs and {len(metadata['fixtures'])} fixture setups")


def stream_ctest(command, env, log_path):
    with log_path.open("w", buffering=1) as log:
        with subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, bufsize=1) as process:
            for line in process.stdout:
                log.write(line)
                print(line, end="", flush=True)
            return process.wait()


def new_invocation(base):
    base.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    latest = base / f".latest-{evidence.name}"
    try:
        latest.symlink_to(evidence.name, target_is_directory=True)
        latest.replace(base / "latest")
    finally:
        latest.unlink(missing_ok=True)
    return evidence


def validate(args):
    build = Path(args.build).resolve()
    evidence = new_invocation(build / ("external-evidence" if args.suite == "external" else "local-evidence"))
    summary = {"state": "running", "suite": args.suite, "expected": [], "executed": [],
               "rejected": [], "exit_status": None}
    report = evidence / "acceptance.json"
    report.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Evidence: {evidence}", flush=True)
    try:
        validate_invocation(args, build, evidence, summary)
        summary["state"] = "passed"
    except Exception as error:
        summary.update(state="failed", error=str(error))
        raise
    finally:
        report.write_text(json.dumps(summary, indent=2) + "\n")


def validate_invocation(args, build, evidence, summary):
    label = "^integration$" if args.suite == "external" else "^local$"
    selection = ["-L", label]
    if args.portable:
        if args.suite != "local":
            raise RuntimeError("--portable applies to local tests; select external backends at configuration")
        selection += ["-LE", "^requires-kvm$"]
    env = clean_environment()
    env["DAZE_TEST_INVOCATION_DIR"] = str(evidence)
    discovery = json.loads(run(["ctest", "--test-dir", str(build), *selection, "--show-only=json-v1"],
                               capture_output=True, text=True, env=env).stdout)
    (evidence / "discovery.json").write_text(json.dumps(discovery, indent=2) + "\n")
    expected = {t["name"] for t in discovery["tests"]}
    summary["expected"] = sorted(expected)
    if not expected:
        raise RuntimeError("No tests discovered")
    if len(expected) != len(discovery["tests"]):
        raise RuntimeError("Duplicate CTest registrations")
    metadata = {}
    if args.suite == "external":
        metadata = json.loads((build / "external-tests.json").read_text())
        summary.update(metadata)
        (evidence / "selection.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if len(metadata["tests"]) != len(set(metadata["tests"])):
            raise RuntimeError("Duplicate tests in external selection manifest")
        if expected != set(metadata["tests"]):
            raise RuntimeError(f"CTest registrations differ from required set: missing={set(metadata['tests']) - expected}, extra={expected - set(metadata['tests'])}")
        if metadata["revision"] != json.loads(PIN.read_text())["revision"]:
            raise RuntimeError("External registrations use an old pin; reconfigure the build")
        check_corpus(Path(metadata["corpus"]), metadata["revision"])
        command = next(t["command"] for t in discovery["tests"] if t["name"].startswith("compat."))
        binary = Path(command[command.index("--daze") + 1])
        metadata.update(daze_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                        daze_version=run([str(binary), "--version"], capture_output=True, text=True).stdout.strip())
        summary.update(metadata)
    junit = evidence / "tests.xml"
    command = ["ctest", "--test-dir", str(build), *selection, "-j1", "--output-on-failure", "--no-tests=error", "--output-junit", str(junit)]
    if args.suite == "local":
        command += ["--timeout", "60"]
    summary["command"] = command
    print(f"Running {len(expected)} {args.suite} tests serially in {build}", flush=True)
    status = stream_ctest(command, env, evidence / "ctest.log")
    summary["exit_status"] = status
    cases = list(ET.parse(junit).iter("testcase")) if junit.exists() else []
    executed = {c.attrib["name"] for c in cases}
    rejected = [c.attrib["name"] for c in cases if any(c.find(tag) is not None for tag in ("skipped", "failure", "error"))]
    summary.update(executed=sorted(executed), rejected=rejected, test_count=len(cases))
    if status or executed != expected or len(cases) != len(expected) or rejected:
        raise RuntimeError(f"Incomplete or failed CTest run: missing={expected - executed}, rejected={rejected}")


def check(args):
    """Verify a corpus checkout matches the pin, without side effects."""
    pin = json.loads(PIN.read_text())
    corpus = Path(args.corpus).resolve()
    if not (corpus / "daze_tests.py").exists():
        raise RuntimeError(
            f"No corpus checkout at {corpus}; run `python3 tools/external_tests.py prepare` "
            f"(see tests/README.md)")
    actual = run(["git", "-C", str(corpus), "rev-parse", "HEAD"], capture_output=True,
                 text=True).stdout.strip()
    if actual != pin["revision"]:
        raise RuntimeError(
            f"Corpus checkout {corpus} is at {actual}, pin requires {pin['revision']}.\n"
            f"Refresh the disposable helper clone, e.g.:\n"
            f"  git -C {corpus} fetch origin && git -C {corpus} checkout --detach {pin['revision']}\n"
            f"(see tests/README.md)")
    dirty = run(["git", "-C", str(corpus), "status", "--porcelain", "--", *CORPUS_PATHS],
                capture_output=True, text=True).stdout
    if dirty:
        raise RuntimeError(f"Pinned corpus test contents are dirty:\n{dirty}")
    lines = [f"Corpus: {corpus}", f"Revision: {actual} (matches pin)"]
    if args.build:
        manifest_path = Path(args.build).resolve() / "external-tests.json"
        if not manifest_path.exists():
            raise RuntimeError(
                f"No external-tests.json in {Path(args.build).resolve()}; configure a build "
                f"with DAZE_EXTERNAL_TESTS=ON first")
        metadata = json.loads(manifest_path.read_text())
        if metadata.get("revision") != pin["revision"]:
            raise RuntimeError(
                f"Build {Path(args.build).resolve()} registered corpus revision "
                f"{metadata.get('revision')}, pin requires {pin['revision']}; reconfigure the build")
        lines.append(f"Build manifest: {manifest_path} (matches pin)")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("probe-kvm")
    p.set_defaults(func=probe_kvm)
    p = commands.add_parser("prepare")
    p.add_argument("--corpus", default="build/daze-tests")
    p.add_argument("--venv", default="build/daze-tests-venv")
    p.set_defaults(func=prepare)
    p = commands.add_parser("check")
    p.add_argument("--corpus", default="build/daze-tests")
    p.add_argument("--build", default=None)
    p.set_defaults(func=check)
    p = commands.add_parser("generate")
    p.add_argument("--corpus", required=True)
    p.add_argument("--backends", nargs="+", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--evidence-dir", required=True)
    p.set_defaults(func=generate)
    p = commands.add_parser("run")
    p.add_argument("--build", required=True)
    p.add_argument("--suite", choices=("local", "external"), default="external")
    p.add_argument("--portable", action="store_true")
    p.set_defaults(func=validate)
    args = parser.parse_args()
    try:
        args.func(args)
    except (RuntimeError, OSError, ValueError, KeyError, ET.ParseError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"external-tests: {error}\n")


if __name__ == "__main__":
    main()
