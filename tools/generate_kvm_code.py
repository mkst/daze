#!/usr/bin/env python3
"""Emit the portable C byte arrays for the KVM guest-side assembly helpers.

Usage: generate_kvm_code.py <profile> | --check [<profile>]

Profiles and their section tables live in PROFILES below. The output is a
header of static uint8_t arrays with the disassembly as per-instruction
comments; pipe it through clang-format before applying it to the checked-in
header.
"""
import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

PROFILES = {
  "exception_delivery": {
    "source": "src/backend/kvm/exception_delivery.S",
    "entry": "exception_delivery",
    "sections": [{"name": "exception_delivery_code", "section": ".text",
                  "base": 0xfdd000, "limit": 0xfdd800, "start": 0xfdd000,
                  "disasm": "intel"}],
  },
  "exception_return": {
    "source": "src/backend/kvm/exception_return.S",
    "entry": "exception_return",
    "sections": [{"name": "exception_return_code", "section": ".text",
                  "base": 0xee00, "limit": 0xf100, "start": 0xee00,
                  "disasm": "intel"}],
  },
  "rm_entry": {
    "source": "src/backend/kvm/rm_entry.S",
    "entry": "native_entry",
    "sections": [
      {
        "name": "native_entry_code",
        "section": ".text",
        "base": 0x5000,
        "limit": 0x5800,
        "start": 0x5000,
        "disasm": "intel",
      },
      {
        "name": "native_set_descriptor_code",
        "section": ".set_descriptor",
        "base": 0x5ea0,
        "limit": 0x5ffc,
        "start": 0x5ea0,
        "disasm": "intel",
      },
      {
        "name": "native_low_code",
        "section": ".low",
        "base": 0x2720,
        "limit": 0x2800,
        "start": 0x2720,
        "disasm": "intel,addr16,data16",
        "raw_tail_bytes": 6,
        "raw_tail_comment": "real-mode IDTR: limit 03ffh, base 0",
      },
      {
        "name": "native_get_base_code",
        "section": ".get_base",
        "base": 0x2800,
        "limit": 0x2a00,
        "start": 0x2800,
        "disasm": "intel",
      },
    ],
  },
  "write_batch": {
    "source": "src/backend/kvm/write_batch.S",
    "entry": "write_entry",
    "sections": [
      {
        "name": "write_batch_code",
        "section": ".text",
        "base": 0,
        "limit": 0x400,
        "start": 0,
        "disasm": "intel,addr16,data16",
      },
    ],
  },
}

INSTRUCTION = re.compile(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s+(.+)")


def emit_section(lines, root, binary_path, spec):
  data = binary_path.read_bytes()
  base = spec["base"]
  if base + len(data) > spec["limit"]:
    raise ValueError("callback code overlaps private state")
  disassembly = subprocess.check_output(
    ["objdump", "-D", "-b", "binary", "-m", "i386", "-M", spec["disasm"],
     "--insn-width=16", "--adjust-vma=" + str(base), str(binary_path)], text=True)
  raw_tail = spec.get("raw_tail_bytes", 0)
  lines.extend(["", "static const uint8_t " + spec["name"] + "[] = {"])
  consumed = 0
  for line in disassembly.splitlines():
    match = INSTRUCTION.match(line)
    if not match:
      continue
    address = int(match[1], 16)
    instruction = bytes.fromhex(match[2])
    if raw_tail and consumed + len(instruction) > len(data) - raw_tail:
      break
    if address != base + consumed or data[consumed:consumed + len(instruction)] != instruction:
      raise ValueError("disassembly does not cover callback bytes")
    lines.append("  " + ", ".join(f"0x{x:02x}" for x in instruction) +
                 ", /* " + match[3].strip() + " */")
    consumed += len(instruction)
  if consumed < len(data):
    if consumed != len(data) - raw_tail:
      raise ValueError("unexplained bytes after callback code")
    lines.append("  " + ", ".join(f"0x{x:02x}" for x in data[consumed:]) +
                 ", /* " + spec["raw_tail_comment"] + " */")
  lines.append("};")


def generate(profile):
  config = PROFILES[profile]
  source = REPO / config["source"]
  lines = ["#ifndef DAZE_KVM_" + profile.upper() + "_CODE_H",
           "#define DAZE_KVM_" + profile.upper() + "_CODE_H", "",
           "#include <stdint.h>", "",
           "/* Generated from " + source.name + " with tools/generate_kvm_code.py. */"]
  with tempfile.TemporaryDirectory(prefix="daze-kvm-code-") as directory:
    root = Path(directory)
    obj, elf = root / "entry.o", root / "entry.elf"
    subprocess.run(["as", "--32", str(source), "-o", str(obj)], check=True)
    subprocess.run(["ld", "-m", "elf_i386", "-e", config["entry"]] +
                   sum([["--section-start=" + s["section"] + "=" + hex(s["start"])]
                        for s in config["sections"]], []) +
                   [str(obj), "-o", str(elf)], check=True)
    for spec in config["sections"]:
      binary = root / (spec["name"] + ".bin")
      subprocess.run(["objcopy", "-O", "binary", "--only-section=" + spec["section"],
                      str(elf), str(binary)], check=True)
      emit_section(lines, root, binary, spec)
  lines.extend(["", "#endif", ""])
  return "\n".join(lines)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("profile", nargs="?", choices=PROFILES)
  parser.add_argument("--check", action="store_true", help="Check headers without writing them")
  args = parser.parse_args()
  if args.check:
    stale = False
    for profile in (args.profile,) if args.profile else PROFILES:
      source = REPO / PROFILES[profile]["source"]
      header = source.with_name(source.stem + "_code.h")
      # clang-format wraps arrays and aligns comments without changing their contents.
      expected = re.sub(r"\s+", "", generate(profile))
      actual = re.sub(r"\s+", "", header.read_text()) if header.exists() else None
      if actual != expected:
        print(f"Stale generated header: {header.relative_to(REPO)}", file=sys.stderr)
        stale = True
    return int(stale)
  if args.profile is None:
    parser.error("a profile is required unless --check is used")
  sys.stdout.write(generate(args.profile))
  return 0


if __name__ == "__main__":
  sys.exit(main())
