#!/usr/bin/env python3
"""Emit the portable C byte arrays for the KVM DOS write-batching helper."""
import re
import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
source = repo / "src/backend/kvm/write_batch.S"
lines = ["#ifndef DAZE_KVM_WRITE_BATCH_CODE_H", "#define DAZE_KVM_WRITE_BATCH_CODE_H", "",
         "#include <stdint.h>", "",
         "/* Generated from write_batch.S with tools/generate_kvm_write_batch.py. */"]
with tempfile.TemporaryDirectory(prefix="daze-write-batch-") as directory:
    root = Path(directory)
    obj, elf = root / "entry.o", root / "entry.elf"
    subprocess.run(["as", "--32", str(source), "-o", str(obj)], check=True)
    subprocess.run(["ld", "-m", "elf_i386", "-e", "write_entry",
                    "--section-start=.text=0",
                    str(obj), "-o", str(elf)], check=True)
    for name, section, base, options in [
        ("write_batch_code", ".text", 0, "intel,addr16,data16"),
    ]:
        binary = root / (name + ".bin")
        subprocess.run(["objcopy", "-O", "binary", "--only-section=" + section,
                        str(elf), str(binary)], check=True)
        data = binary.read_bytes()
        limit = 0x400
        if base + len(data) > limit:
            raise ValueError("write code overlaps private state")
        disassembly = subprocess.check_output([
            "objdump", "-D", "-b", "binary", "-m", "i386", "-M", options,
            "--insn-width=16", "--adjust-vma=" + str(base), str(binary)], text=True)
        lines.extend(["", "static const uint8_t " + name + "[] = {"])
        consumed = 0
        for line in disassembly.splitlines():
            match = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s+(.+)", line)
            if not match:
                continue
            address = int(match[1], 16)
            instruction = bytes.fromhex(match[2])
            if address != base + consumed or data[consumed:consumed + len(instruction)] != instruction:
                raise ValueError("disassembly does not cover write bytes")
            lines.append("  " + ", ".join(f"0x{x:02x}" for x in instruction) +
                         ", /* " + match[3].strip() + " */")
            consumed += len(instruction)
        if consumed != len(data):
            raise ValueError("unexplained bytes after write code")
        lines.append("};")
lines.extend(["", "#endif", ""])
print("\n".join(lines), end="")
