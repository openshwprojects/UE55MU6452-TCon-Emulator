"""Swap bytes within each 32-bit word (BE -> LE) for Ghidra import."""
import os
DIR = os.path.dirname(os.path.abspath(__file__))
data = open(os.path.join(DIR, "flash2.bin"), "rb").read()
out = bytearray()
for i in range(0, len(data) - 3, 4):
    out.extend(data[i:i+4][::-1])
open(os.path.join(DIR, "flash2_swapped.bin"), "wb").write(out)
print(f"Done: flash2_swapped.bin ({len(out)} bytes)")
