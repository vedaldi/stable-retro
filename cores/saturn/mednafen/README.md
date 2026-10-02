# VF2 reverse-engineering instrumentation

This copy of Mednafen's Saturn core (`ss/ss.cpp`, `ss/sh7095.inc`) carries a
patch — added on this fork's `inspect` branch, see `git log` on that branch
— that instruments the SH-2 interpreter with 16 independent trace sites
(`RE2` through `RE16`) used to reverse-engineer Virtua Fighter 2's vertex
pipeline. It is not part of upstream Mednafen or stable-retro.

Each site is a ring buffer (or, for `RE15`, a fixed-size non-wrapping log)
that fires on either an instruction fetch at a specific PC, an instruction
fetch across a PC range, or an external-bus write into a specific address
range. All sites share one global monotonic counter, `RE_GlobalSeq`, so
independently-sized/shaped buffers can still be merged back into one
chronological order after the fact.

No libretro ABI or stable-retro Python/C++ binding changes were needed: every
trace array is registered in `LibRetro_StateAction`'s `SFVAR` list, so the
captured data rides out through the engine's existing, unmodified
`retro_serialize()` / savestate mechanism. On the vf2 project side,
`src/vf2/transform_capture.py` reads these arrays back out of a savestate.

See `docs/re/README.md` and `docs/re/disassembly_evidence.s` in the vf2
project for the analysis that motivated each site and the findings drawn
from its captured data.

## Trace sites

- **RE2** — external-bus writes into the shared per-vertex-cache table
  (`0x06096eb0 - 0x2000` .. `+0x8000`, widened after a second character's
  output table was found 0x800 bytes below the first). Captures PC, PR,
  address, value, the full register file, sequence number, and which SH-2
  core (master/slave) wrote it.
- **RE3** — instruction fetch at `0x060288b6`, right before the suspected
  matrix-multiply dot-product sequence. Captures the full register file, a
  24-word window of the matrix workspace at `R[6]-48`, a 5-word vertex
  record at `R[14]`, sequence number, and core.
- **RE4** — instruction fetch at `0x060288a6`, the entry point of section
  1's vertex-transform subroutine. Fires once per *call* (not per vertex):
  captures PR, R4, R6, the vertex count read from memory at `R4+4`,
  sequence number, and core.
- **RE5** — external-bus writes into the confirmed "current matrix"
  workspace (`0x06051d00`, 48 bytes: rowA/rowB/rowC + 3 biases). Captures
  PC, PR, address, value, sequence number. Master core only.
- **RE6** — instruction fetch at `0x0602c962`, the `jsr` into
  `vtable[48]`/`slTranslate` inside the confirmed old bone loop. Captures
  the bone counter (`R12`) and the translation `tx/ty/tz` (`R4/R5/R6`).
  Master core only.
- **RE7** — instruction fetch at `0x0602c946`, the bone-loop body branch
  target reached before each iteration's own `slPushMatrix`. Captures the
  shared parent-level rowB/rowC read straight out of the matrix workspace.
  Master core only.
- **RE8** — instruction fetch at `0x06017e98`, inside the SGL-vtable-driven
  draw-list loop. Captures the bounding-record pointer (`R0`) and the
  values at offsets `+36`, `+40`, `+44` (a translation triple, of which the
  game's own clip test only reads `+36`/`+44`). Master core only.
- **RE9** — instruction fetch at `0x0602e0c8` (retargeted 2 bytes past the
  vtable[60] return site, which the interpreter's fetch path never visits
  directly). Captures `R8` and an 11-word memory dump around it, to probe
  for a genuine per-node position field in the 44-byte scene-graph node
  record. Master core only.
- **RE10** — every instruction fetch across `0x0602e090`-`0x0602e120`
  (whole-function PC range), logging just PC and sequence number, used to
  recover the real control flow through that function when RE9's
  single-PC trap failed to fire as expected. Master core only.
- **RE11** / **RE12** — instruction fetch at `0x06028912` and `0x0602891a`,
  the two perspective-divide LUT coefficient loads (`LUT[idx][0]` and
  `LUT[idx][1]`). Each captures the full register file and sequence number,
  so both can be matched back to the RE3 vertex hit they belong to.
- **RE13** — every instruction fetch across the whole per-vertex loop
  (`0x060288a6`-`0x06028928`), logging PC and the full register file,
  cycle by cycle. Unguarded (merges both cores), to correlate 1:1 against
  RE3.
- **RE14** — every instruction fetch across the narrower rowA-accumulation
  window (`0x060288b4`-`0x060288cc`), additionally logging the `MACH`/
  `MACL` accumulator registers so the three `mac.l` steps can be observed
  settling, not just the final result. Unguarded, ambient (non-incrementing)
  `RE_GlobalSeq` read so each row ties back to its own RE3 hit.
- **RE15** — at each call into `0x060288a6` (same PC as RE4), dumps the
  *entire* 2MB WorkRAM buffer plus R4, R6, and PR. Not a ring buffer (fixed
  cap of 200 snapshots) since it exists to validate a Python
  re-implementation of the function end-to-end, not to align with one
  frame's hits. Dominates this patch's savestate size (~400MB at full
  capacity) but is cheap to read/write in practice. Master core only.
- **RE16** — instruction fetch at `0x0602890c`, the confirmed
  `mov.l @(0,r0),r3` LUT-coefficient load. Reads both raw coefficient
  dwords directly out of WorkRAM at that instant (rather than trusting a
  single later RAM snapshot, since that memory is reused per-object within
  a frame). Captures address, both coefficients, sequence number, and core.

`RE_ReadWorkRAM32` is a small helper shared by several sites above to read a
32-bit word directly out of the WorkRAM backing array (both the `0x002xxxxx`
and `0x06xxxxxx` aliases), independent of the CPU's own load/store timing.
