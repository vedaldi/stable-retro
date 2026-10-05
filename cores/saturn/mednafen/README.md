# VF2 reverse-engineering instrumentation

This fork's `inspect` branch instruments Mednafen's Saturn core to trace
Virtua Fighter 2's 3D pipeline, for the vf2 project. It is not part of
upstream Mednafen or stable-retro.

All of it is in **`ss/vf2_re.inc`**, included once from `ss/ss.cpp`. The
upstream files only carry one-line hooks, listed at the top of that file:

| File | Hook |
|------|------|
| `ss/ss.cpp` | `#include "vf2_re.inc"`; `VF2RE_BeginFrame()` / `VF2RE_EndFrame()` around `Emulate()`'s run loop; `VF2RE_STATE_REGS` in `LibRetro_StateAction` |
| `ss/sh7095.inc` | `VF2RE_STEP()` in `SH7095::Step()`; `VF2RE_EXTBUS_WRITE()`; `VF2RE_SH2_DMA()`; `PC_IF`/`PC_ID` bookkeeping in the fetch macros |
| `ss/sh7095s_rsu.inc` | `VF2RE_STEP()` |
| `ss/scu.inc` | `VF2RE_SCU_DMA()` |

The traces:

- **`RE_VT`**: one record per vertex transformed by VF2's per-vertex
  transform, at `0x06028922`: the vertex, matrix, LUT entry and screen
  output, and which game element the call draws (player, part), classified
  from the return addresses on the stack at the routine's entry.
- **`RE_WR`**: a write watch on a physical address range, set per frame by
  the environment variable `VF2_WATCH="lo:hi"`. It logs SH-2 stores, SCU DMA
  and SH-2 DMAC transfers into the range.
- **`RE_PT`**: a register snapshot at one PC, set by `VF2_TRAP="pc:reg"`,
  with 256 words at `R[reg]` (e.g. the stack).

No libretro ABI or binding changes are needed: the traces are registered in
the savestate (`VF2RE_STATE_REGS`) and read back from
`env.unwrapped.em.get_state()` by `src/vf2/vt.py` and `src/vf2/re_trace.py`
in the vf2 project. See that project's `docs/` for what they found.

Traps run at the start of each instruction's EX step, keyed on `PC_ID`, the
address of the instruction about to execute, so a trap sees registers and
memory exactly as they are just before that instruction.
