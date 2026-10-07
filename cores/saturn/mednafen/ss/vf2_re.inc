// VF2 reverse-engineering (RE) instrumentation for Mednafen's Saturn core.
//
// Not part of upstream Mednafen or stable-retro: everything the vf2 project
// adds to the core lives in this file, included once from ss.cpp (before
// scu.inc and sh7095.inc, which use it). Upstream files only carry one-line
// hooks:
//
//   ss.cpp           #include "vf2_re.inc"; VF2RE_BeginFrame() and
//                    VF2RE_EndFrame() around Emulate()'s run loop;
//                    VF2RE_STATE_REGS in LibRetro_StateAction's StateRegs
//   sh7095.inc       VF2RE_STEP() in SH7095::Step(), VF2RE_EXTBUS_WRITE() in
//                    ExtBusWrite_INLINE(), VF2RE_SH2_DMA() in DMA_DoTransfer(),
//                    and the PC_IF/PC_ID bookkeeping in the fetch macros
//                    (FetchIF_ForceIBufferFill, the decode and branch macros)
//   sh7095s_rsu.inc  VF2RE_STEP()
//   scu.inc          VF2RE_SCU_DMA() in StartDMATransfer()
//
// The traces reach Python through the savestate (VF2RE_STATE_REGS), so no
// libretro or binding changes are needed; see src/vf2/vt.py and
// src/vf2/re_trace.py in the vf2 project, and its docs/.

// One trap, RE_VT, in the per-vertex transform-and-project routine
// (0x060288a4-0x0602892a; see docs/vf2-vertex-transform.md). It fires at
// 0x06028922, `mov.l r2,@(0,r12)`, the store of the vertex's packed screen
// position: every value the vertex's computation needs or produces is live
// in a register or in memory there. Traps run just before the instruction at
// their PC executes, with all earlier instructions completed (see RE_TRAPS()
// below). Both SH-2 cores run this routine, so each record carries
// its core.
//
// Register state at 0x06028922 (traced through the routine):
//   R6  = &matrix[0][0] (back at its entry value)
//   R14 = vertex + 12 (already advanced to the next vertex)
//   R15 = stack, @R15 = the routine's saved r4 argument (PDATA*)
//   R13 = vertices remaining after this one (0 on the call's last vertex)
//   R0  = &LUT[lut_index], R11 = zp_cam, R2 = packed(u, v) about to be
//   stored at R12, R5 = packed(zp_cam, x_cam) already stored at R12+4
//
// Records go into a ring buffer, one per vertex, in execution order, each
// tagged with RE_VT.frame, the index of the Emulate() call (= env.step()) it
// was written in, and RE_VT.loop, the game's logical frame (see RE_LOOP_PC
// below); Python selects a frame's records by these tags, within the
// last min(RE_VT.count, RE_VT_TRACE_SIZE) slots. RE_VT -- counters and buffer
// -- is one savestate entry, so a state either restores all of it or (if
// saved with a different layout) none of it, and the two always agree. The
// layout is mirrored by `VtTrace` and `VtCallRecord` in src/vf2/vt.py.
enum : uint32 { RE_VT_PC = 0x06028922 };
struct RE_VTRecord
{
 uint32 frame;        // RE_VT.frame when written
 uint32 loop;         // RE_VT.loop when written: the game's logical frame
 uint32 core;         // 0 = master (CPU[0]), 1 = slave
 uint32 pr;           // caller's return address
 uint32 pdata;        // PDATA* argument (read from @R15)
 uint32 pntbl;        // PDATA.pntbl, the call's vertex array (read from @PDATA)
 uint32 remaining;    // R13
 uint32 vertex_addr;  // R14 - 12
 uint32 vertex[3];    // object-space vertex, Q16.16
 uint32 matrix_addr;  // R6
 uint32 matrix[12];   // 3x4 matrix, Q16.16, row-major
 uint32 zp_cam;       // R11
 uint32 lut_addr;     // R0
 uint32 lut[2];       // LUT[lut_index] = (coef_x, coef_y), Q16.16
 uint32 out[2];       // output slot: R2 = packed(u, v), screen position relative to center; R5 = packed(zp_cam, x_cam)
 uint32 out_addr;     // R12: output slot
 uint32 player;       // whose draw pass the call is in (RE_VT_Ctx): 0 = none, 1, 2
 uint32 part;         // what the call draws (RE_VT_Ctx): RE_PART_*
};
static_assert(sizeof(RE_VTRecord) == 33 * sizeof(uint32), "RE_VTRecord must have no padding");
enum : unsigned { RE_VT_TRACE_SIZE = 8192 };
struct RE_VTTrace
{
 uint32 count;  // records written so far; the next goes to records[count % RE_VT_TRACE_SIZE]
 uint32 frame;  // Emulate() calls so far
 uint32 loop;   // main-loop iterations started so far (RE_LOOP_PC)
 uint32 synced; // the last iteration to reach its vblank wait (RE_SYNC_PC): its draws are all issued
 RE_VTRecord records[RE_VT_TRACE_SIZE];
};
static_assert(sizeof(RE_VTTrace) == (4 + RE_VT_TRACE_SIZE * 33) * sizeof(uint32), "RE_VTTrace must have no padding");
RE_VTTrace RE_VT;

// The game's logical frame: one iteration of its main loop, on the master,
// 0x0600406E-0x060040EE (docs/vf2-sync.md). Each iteration runs the game
// mode's handler, then the task runner 0x06004842 (which draws both
// players), then waits for the vblank (the call at 0x060040C8); the emulator
// ends each frame at a fixed point instead, so a late iteration's draws can
// straddle two Emulate() calls, and an iteration can span several.
// RE_VT.loop counts the iterations started (the loop head, RE_LOOP_PC), and
// RE_VT.synced is the last iteration to reach its vblank wait (RE_SYNC_PC).
enum : uint32 { RE_LOOP_PC = 0x0600406E, RE_SYNC_PC = 0x060040C8 };

// What each vertex transform call draws, from the return addresses on the
// stack at its entry (RE_VT_ENTRY_PC; see docs/vf2-scene-objects.md). Each
// player is drawn by 0x06017B54: player 1 on the master, returning to
// 0x06017AE8, player 2 as a slave task, returning to 0x06017B44. Within it,
// the innermost of these return addresses identifies the part. Set per core
// at each call's entry; copied into the call's RE_VTRecords.
enum : uint32 { RE_VT_ENTRY_PC = 0x060288A4 };
enum : uint32
{
 RE_PART_NONE = 0,          // not inside a player's draw
 RE_PART_OTHER = 1,         // inside 0x06017B54, no known part
 RE_PART_BODY = 2,          // the body, drawn inline (returns 0x06017C12, 0x06017C1E)
 RE_PART_DETAIL = 3,        // character-specific details (hair, clothing), 0x06023D44 (returns 0x06017BCC)
 RE_PART_SHADOW = 4,        // ground shadows, 0x06017E54 (returns 0x06017BC0)
 RE_PART_STAGE_EFFECT = 5,  // 0x0602C8F4, e.g. the leaves (returns 0x0602C820); player 1's pass only
 RE_PART_PLAYER_EFFECT = 6, // 0x0602C832, per player (returns 0x0602C7C8); player 1's pass only
};
enum : unsigned { RE_VT_CTX_SCAN = 512 };  // stack words searched
struct RE_VTContext { uint32 player, part; };
static RE_VTContext RE_VT_Ctx[2];  // per core, for the call in progress

// RE_WR: a write watch on one physical address range [lo, hi) (A & 0x07FFFFFF,
// so cache-through mirrors coincide; e.g. VDP2 VRAM is 0x05E00000-0x05E80000).
// Logs every SH-2 store into it (with the storing core's PC and PR), every
// SCU DMA transfer whose destination overlaps it, and every SH-2 DMAC unit
// written into it. The range is re-read at each Emulate() from the
// environment variable VF2_WATCH="lo:hi" (C integer syntax); unset = off.
enum : uint32 { RE_WR_STORE = 0, RE_WR_SCU_DMA = 1, RE_WR_SH2_DMA = 2 };
struct RE_WRRecord
{
 uint32 frame;   // RE_VT.frame when written
 uint32 kind;    // RE_WR_*
 uint32 unit;    // store/SH-2 DMA: core (0 = master); SCU DMA: level
 uint32 pc;      // store: address of the store instruction; else 0
 uint32 pr;      // store: PR; else 0
 uint32 addr;    // store/SH-2 DMA: address written; SCU DMA: destination start
 uint32 value;   // store: value; SCU DMA/SH-2 DMA: source address
 uint32 size;    // store/SH-2 DMA: bytes; SCU DMA: byte count
};
enum : unsigned { RE_WR_TRACE_SIZE = 16384 };
struct RE_WRTrace
{
 uint32 count;  // records written so far; the next goes to records[count % RE_WR_TRACE_SIZE]
 uint32 lo, hi; // the watched range (lo == hi: off)
 RE_WRRecord records[RE_WR_TRACE_SIZE];
};
static_assert(sizeof(RE_WRTrace) == (3 + RE_WR_TRACE_SIZE * 8) * sizeof(uint32), "RE_WRTrace must have no padding");
RE_WRTrace RE_WR;

// RE_PT: a register snapshot at one PC, set at each Emulate() from the
// environment variable VF2_TRAP="pc:reg" (unset = off): all registers, and
// the RE_PT_MEM words at the address in R[reg]. Runs where RE_VT does (RE_TRAPS()),
// just before the instruction at pc executes.
enum : unsigned { RE_PT_MEM = 256 };  // words snapshotted at R[reg] (e.g. the stack, reg 15)
struct RE_PTRecord
{
 uint32 frame;
 uint32 core;
 uint32 R[16];
 uint32 pr, gbr, mach, macl;
 uint32 mem[RE_PT_MEM];
};
enum : unsigned { RE_PT_TRACE_SIZE = 256 };
struct RE_PTTrace
{
 uint32 count;
 uint32 pc, reg;  // pc == 0: off
 RE_PTRecord records[RE_PT_TRACE_SIZE];
};
static_assert(sizeof(RE_PTRecord) == (22 + RE_PT_MEM) * sizeof(uint32), "RE_PTRecord must have no padding");
RE_PTTrace RE_PT;

static INLINE bool RE_WR_Hit(uint32 a, uint32 n)
{
 a &= 0x07FFFFFF;
 return a < RE_WR.hi && a + n > RE_WR.lo;
}

static INLINE void RE_WR_Log(uint32 kind, uint32 unit, uint32 pc, uint32 pr, uint32 addr, uint32 value, uint32 size)
{
 RE_WRRecord& r = RE_WR.records[RE_WR.count++ % RE_WR_TRACE_SIZE];
 r = { RE_VT.frame, kind, unit, pc, pr, addr, value, size };
}

static INLINE uint32 RE_ReadWorkRAM32(uint32 addr)
{
 uint32 off;
 if(addr >= 0x00200000 && addr <= 0x003FFFFF)
  off = addr & 0xFFFFF;
 else if(addr >= 0x06000000 && addr <= 0x07FFFFFF)
  off = 0x100000 + (addr & 0xFFFFF);
 else
  return 0;
 uint16 hi = *(uint16*)&WorkRAM[off];
 uint16 lo = *(uint16*)&WorkRAM[off + 2];
 return (((uint32)hi) << 16) | lo;
}

static RE_VTContext RE_VT_Classify(uint32 sp)
{
 RE_VTContext ctx = { 0, RE_PART_NONE };
 for(unsigned i = 0; i < RE_VT_CTX_SCAN && !ctx.player; i++)
 {
  const uint32 w = RE_ReadWorkRAM32(sp + i * 4);
  uint32 part = RE_PART_NONE;
  switch(w)
  {
   case 0x06017AE8: ctx.player = 1; break;
   case 0x06017B44: ctx.player = 2; break;
   case 0x06017C12: case 0x06017C1E: part = RE_PART_BODY; break;
   case 0x06017BCC: part = RE_PART_DETAIL; break;
   case 0x06017BC0: part = RE_PART_SHADOW; break;
   case 0x0602C820: part = RE_PART_STAGE_EFFECT; break;
   case 0x0602C7C8: part = RE_PART_PLAYER_EFFECT; break;
  }
  if(part != RE_PART_NONE && ctx.part == RE_PART_NONE)
   ctx.part = part;  // the innermost
 }
 if(ctx.player && ctx.part == RE_PART_NONE)
  ctx.part = RE_PART_OTHER;
 if(!ctx.player)
  ctx.part = RE_PART_NONE;
 return ctx;
}

/* RE trace traps.  Run at the start of each instruction's EX step, keyed on */
/* PC_ID (the address of the instruction in Pipe_ID): every earlier        */
/* instruction has completed and the one at PC_ID has not yet run, so      */
/* registers and memory are exactly as they are just before PC_ID.        */
/*								*/
#define RE_TRAPS()                                                      \
{                                                                       \
 if(MDFN_UNLIKELY(PC_ID == RE_VT_PC))                                   \
 {                                                                      \
  RE_VTRecord& re_rec = RE_VT.records[RE_VT.count % RE_VT_TRACE_SIZE]; \
  const uint32 re_vertex = R[14] - 12;                                  \
  re_rec.frame = RE_VT.frame;                                           \
  re_rec.loop = RE_VT.loop;                                             \
  re_rec.core = (this == &CPU[0]) ? 0 : 1;                              \
  re_rec.pr = PR;                                                       \
  re_rec.pdata = RE_ReadWorkRAM32(R[15]);                               \
  re_rec.pntbl = RE_ReadWorkRAM32(re_rec.pdata);                        \
  re_rec.remaining = R[13];                                             \
  re_rec.vertex_addr = re_vertex;                                       \
  for(unsigned re_i = 0; re_i < 3; re_i++)                              \
   re_rec.vertex[re_i] = RE_ReadWorkRAM32(re_vertex + re_i * 4);        \
  re_rec.matrix_addr = R[6];                                            \
  for(unsigned re_i = 0; re_i < 12; re_i++)                             \
   re_rec.matrix[re_i] = RE_ReadWorkRAM32(R[6] + re_i * 4);             \
  re_rec.zp_cam = R[11];                                                \
  re_rec.lut_addr = R[0];                                               \
  re_rec.lut[0] = RE_ReadWorkRAM32(R[0]);                               \
  re_rec.lut[1] = RE_ReadWorkRAM32(R[0] + 4);                           \
  re_rec.out[0] = R[2];                                                 \
  re_rec.out[1] = R[5];                                                 \
  re_rec.out_addr = R[12];                                              \
  re_rec.player = RE_VT_Ctx[re_rec.core].player;                        \
  re_rec.part = RE_VT_Ctx[re_rec.core].part;                            \
  RE_VT.count++;                                                        \
 }                                                                      \
 if(MDFN_UNLIKELY(PC_ID == RE_VT_ENTRY_PC))                             \
  RE_VT_Ctx[this != &CPU[0]] = RE_VT_Classify(R[15]);                   \
 if(MDFN_UNLIKELY(PC_ID == RE_LOOP_PC) && this == &CPU[0])              \
  RE_VT.loop++;                                                         \
 if(MDFN_UNLIKELY(PC_ID == RE_SYNC_PC) && this == &CPU[0])              \
  RE_VT.synced = RE_VT.loop;                                            \
 if(MDFN_UNLIKELY(PC_ID == RE_PT.pc))                                   \
 {                                                                      \
  RE_PTRecord& re_pt = RE_PT.records[RE_PT.count++ % RE_PT_TRACE_SIZE]; \
  re_pt.frame = RE_VT.frame;                                            \
  re_pt.core = (this == &CPU[0]) ? 0 : 1;                               \
  for(unsigned re_i = 0; re_i < 16; re_i++)                             \
   re_pt.R[re_i] = R[re_i];                                             \
  re_pt.pr = PR;                                                        \
  re_pt.gbr = GBR;                                                      \
  re_pt.mach = MACH;                                                    \
  re_pt.macl = MACL;                                                    \
  for(unsigned re_i = 0; re_i < RE_PT_MEM; re_i++)                      \
   re_pt.mem[re_i] = RE_ReadWorkRAM32(R[RE_PT.reg] + re_i * 4);         \
 }                                                                      \
}

// Run at the start of each instruction's EX step (SH7095::Step and the RSU
// variant). Pseudo-ops (standby, exception pending, DMA burst stall) aren't
// real instructions; skip them so a trap fires once per executed instruction.
#define VF2RE_STEP()                                                    \
{                                                                       \
 if(MDFN_LIKELY(((Pipe_ID >> 24) & 0x7F) < 0x7E))                      \
  RE_TRAPS();                                                           \
}

// RE_WR hooks: an SH-2 store (in SH7095::ExtBusWrite_INLINE), an SH-2 DMAC
// unit (in SH7095::DMA_DoTransfer; ts = transfer size code), and an SCU DMA
// transfer (in StartDMATransfer).
#define VF2RE_EXTBUS_WRITE(A, V)                                        \
{                                                                       \
 if(MDFN_UNLIKELY(RE_WR_Hit((A), sizeof(V))))                           \
  RE_WR_Log(RE_WR_STORE, this != &CPU[0], PC_ID, PR, (A), (V), sizeof(V)); \
}

#define VF2RE_SH2_DMA(dar, sar, ts)                                     \
{                                                                       \
 const uint32 re_n = 1U << std::min<unsigned>((ts), 2) << ((ts) == 3 ? 2 : 0); \
 if(MDFN_UNLIKELY(RE_WR_Hit((dar), re_n)))                              \
  RE_WR_Log(RE_WR_SH2_DMA, this != &CPU[0], 0, 0, (dar) & 0x07FFFFFF, (sar) & 0x07FFFFFF, re_n); \
}

#define VF2RE_SCU_DMA(d, wa, ra, bc)                                    \
{                                                                       \
 if(MDFN_UNLIKELY(RE_WR_Hit((wa), (bc))))                               \
  RE_WR_Log(RE_WR_SCU_DMA, (unsigned)((d) - DMALevel), 0, 0, (wa) & 0x07FFFFFF, (ra) & 0x07FFFFFF, (bc)); \
}

// Per Emulate() call (= env.step()): read the RE_WR/RE_PT settings from the
// environment before the run loop, and count the frame after it.
static void VF2RE_BeginFrame(void)
{
 const char* w = getenv("VF2_WATCH");
 char* end = nullptr;
 RE_WR.lo = RE_WR.hi = 0;
 if(w)
 {
  RE_WR.lo = strtoul(w, &end, 0) & 0x07FFFFFF;
  if(end && *end == ':')
   RE_WR.hi = strtoul(end + 1, nullptr, 0) & 0x07FFFFFF;
 }
 const char* t = getenv("VF2_TRAP");
 RE_PT.pc = RE_PT.reg = 0;
 if(t)
 {
  RE_PT.pc = strtoul(t, &end, 0);
  if(end && *end == ':')
   RE_PT.reg = strtoul(end + 1, nullptr, 0) & 0xF;
 }
}

static void VF2RE_EndFrame(void)
{
 RE_VT.frame++;
}

// Entries for LibRetro_StateAction's StateRegs: the traces ride out to
// Python through the savestate.
#define VF2RE_STATE_REGS                                                \
  SFPTR32N(&RE_VT.count, sizeof(RE_VT) / sizeof(uint32), "RE_VT"),      \
  SFPTR32N(&RE_WR.count, sizeof(RE_WR) / sizeof(uint32), "RE_WR"),      \
  SFPTR32N(&RE_PT.count, sizeof(RE_PT) / sizeof(uint32), "RE_PT"),
