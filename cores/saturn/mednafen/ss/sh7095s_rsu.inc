 enum : unsigned { which = 1 };
 enum : bool { EmulateICache = true };
 enum : bool { DebugMode = SH7095_DEBUG_MODE };
 enum : bool { CacheBypassHack = false };

 if(MDFN_UNLIKELY(timestamp >= bound_timestamp))
  return;

 if(ResumePoint)
 {
  const void* const tmp = ResumePoint;
  ResumePoint = nullptr;
  goto *tmp;
 }

 do
 {
  //
  // Ideally, we would place SPEPRecover: after the FRT event check, but doing
  // so causes gcc(multiple versions) to produce inconceivably awful code under certain conditions
  // (such as disabling all the SS_DBG stuff at compile-time) because it thinks it's an important loop
  // or something?(even with all our branch hinting!)
  //
  SPEPRecover:;

  if(MDFN_UNLIKELY(timestamp >= FRT_WDT_NextTS))
  {
   FRT_WDT_Update();
   FRT_WDT_Recalc_NET();
  }

  // Latch the executing instruction's address; PC_ID moves on once DoIDIF()
  // runs inside the instruction body.
  RE_EX_PC = PC_ID;

  // Pseudo-ops (standby, exception pending, DMA burst stall) aren't real
  // instructions; skip them so a trap fires once per executed instruction.
  if(MDFN_LIKELY(((Pipe_ID >> 24) & 0x7F) < 0x7E))
   RE_TRAPS();

  instr = (uint16)Pipe_ID;
  //
  #include "sh7095_ops.inc"
  //
 } while(timestamp < bound_timestamp);
