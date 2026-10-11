#include "runtime.c"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

static void descriptor(uc_engine *uc, uint16_t selector, uint32_t base, uint8_t access) {
  uint8_t bytes[8];
  daze_dpmi_descriptor_encode(bytes, base, 0xffff, access, 0);
  assert(uc_mem_write(uc, k_dpmi_gdt_address + selector, bytes, 8) == UC_ERR_OK);
}

static uc_engine *fixture(void) {
  uc_engine *uc;
  assert(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  assert(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  descriptor(uc, 8, 0x10000, 0x9a);
  descriptor(uc, 0x10, 0x20000, 0x92);
  descriptor(uc, 0x18, 0x30000, 0x92);
  descriptor(uc, 0x20, 0x40000, 0x1a);
  uc_x86_mmr gdtr = {.base = k_dpmi_gdt_address, .limit = 0xff};
  assert(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) == UC_ERR_OK);
  set_reg32(uc, UC_X86_REG_CR0, 1);
  set_reg16(uc, UC_X86_REG_CS, 8);
  set_reg16(uc, UC_X86_REG_DS, 0x10);
  set_reg16(uc, UC_X86_REG_ES, 0x10);
  set_reg16(uc, UC_X86_REG_SS, 0x18);
  set_reg32(uc, UC_X86_REG_ESP, 0x800);
  set_reg16(uc, UC_X86_REG_IP, 0x100);
  return uc;
}

static void exception_operands(void) {
  uc_engine *uc = fixture();
  DazeDpmiProcessState dpmi = {0};
  dpmi.exception_vector_segment[0xb] = 8;
  const uint8_t instructions[][8] = {
    {0xff, 0x1e, 0x00, 0x02}, /* call far [0200h] */
    {0x26, 0xc4, 0x3f},       /* les di,es:[bx] */
    {0xcb},                   /* retf */
    {0xca, 0x04, 0x00},       /* retf 4 */
  };
  uint8_t pointer[4];
  daze_write_u16(pointer, 0x1234);
  daze_write_u16(pointer + 2, 0x20);
  for (size_t form = 0; form < 4; ++form) {
    assert(uc_mem_write(uc, 0x10100, instructions[form], 8) == UC_ERR_OK);
    assert(uc_mem_write(uc, 0x20200, pointer, 4) == UC_ERR_OK);
    assert(uc_mem_write(uc, 0x30800, pointer, 4) == UC_ERR_OK);
    set_reg16(uc, UC_X86_REG_BX, 0x200);
    DazeDpmiExceptionFault fault = {0};
    assert(daze_dpmi_exception_classify(uc, &dpmi, &fault));
    assert(fault.error_code == 0x20 && fault.fault_cs == 8 && fault.fault_ip == 0x100);
    assert(fault.instruction_size == (form == 0 ? 4 : form == 1 ? 3 : form == 2 ? 1 : 3));
    int reg = form < 2 ? (form == 0 ? UC_X86_REG_DS : UC_X86_REG_ES) : UC_X86_REG_SS;
    uint16_t saved = get_reg16(uc, reg);
    set_reg16(uc, reg, 0);
    assert(!daze_dpmi_exception_classify(uc, &dpmi, &fault));
    set_reg16(uc, reg, saved);
    uint32_t address = form < 2 ? 0x20000 : 0x30000;
    assert(uc_mem_unmap(uc, address, 0x1000) == UC_ERR_OK);
    assert(!daze_dpmi_exception_classify(uc, &dpmi, &fault));
    assert(uc_mem_map(uc, address, 0x1000, UC_PROT_ALL) == UC_ERR_OK);
  }
  uc_close(uc);
}

static void flags_and_switch(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  uint8_t frame[6] = {0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb}, after[6];
  assert(uc_mem_write(uc, 0x30800, frame, 6) == UC_ERR_OK);
  set_reg32(uc, UC_X86_REG_EFLAGS, 0x247);
  update_protected_interrupt_return_flags(uc);
  assert(uc_mem_read(uc, 0x30800, after, 6) == UC_ERR_OK);
  assert(memcmp(after, frame, 4) == 0 && daze_read_u16(after + 4) == 0x247);
  for (int invalid = 0; invalid < 3; ++invalid) {
    if (invalid == 0) set_reg16(uc, UC_X86_REG_SS, 0);
    if (invalid == 1) {
      set_reg16(uc, UC_X86_REG_SS, 0x18);
      set_reg32(uc, UC_X86_REG_ESP, k_memory_size);
    }
    if (invalid == 2) {
      descriptor(uc, 0x18, k_memory_size - 1, 0x92);
      set_reg32(uc, UC_X86_REG_ESP, 0x800);
    }
    update_protected_interrupt_return_flags(uc);
    uint8_t check[6];
    assert(uc_mem_read(uc, 0x30800, check, 6) == UC_ERR_OK && memcmp(check, after, 6) == 0);
  }
  descriptor(uc, 0x18, 0x30000, 0x92);
  set_reg16(uc, UC_X86_REG_SS, 0x18);
  set_reg32(uc, UC_X86_REG_ESP, 0x800);
  assert(daze_restart_address(uc) == 0x100);
  context.engine.last_code_address = 0x100ff;
  assert(daze_next_interrupt_address(uc, &context.engine) == 0x181);
  context.engine.last_code_address = 0;
  assert(daze_next_interrupt_address(uc, &context.engine) == 2);
  context.process.child_process.active = 1;
  context.process.child_process.allocation_segment = 0x3000;
  context.process.dos_process.dos_vector_segment[0x2f] = 0x3000;
  context.process.dos_process.dos_vector_offset[0x2f] = 0x20;
  set_reg16(uc, UC_X86_REG_AX, 0x1111);
  set_reg16(uc, UC_X86_REG_CX, 0x2222);
  set_reg16(uc, UC_X86_REG_DX, 0x3333);
  set_reg16(uc, UC_X86_REG_BX, 0x4444);
  set_reg16(uc, UC_X86_REG_SI, 0x5555);
  set_reg16(uc, UC_X86_REG_DI, 0x6666);
  assert(daze_dispatch_interrupt(uc, DAZE_INT_RAW_SWITCH_GATE, &context.engine, &context.run,
                                 &context.process, NULL));
  assert(!(get_reg32(uc, UC_X86_REG_CR0) & 1));
  assert(get_reg16(uc, UC_X86_REG_DS) == 0x1111 && get_reg16(uc, UC_X86_REG_ES) == 0x2222);
  assert(get_reg16(uc, UC_X86_REG_SS) == 0x3333 && get_reg16(uc, UC_X86_REG_SP) == 0x4444);
  assert(get_reg16(uc, UC_X86_REG_CS) == 0x5555 && get_reg16(uc, UC_X86_REG_IP) == 0x6666);
  assert(context.run.resume_address == 0x5bbb6);
  assert(context.run.raw_vector_snapshot_valid && context.run.raw_vector_snapshot_child_active);
  assert(context.run.raw_vector_snapshot_segment[0x2f] == 0x3000 &&
         context.run.raw_vector_snapshot_offset[0x2f] == 0x20);
  assert(daze_restart_address(uc) == context.run.resume_address);
  update_protected_interrupt_return_flags(uc);
  uint32_t base;
  assert(!guest_segment_base(NULL, 0, &base));
  assert(!guest_segment_base(uc, 0, NULL));
  char text[8];
  assert(!daze_read_guest_asciiz(uc, 0, 0, text, 0));
  assert(!daze_read_guest_asciiz(NULL, 0, 0, text, sizeof(text)) && text[0] == 0);
  uc_close(uc);
}

static void tracing(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  context.engine.metrics.enabled = 1;
  context.engine.full_code_hook = 1;
  assert(daze_unicorn_trace_configure(&context.engine.diagnostic_trace, k_memory_size, "1", "65792",
                                      "65808", "1", "131584", "4") == NULL);
  uint8_t nop[8] = {0x90}, dump[4] = {0xde, 0xad, 0xbe, 0xef};
  assert(uc_mem_write(uc, 0x10100, nop, sizeof(nop)) == UC_ERR_OK);
  assert(uc_mem_write(uc, 0x20200, dump, sizeof(dump)) == UC_ERR_OK);
  for (unsigned i = 0; i < 1024; ++i)
    daze_on_code(uc, 0x10100, 1, &context);
  assert(context.engine.metrics.code_hook_calls == 1024 &&
         context.engine.metrics.guest_instructions == 1024);
  assert(context.engine.recent_code_count ==
         sizeof(context.engine.recent_code) / sizeof(context.engine.recent_code[0]));
  context.engine.diagnostic_trace.records = DAZE_TRACE_MAX_RECORDS;
  daze_on_code(uc, 0x10100, 1, &context);
  assert(context.engine.diagnostic_trace.truncated);
  context.engine.diagnostic_trace.records = 0;
  context.engine.diagnostic_trace.dump_address = k_memory_size;
  daze_on_code(uc, 0x10100, 1, &context);
  uint8_t interrupt[8] = {0xcd, DAZE_INT_RAW_SWITCH_GATE}; /* int 0xfc */
  assert(uc_mem_write(uc, 0x10100, interrupt, 8) == UC_ERR_OK);
  daze_on_code(uc, 0x10100, 2, &context);
  assert(context.run.stopped && context.run.interrupt_number == DAZE_INT_RAW_SWITCH_GATE);
  print_trace_line(uc, k_memory_size);
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char *text = calloc(1, 1024 * 1024);
  assert(text != NULL);
  size_t bytes = fread(text, 1, 1024 * 1024 - 1, capture);
  assert(bytes > 0 && bytes < 1024 * 1024 - 1);
  assert(strstr(text, "trace memory 00020200: de ad be ef") != NULL);
  assert(strstr(text, "trace memory 01000000: unavailable") != NULL);
  assert(strstr(text, "Unicorn trace truncated after 4096") != NULL);
  free(text);
  fclose(capture);
  uc_close(uc);
}

static void continuation_guards(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  DazeUnicornRunState *run = &context.run;
  uc_context *caller;
  assert(uc_context_alloc(uc, &caller) == UC_ERR_OK);
  assert(uc_context_save(uc, caller) == UC_ERR_OK);
  for (int kind = 0; kind < 14; ++kind) {
    run->dos_continuation = (DazeProtectedDosContinuation){.active = 1,
                                                           .caller_context = caller,
                                                           .delivered_cs = 8,
                                                           .frame_ss = 0x18,
                                                           .frame_esp = 0x800};
    if (kind == 0) run->dos_continuation.active = 0;
    if (kind == 1) run->dos_continuation.caller_context = NULL;
    if (kind == 2) run->dos_continuation.delivered_cs = 0;
    if (kind == 3) run->dos_continuation.delivered_cs = 0x20;
    set_reg32(uc, UC_X86_REG_CR0, kind == 4 ? 0 : 1);
    set_reg16(uc, UC_X86_REG_SS, kind == 5 ? 0x10 : 0x18);
    set_reg32(uc, UC_X86_REG_ESP, kind == 6 ? 0x900 : 0x800);
    uint8_t jump[5] = {0xea, 0, 0, 0, 0}; /* jmp far 0000:0000 */
    if (kind >= 8 && kind <= 12) jump[kind - 8] ^= 1;
    assert(uc_mem_write(uc, 0x10100, jump, 5) == UC_ERR_OK);
    assert(protected_dos_continuation_declined(uc, run, 8, kind == 7 ? k_memory_size : 0x10100) ==
           (kind == 13));
  }
  run->dos_continuation.caller_context = NULL;
  uc_context_free(caller);
  for (int absent = 0; absent < 6; ++absent) {
    DazeDosfsFileService files = {0};
    DazeUnicornContinuationContext hook = {
      .run = run, .engine = &context.engine, .process = &context.process, .files = &files};
    if (absent == 1) hook.run = NULL;
    if (absent == 2) hook.engine = NULL;
    if (absent == 3) hook.process = NULL;
    if (absent == 4) hook.files = NULL;
    run->dos_continuation.active = 0;
    daze_on_protected_dos_continuation_code(uc, 0x10100, 5, absent == 0 ? NULL : &hook);
    assert(!run->dos_continuation.active);
  }
  for (int kind = 0; kind < 7; ++kind) {
    run->dos_continuation = (DazeProtectedDosContinuation){.active = kind != 1,
                                                           .return_cs = 8,
                                                           .return_eip = 0x100,
                                                           .frame_ss = 0x18,
                                                           .frame_esp = 0x7fa,
                                                           .frame_size = 6};
    set_reg32(uc, UC_X86_REG_CR0, kind == 2 ? 0 : 1);
    set_reg16(uc, UC_X86_REG_CS, 8);
    set_reg16(uc, UC_X86_REG_IP, kind == 4 ? 0x101 : 0x100);
    set_reg16(uc, UC_X86_REG_SS, kind == 5 ? 0x10 : 0x18);
    set_reg32(uc, UC_X86_REG_ESP, kind == 6 ? 0x802 : 0x800);
    if (kind == 3) run->dos_continuation.return_cs = 0x20;
    daze_on_protected_dos_return_code(uc, 0x10100, 1, kind == 0 ? NULL : run);
    assert(run->dos_continuation.active == (kind != 1));
  }
  daze_protected_dos_continuation_clear(run);
  daze_protected_dos_continuation_clear(NULL);
  uc_close(uc);
}

static void projection_guards(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  uint8_t descriptor_bytes[8], after[8];
  DazeDosAllocation *allocation = &context.process.dos_memory.allocations[0];
  *allocation = (DazeDosAllocation){.in_use = 1, .segment = 0x3000, .paragraphs = 8};
  for (int kind = 0; kind < 4; ++kind) {
    DazeRawVectorProjection *p = &context.run.raw_vector_projections[0];
    *p = (DazeRawVectorProjection){.in_use = 1,
                                   .selector = 0x3004,
                                   .allocation_segment = 0x3000,
                                   .allocation_paragraphs = kind == 1 ? 7 : 8};
    context.process.dos_process.dos_vector_segment[0x2f] = kind == 2 ? 0 : 0x3004;
    allocation->in_use = kind != 0;
    memset(descriptor_bytes, 0x5a, 8);
    uint32_t address = k_dpmi_ldt_address + 0x3000;
    assert(uc_mem_write(uc, address, descriptor_bytes, 8) == UC_ERR_OK);
    assert(daze_materialize_raw_vector_descriptors(uc, &context.run, &context.process,
                                                   &context.engine.metrics));
    assert(uc_mem_read(uc, address, after, 8) == UC_ERR_OK);
    assert(memcmp(after, kind == 3 ? descriptor_bytes : (uint8_t[8]){0}, 8) == 0);
    assert(p->in_use == (kind == 3));
  }
  assert(daze_raw_vector_allocation(&context.process.dos_memory, 0x4000) == NULL);
  context.run.raw_vector_projections[0].allocation_segment = 0x4000;
  assert(daze_withdraw_raw_vector_projections(uc, &context.run, &context.engine.metrics, 0x3000));
  assert(context.run.raw_vector_projections[0].in_use);
  assert(uc_mem_unmap(uc, k_dpmi_ldt_address + 0x3000, 0x1000) == UC_ERR_OK);
  assert(!daze_raw_vector_descriptor_is_empty(uc, 0x3004));
  DazeRawVectorProjection before = context.run.raw_vector_projections[0];
  assert(!daze_withdraw_raw_vector_projections(uc, &context.run, &context.engine.metrics, 0x4000));
  assert(memcmp(&before, &context.run.raw_vector_projections[0], sizeof(before)) == 0);
  assert(!daze_materialize_raw_vector_descriptors(uc, &context.run, &context.process,
                                                  &context.engine.metrics));
  uc_close(uc);
}

static void selector_guards(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  DazeDpmiExceptionFault fault = {0};
  assert(!daze_dpmi_exception_classify(NULL, &context.process.dpmi, &fault));
  assert(!daze_dpmi_exception_classify(uc, NULL, &fault));
  assert(!daze_dpmi_exception_classify(uc, &context.process.dpmi, NULL));
  context.process.dpmi.exception_vector_segment[0xb] = 8;
  const uint8_t malformed[][5] = {
    {0xff, 0x1f},       /* unsupported indirect far-call addressing */
    {0x26, 0xc5, 0x3f}, /* unsupported ES-prefixed LDS */
    {0x26, 0xc4, 0x3e}, /* unsupported LES addressing */
    {0xcb},             /* retf to a non-code descriptor */
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
    assert(uc_mem_write(uc, 0x10100, malformed[i], 5) == UC_ERR_OK);
    uint16_t frame[2] = {0x1234, 0x10};
    assert(uc_mem_write(uc, 0x30800, frame, sizeof(frame)) == UC_ERR_OK);
    DazeDpmiExceptionFault before = fault;
    assert(!daze_dpmi_exception_classify(uc, &context.process.dpmi, &fault));
    assert(memcmp(&fault, &before, sizeof(fault)) == 0);
  }
  set_reg32(uc, UC_X86_REG_CR0, 0);
  assert(!daze_dpmi_exception_classify(uc, &context.process.dpmi, &fault));
  set_reg32(uc, UC_X86_REG_CR0, 1);
  uint8_t bytes[8];
  daze_dpmi_descriptor_encode(bytes, 0x10000, 0xffff, 0x9a, 4);
  assert(uc_mem_write(uc, k_dpmi_gdt_address + 8, bytes, 8) == UC_ERR_OK);
  assert(!daze_dpmi_exception_classify(uc, &context.process.dpmi, &fault));
  descriptor(uc, 8, 0x10000, 0x9a);
  uint8_t instruction[5] = {0x9a, 0, 0, 0x20, 0}; /* call far 0020:0000 */
  assert(uc_mem_write(uc, 0x10100, instruction, 5) == UC_ERR_OK);
  context.process.dpmi.exception_vector_segment[0xb] = 0x10;
  assert(!daze_dpmi_exception_classify(uc, &context.process.dpmi, &fault));
  context.process.dpmi.exception_vector_segment[0xb] = 8;
  assert(uc_mem_unmap(uc, 0x10000, 0x1000) == UC_ERR_OK);
  assert(!daze_dpmi_exception_classify(uc, &context.process.dpmi, &fault));
  context.process.dpmi.exception_vector_segment[0xb] = 0;
  for (int absent = 0; absent < 5; ++absent)
    assert(!daze_dpmi_exception_transfer(
      absent == 0 ? NULL : uc, absent == 1 ? NULL : &context.engine,
      absent == 2 ? NULL : &context.run, absent == 3 ? NULL : &context.process.dpmi,
      absent == 4 ? NULL : &fault));
  context.run.exception_delivery_stack.depth = k_dpmi_exception_max_depth;
  assert(!daze_dpmi_exception_transfer(uc, &context.engine, &context.run, &context.process.dpmi,
                                       &fault));
  context.run.exception_delivery_stack.depth = 0;
  assert(!daze_dpmi_exception_transfer(uc, &context.engine, &context.run, &context.process.dpmi,
                                       &fault));
  assert(!daze_dpmi_selector_nonpresent(uc, 0));
  assert(!daze_dpmi_selector_nonpresent_code16(uc, 0));
  assert(daze_dpmi_selector_nonpresent(uc, 0xfffc));
  assert(!daze_dpmi_selector_nonpresent_code16(uc, 0xfffc));
  for (int kind = 0; kind < 4; ++kind) {
    uint8_t bytes[8];
    daze_dpmi_descriptor_encode(bytes, 0x40000, 0xffff,
                                kind == 0 || kind == 3 ? 0x1a
                                : kind == 1            ? 0x9a
                                                       : 0x12,
                                kind == 3 ? 4 : 0);
    assert(uc_mem_write(uc, k_dpmi_ldt_address + 0x100, bytes, 8) == UC_ERR_OK);
    assert(daze_dpmi_selector_nonpresent_code16(uc, 0x104) == (kind == 0));
    assert(daze_dpmi_selector_nonpresent(uc, 0x104) == (kind != 1));
  }
  assert(uc_mem_unmap(uc, k_dpmi_ldt_address, 0x10000) == UC_ERR_OK);
  assert(!daze_dpmi_selector_nonpresent(uc, 0x104));
  assert(!daze_dpmi_selector_nonpresent_code16(uc, 0x104));
  uc_close(uc);
}

static void exception_hook_guards(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  DazeUnicornRunState *run = &context.run;
  for (int absent = 0; absent < 5; ++absent) {
    DazeUnicornExceptionHookContext hook = {
      .run = run, .engine = &context.engine, .dpmi = &context.process.dpmi};
    if (absent == 1) hook.run = NULL;
    if (absent == 2) hook.engine = NULL;
    if (absent == 3) hook.dpmi = NULL;
    daze_on_exception_entry(uc, 0x10100, 1, absent == 0 ? NULL : &hook);
    daze_on_exception_return(uc, 0x10100, 1, absent == 0 ? NULL : &hook);
    daze_on_exception_return_successor(uc, 0x10100, 1, absent == 0 ? NULL : &hook);
    assert(run->exception_delivery_stack.depth == 0);
  }
  assert(daze_dpmi_exception_record(NULL, 0) == NULL);
  assert(daze_dpmi_exception_record(run, 0) == NULL);
  assert(daze_dpmi_exception_active(NULL) == NULL);
  assert(!daze_dpmi_exception_transfer_dispose_active(NULL, run));
  assert(!daze_dpmi_exception_transfer_dispose_active(uc, NULL));
  daze_dpmi_exception_transfer_disarm(NULL, run);
  daze_dpmi_exception_transfer_disarm(uc, NULL);
  run->exception_delivery_stack.depth = 1;
  DazeDpmiExceptionTransfer *transfer = daze_dpmi_exception_active(run);
  DazeUnicornExceptionHookContext hook = {
    .run = run, .engine = &context.engine, .dpmi = &context.process.dpmi};
  for (int kind = 0; kind < 4; ++kind) {
    *transfer = (DazeDpmiExceptionTransfer){.armed = kind != 0,
                                            .entry_linear = 0x10200,
                                            .return_armed = kind != 0,
                                            .return_linear = kind == 1 ? 0x10200 : 0x10100};
    daze_write_u16(transfer->frame, kind == 3 ? 0x101 : 0x100);
    daze_write_u16(transfer->frame + 2, kind == 2 ? 0x10 : 8);
    DazeDpmiExceptionTransfer before = *transfer;
    daze_on_exception_entry(uc, 0x10100, 1, &hook);
    daze_on_exception_return(uc, 0x10100, 1, &hook);
    daze_on_exception_return_successor(uc, 0x10100, 1, &hook);
    assert(memcmp(&before, transfer, sizeof(before)) == 0);
  }
  transfer->successor_armed = 1;
  daze_on_exception_return_successor(uc, 0x10100, 1, &hook);
  assert(transfer->successor_armed && run->exception_delivery_stack.depth == 1);
  transfer->armed = transfer->return_armed = transfer->successor_armed = 0;
  assert(daze_dpmi_exception_transfer_dispose_active(uc, run));
  assert(!run->exception_delivery_stack.depth);
  uc_close(uc);
}

static void widening_guards(void) {
  for (int kind = 0; kind < 10; ++kind) {
    uc_engine *uc = fixture();
    DazeUnicornContext context = {0};
    uint8_t instruction[2] = {0x66, 0xcb}; /* retf with 32-bit operands */
    uint16_t words[3] = {0x1234, 8, 0};
    if (kind == 0) set_reg16(uc, UC_X86_REG_CS, 0);
    if (kind == 1) instruction[0] = 0x90;
    if (kind == 2) instruction[1] = 0x90;
    assert(uc_mem_write(uc, 0x10102, instruction, 2) == UC_ERR_OK);
    if (kind == 3) set_reg32(uc, UC_X86_REG_ESP, 3);
    if (kind == 4) set_reg16(uc, UC_X86_REG_SS, 0);
    if (kind == 5) descriptor(uc, 0x18, k_memory_size - 1, 0x92);
    if (kind == 6) set_reg32(uc, UC_X86_REG_ESP, k_memory_size);
    if (kind == 7) words[1] = 0;
    assert(uc_mem_write(uc, 0x30800, words, sizeof(words)) == UC_ERR_OK);
    if (kind == 8) assert(uc_mem_unmap(uc, 0x30000, 0x1000) == UC_ERR_OK);
    if (kind == 9) assert(uc_mem_unmap(uc, 0x10000, 0x1000) == UC_ERR_OK);
    uint32_t sp = get_reg32(uc, UC_X86_REG_ESP);
    assert(!state_procedure_widen_caller_frame(uc, &context.engine, &context.run));
    assert(get_reg32(uc, UC_X86_REG_ESP) == sp);
    uc_close(uc);
  }
}

static void interrupt_diagnostics(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  DazeUnicornInterruptContext hook = {.context = &context};
  daze_on_interrupt(uc, 0, NULL);
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  for (int kind = 0; kind < 3; ++kind) {
    context.engine.full_code_hook = kind != 0;
    context.engine.have_code = kind != 1;
    context.engine.last_code_address = 0x10100;
    set_reg32(uc, UC_X86_REG_CR0, kind == 0 ? 1 : 0);
    set_reg16(uc, UC_X86_REG_CS, 8);
    set_reg16(uc, UC_X86_REG_IP, 0x100);
    daze_on_interrupt(uc, DAZE_INT_GP_FAULT, &hook);
    assert(context.run.stopped && context.run.interrupt_number == DAZE_INT_GP_FAULT);
  }
  set_reg32(uc, UC_X86_REG_CR0, 1);
  set_reg16(uc, UC_X86_REG_CS, 8);
  set_reg16(uc, UC_X86_REG_SS, 0x18);
  set_reg32(uc, UC_X86_REG_ESP, 0x800);
  set_reg16(uc, UC_X86_REG_AX, 0x3000);
  context.run.host_dos_gate = 0;
  assert(daze_dispatch_interrupt(uc, DAZE_INT_DOS_PROXY, &context.engine, &context.run,
                                 &context.process, NULL));
  assert(!context.run.host_dos_gate && get_reg16(uc, UC_X86_REG_AX) == 5);
  uint16_t flags;
  assert(daze_read_guest_bytes(uc, 0x18, 0x804, &flags, 2));
  assert(flags == (uint16_t)get_reg32(uc, UC_X86_REG_EFLAGS));
  context.process.dpmi.exception_vector_segment[0xb] = 8;
  context.run.terminated = 1;
  daze_on_interrupt(uc, DAZE_INT_SEGMENT_NOT_PRESENT, &hook);
  assert(context.run.terminated);
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[8192] = {0};
  assert(fread(text, 1, sizeof(text) - 1, capture) > 0);
  assert(strstr(text, "fault-site bytes") != NULL);
  uc_close(uc);
  fclose(capture);
}

static void hook_boundaries(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  context.engine.metrics.enabled = 1;
  context.engine.full_code_hook = 0;
  assert(daze_unicorn_trace_configure(&context.engine.diagnostic_trace, k_memory_size, NULL, NULL,
                                      NULL, "1", NULL, NULL) == NULL);
  assert(uc_mem_unmap(uc, 0x10000, 0x1000) == UC_ERR_OK);
  daze_on_code(uc, 0x10100, 1, &context);
  assert(context.engine.have_code && context.engine.metrics.guest_instructions == 0);
  assert(context.engine.recent_code_count == 0);
  assert(uc_mem_map(uc, 0x10000, 0x1000, UC_PROT_ALL) == UC_ERR_OK);
  set_reg16(uc, UC_X86_REG_IP, 0xffa);
  assert(uc_mem_unmap(uc, 0x11000, 0x1000) == UC_ERR_OK);
  daze_on_code(uc, 0x10ffa, 1, &context);
  assert(context.engine.recent_code_count == 0);
  uint8_t direct[2] = {0xcd, 0x21}; /* int 0x21 */
  assert(uc_mem_write(uc, 0x10100, direct, 2) == UC_ERR_OK);
  set_reg16(uc, UC_X86_REG_IP, 0x100);
  daze_on_code(uc, 0x10100, 2, &context);
  assert(!context.run.stopped);
  for (int vector = DAZE_INT_STATE_SAVE_GATE; vector <= DAZE_INT_DPMI_ENTRY; ++vector)
    if (vector == DAZE_INT_STATE_SAVE_GATE || vector == DAZE_INT_RAW_SWITCH_GATE ||
        vector == DAZE_INT_DOS_PROXY || vector == DAZE_INT_DPMI_ENTRY)
      assert(!direct_interrupt_in_place((uint8_t)vector));
  context.run.rm_procedure_active = 1;
  daze_on_code(uc, 0x10100, 1, &context);
  assert(!context.run.stopped);
  set_reg32(uc, UC_X86_REG_CR0, 0);
  set_reg16(uc, UC_X86_REG_CS, 0);
  set_reg16(uc, UC_X86_REG_IP, 0x100);
  daze_on_code(uc, 0x100, 1, &context);
  assert(!context.run.stopped);
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  set_reg16(uc, UC_X86_REG_IP, k_dpmi_rm_gate_linear);
  context.run.rm_procedure_frame_address = k_memory_size;
  daze_on_code(uc, k_dpmi_rm_gate_linear, 1, &context);
  assert(context.run.stopped);
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[512] = {0};
  assert(fread(text, 1, sizeof(text) - 1, capture) > 0);
  assert(strstr(text, "cannot return to protected mode") != NULL);
  fclose(capture);
  uc_close(uc);
}

int main(void) {
  exception_operands();
  flags_and_switch();
  tracing();
  continuation_guards();
  projection_guards();
  selector_guards();
  exception_hook_guards();
  widening_guards();
  interrupt_diagnostics();
  hook_boundaries();
  return 0;
}
