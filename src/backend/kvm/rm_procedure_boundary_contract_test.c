/* Exercise the real-mode reply codec without publishing private transport APIs. */
#include "rm_procedure.c"

#include "descriptor.h"
#include <assert.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static void return_bridge_contract(void) {
  uint8_t guest[0x4000] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  ParkedState parked = {.regs = {.rax = 0x12345678, .rip = 0x1504, .rsp = 0x100, .rflags = 0x87},
                        .sregs = {.cr0 = 0x11,
                                  .gdt = {.base = 0x1000, .limit = 0x5f},
                                  .ldt = {.base = 0x1800, .limit = 0xff, .present = 1},
                                  .idt = {.base = 0x1900, .limit = 0x7ff}}};
  parked.sregs.cs = protected_code_segment(DAZE_SEL_GATE_CODE, 0x2000);
  parked.sregs.ss = (struct kvm_segment){
    .selector = 0x10, .base = 0x3100, .limit = 0xffff, .type = 3, .present = 1, .s = 1};
  parked.sregs.ds = parked.sregs.es = parked.sregs.ss;
  parked.sregs.fs = parked.sregs.ss;
  parked.sregs.fs.selector = 0x84;
  parked.sregs.gs.unusable = 1;
  daze_dpmi_descriptor_encode(guest + 0x1010, 0x3100, 0xffff, 0x92, 0);
  daze_dpmi_descriptor_encode(guest + 0x1880, 0x3100, 0xffff, 0x93, 0);
  daze_dpmi_descriptor_encode(guest + 0x1028, 0x2000, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(guest + 0x1050, 0x2000, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(guest + 0x1058, 0, 0xfffff, 0x92, 12);
  assert(return_bridge_eligible(&machine, &parked, 0x3400));
  for (unsigned kind = 0; kind < 36; ++kind) {
    ParkedState bad = parked;
    uint32_t address = 0x3400;
    switch (kind) {
    case 0:
      bad.sregs.cs.selector = 8;
      break;
    case 1:
      bad.sregs.cs.type = 3;
      break;
    case 2:
      bad.sregs.cr0 |= 0x80000000u;
      break;
    case 3:
      bad.sregs.cr0 &= ~UINT64_C(1);
      break;
    case 4:
      bad.regs.rflags |= 1u << 8;
      break;
    case 5:
      bad.regs.rflags |= 1u << 16;
      break;
    case 6:
      bad.regs.rflags |= 1u << 17;
      break;
    case 7:
      bad.regs.rsp = 3;
      break;
    case 8:
      bad.sregs.ss.limit = 0xff;
      break;
    case 9:
      bad.sregs.ss.limit = UINT32_MAX;
      bad.regs.rsp = 0x10000;
      break;
    case 10:
      bad.sregs.ss.type = 7;
      break;
    case 11:
      bad.sregs.ss.base = UINT32_MAX;
      break;
    case 12:
      bad.sregs.idt.base = UINT64_C(1) << 32;
      break;
    case 13:
      bad.regs.rip = 0x10000;
      break;
    case 14:
      address = 0x2400;
      break;
    case 15:
      address = 0x31fc;
      break;
    case 16:
      bad.regs.rax = UINT64_C(1) << 32;
      break;
    case 17:
      bad.sregs.ss.base++;
      break;
    case 18:
      bad.sregs.gdt.limit = 0x57;
      break;
    case 19:
      bad.sregs.ldt.unusable = 1;
      break;
    case 20:
      bad.sregs.ds.present = 0;
      break;
    case 21:
      bad.sregs.ds.dpl = 3;
      break;
    case 22:
      bad.sregs.ds.l = 1;
      break;
    case 23:
      bad.sregs.ds.selector |= 1;
      break;
    case 24:
      bad.sregs.ldt.limit = 0x86;
      break;
    case 25:
      bad.sregs.gdt.base = UINT64_C(1) << 32;
      break;
    case 26:
      bad.sregs.gdt.base = UINT32_MAX - 7;
      break;
    case 27:
      bad.sregs.ds.db = 1;
      break;
    case 28:
      bad.sregs.ds.limit--;
      break;
    case 29:
      bad.sregs.gs.unusable = 0;
      break;
    case 30:
      bad.sregs.ds.s = 0;
      break;
    case 31:
      bad.sregs.ds.unusable = 1;
      break;
    case 32:
      bad.sregs.ldt.present = 0;
      break;
    case 33:
      address = sizeof(guest) - 1;
      break;
    case 34:
      bad.regs.r8 = 1;
      break;
    case 35:
      bad.sregs.ds.type = 9;
      break;
    }
    assert(install_return_bridge(&machine, &bad, address) == 0);
    assert(guest[0x2300] == 0);
  }
  assert(install_return_bridge(&machine, &parked, 0x3400) == 1);
  assert(sizeof(rm_return_code) == 0x157 && guest[0x2300] == 0xea &&
         daze_read_u32(guest + 0x2a00) == 0x12345678 && daze_read_u32(guest + 0x2a28) == 0x3400 &&
         daze_read_u32(guest + 0x2a3c) == 0x1504 && daze_read_u16(guest + 0x2a42) == 0);
  parked.sregs.ss.base = 0x2000;
  parked.sregs.ds.base = parked.sregs.es.base = parked.sregs.fs.base = 0x2000;
  daze_dpmi_descriptor_encode(guest + 0x1010, 0x2000, 0xffff, 0x92, 0);
  daze_dpmi_descriptor_encode(guest + 0x1880, 0x2000, 0xffff, 0x93, 0);
  machine.guest_size = 0x2eff;
  assert(install_return_bridge(&machine, &parked, 0x2200) == -1);
}

static void protected_return_contract(void) {
  uint8_t guest[0x2400] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  const ParkedState parked = {.regs = {.rax = 0x12345678, .rip = 0x87654321, .rflags = 2},
                              .sregs = {.cr0 = 0x11, .cs = {.selector = DAZE_SEL_GATE_CODE}}};
  const struct kvm_sregs returned = {.cr0 = 0x10};
  for (unsigned kind = 0; kind < 8; ++kind) {
    ParkedState state = parked;
    struct kvm_sregs current = returned;
    if (kind == 0) state.sregs.cs.selector = 8;
    if (kind == 1) state.sregs.cr0 |= 0x80000000u;
    if (kind == 2) state.sregs.cr0 &= ~UINT64_C(1);
    if (kind == 3) current.cr0 ^= 0x10;
    if (kind == 4) state.regs.rax = UINT64_C(1) << 32;
    if (kind == 5) state.regs.rip = UINT64_C(1) << 32;
    if (kind == 6) state.regs.rflags |= 1u << 8;
    if (kind == 7) state.regs.rflags |= 1u << 17;
    const ParkedState before = state;
    assert(prepare_protected_return(&machine, &state, &current) == 0);
    assert(memcmp(&before, &state, sizeof(state)) == 0);
  }
  ParkedState state = parked;
  machine.guest_size = k_pm_reentry_wrapper;
  assert(prepare_protected_return(&machine, &state, &returned) == -1);
  machine.guest_size = k_pm_reentry_state;
  assert(prepare_protected_return(&machine, &state, &returned) == -1);
  machine.guest_size = sizeof(guest);
  assert(prepare_protected_return(&machine, &state, &returned) == 1);
  assert(state.sregs.cr0 == returned.cr0 && state.sregs.cs.selector == DAZE_SEL_GATE &&
         state.sregs.cs.base == 0x2000 && state.regs.rip == 0x180 &&
         state.regs.rax == parked.regs.rax && state.regs.rflags == parked.regs.rflags);
  assert(daze_read_u32(guest + k_pm_reentry_wrapper + 2) == parked.sregs.cr0 &&
         daze_read_u32(guest + k_pm_reentry_wrapper + 16) == parked.regs.rip &&
         daze_read_u16(guest + k_pm_reentry_wrapper + 20) == DAZE_SEL_GATE_CODE &&
         daze_read_u32(guest + k_pm_reentry_state) == parked.regs.rax);
}

static void descriptor_reply_contract(void) {
  uint8_t guest[0x1000] = {0};
  uint8_t used[32] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .vcpu = -1};
  DazeDpmiLinearMemory linear;
  daze_dpmi_linear_memory_init(&linear, 0x800, 0x1000);
  DazeKvmDpmiMediator mediator = {.guest = guest,
                                  .guest_size = sizeof(guest),
                                  .gdt_address = 0x100,
                                  .gdt_size = 0x100,
                                  .ldt_address = 0x200,
                                  .ldt_size = 0x100,
                                  .ldt_used = used,
                                  .ldt_used_count = sizeof(used),
                                  .ldt_first_index = 16,
                                  .linear_memory = &linear};
  uint8_t record[24] = {0}, reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE];
  const uint16_t functions[] = {DAZE_DPMI_SET_LIMIT, DAZE_DPMI_SET_LIMIT_2, DAZE_DPMI_SET_ACCESS};
  for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); ++i) {
    daze_dpmi_descriptor_encode(guest + 0x280, 0x12345678, 0xffff, 0x92, 0);
    daze_write_u16(record, functions[i]);
    daze_write_u16(record + 2, 0x84);
    daze_write_u16(record + 4, i == 0 ? 0x12ab : i == 1 ? 1 : 0x4092);
    daze_write_u16(record + 6, i == 0 ? 0x3456 : 0x2345);
    assert(serve_real_mode_dpmi(&machine, record, reply, &mediator));
    assert(daze_read_u16(reply + 14) == 2);
    if (i == 0)
      assert(guest[0x282] == 0x56 && guest[0x283] == 0x34 && guest[0x284] == 0xab &&
             guest[0x287] == 0x12);
    else if (i == 1)
      assert(guest[0x280] == 0x45 && guest[0x281] == 0x23 && (guest[0x286] & 0xf) == 1);
    else
      assert(guest[0x285] == 0x92 && (guest[0x286] & 0xf0) == 0x40);
    uint8_t before[8];
    memcpy(before, guest + 0x280, 8);
    daze_write_u16(record + 2, 8);
    assert(serve_real_mode_dpmi(&machine, record, reply, &mediator));
    assert(daze_read_u16(reply + 14) == 3 &&
           daze_read_u16(reply) ==
             (i == 1 ? DAZE_DPMI_ERR_INVALID_SEGMENT : DAZE_DPMI_ERR_INVALID_SELECTOR));
    assert(memcmp(before, guest + 0x280, 8) == 0);
  }
  for (int kind = 0; kind < 2; ++kind) {
    uint8_t before[8];
    memcpy(before, guest + 0x280, 8);
    daze_write_u16(record, kind == 0 ? DAZE_DPMI_SET_LIMIT_2 : DAZE_DPMI_SET_ACCESS);
    daze_write_u16(record + 2, 0x84);
    daze_write_u16(record + 4, kind == 0 ? 0x1234 : 0);
    daze_write_u16(record + 6, 0x5678);
    assert(serve_real_mode_dpmi(&machine, record, reply, &mediator));
    assert(daze_read_u16(reply) == DAZE_DPMI_ERR_INVALID_SEGMENT && daze_read_u16(reply + 14) == 3);
    assert(memcmp(before, guest + 0x280, 8) == 0);
  }
  daze_write_u16(record, DAZE_DPMI_ALLOC_LDT_MULTI);
  daze_write_u16(record + 2, 8);
  daze_dpmi_descriptor_encode(guest + 0x108, 0x12345678, 0xabcde, 0x9a, 4);
  assert(serve_real_mode_dpmi(&machine, record, reply, &mediator));
  assert(daze_read_u16(reply) == 0x84 && daze_read_u16(reply + 14) == 2 && used[16] == 1);
  uint8_t expected[8];
  memcpy(expected, guest + 0x108, 8);
  expected[5] = 0x92;
  assert(memcmp(expected, guest + 0x280, 8) == 0);
  for (int kind = 0; kind < 3; ++kind) {
    DazeKvmDpmiMediator bad = mediator;
    uint8_t before[sizeof(guest)];
    memcpy(before, guest, sizeof(guest));
    if (kind == 0) daze_write_u16(record + 2, 4);
    if (kind == 1) {
      daze_write_u16(record + 2, 8);
      guest[0x10d] = 0x92;
    }
    if (kind == 2) {
      guest[0x10d] = 0x9a;
      memset(used, 1, sizeof(used));
    }
    memcpy(before, guest, sizeof(guest));
    assert(serve_real_mode_dpmi(&machine, record, reply, &bad));
    assert(daze_read_u16(reply) == DAZE_DPMI_ERR_INVALID_SELECTOR &&
           daze_read_u16(reply + 14) == 3);
    assert(memcmp(before, guest, sizeof(guest)) == 0);
  }
  for (int function = 0; function < 2; ++function) {
    daze_write_u16(record, function == 0 ? DAZE_DPMI_ALLOC_LDT : DAZE_DPMI_ALLOC_LDT_MULTI);
    daze_write_u16(record + 2, 8);
    daze_write_u16(record + 4, 2);
    for (int kind = 0; kind < 2; ++kind) {
      DazeKvmDpmiMediator bad = mediator;
      if (kind == 0)
        bad.ldt_used = NULL;
      else
        bad.ldt_used_count = 1;
      assert(!serve_real_mode_dpmi(&machine, record, reply, &bad));
    }
  }
  daze_write_u16(record, DAZE_DPMI_ALLOC_LDT);
  assert(serve_real_mode_dpmi(&machine, record, reply, &mediator));
  assert(daze_read_u16(reply) == DAZE_DPMI_ERR_LDT_FULL && daze_read_u16(reply + 14) == 3);
  memset(used, 0, sizeof(used));
  assert(serve_real_mode_dpmi(&machine, record, reply, &mediator));
  assert(used[16] && used[17] && daze_read_u16(reply) == 0x84);
  const uint8_t inert[8] = {0, 0, 0, 0, 0, 0x92, 0, 0};
  assert(memcmp(guest + 0x280, inert, 8) == 0 && memcmp(guest + 0x288, inert, 8) == 0);
}

static void input_and_metrics_contract(void) {
  const struct kvm_regs returned = {.rip = DAZE_DPMI_RM_RETURN_IP + 1};
  const struct kvm_sregs returned_segments = {
    .cs = {.selector = DAZE_DPMI_RM_RETURN_CS, .base = DAZE_DPMI_RM_GATE_LINEAR}};
  assert(returned_to_gate(&returned, &returned_segments));
  for (int kind = 0; kind < 5; ++kind) {
    struct kvm_regs regs = returned;
    struct kvm_sregs sregs = returned_segments;
    if (kind == 0) sregs.cr0 = 1;
    if (kind == 1) sregs.cs.selector++;
    if (kind == 2) sregs.cs.base++;
    if (kind == 3) regs.rip--;
    if (kind == 4) regs.rip++;
    assert(!returned_to_gate(&regs, &sregs));
  }
  uint8_t guest[0x4000] = {0};
  struct kvm_run run = {0};
  DazeKvmMachine machine = {.guest = guest,
                            .guest_size = sizeof(guest),
                            .vcpu = INT32_MAX,
                            .run = &run,
                            .run_size = sizeof(run)};
  DazeKvmDpmiMediator mediator = {.guest = guest,
                                  .guest_size = sizeof(guest),
                                  .rm_procedure_present = 1,
                                  .rm_procedure = {.frame_address = 0x100, .stack_address = 0x200}};
  DazeDosfsFileService files = {0};
  DazeKvmRmProcedureInput input = {.machine = &machine, .mediator = &mediator, .files = &files};
  DazeKvmDpmiEntryResult successor;
  assert(!daze_kvm_rm_procedure_reflect(NULL, &successor));
  assert(!daze_kvm_rm_procedure_reflect(&input, NULL));
  for (int kind = 0; kind < 10; ++kind) {
    DazeKvmRmProcedureInput bad = input;
    DazeKvmDpmiMediator bad_mediator = mediator;
    DazeKvmMachine bad_machine = machine;
    bad.machine = &bad_machine;
    bad.mediator = &bad_mediator;
    switch (kind) {
    case 0:
      bad.machine = NULL;
      break;
    case 1:
      bad.mediator = NULL;
      break;
    case 2:
      bad.files = NULL;
      break;
    case 3:
      bad_mediator.guest = guest + 1;
      break;
    case 4:
      bad_mediator.guest_size--;
      break;
    case 5:
      bad_mediator.rm_procedure_present = 0;
      break;
    case 6:
      bad_machine.vcpu = -1;
      break;
    case 7:
      bad_machine.run = NULL;
      break;
    case 8:
      bad_mediator.rm_procedure.frame_address = sizeof(guest);
      break;
    case 9:
      bad_mediator.rm_procedure.stack_address = sizeof(guest);
      break;
    }
    memset(&successor, 0xa5, sizeof(successor));
    assert(!daze_kvm_rm_procedure_reflect(&bad, &successor));
    const DazeKvmDpmiEntryResult empty = {0};
    assert(memcmp(&successor, &empty, sizeof(empty)) == 0);
  }
  assert(!daze_kvm_rm_procedure_reflect(&input, &successor));
  assert(!serve_runner(&machine, &files, NULL, &mediator, 0x200, 0x21));
  struct kvm_sregs returned_sregs;
  assert(!write_back_frame(&machine, 0x100, &returned_sregs));
  assert(reflect_run(&machine, &files, NULL, &mediator, 0x200, 0, &successor, 0) == RMRUN_STOP);
  dump_rejected_far_load(&machine, &(struct kvm_regs){.rip = 0x1234});
  DazeRunMetrics metrics = {0};
  record_reflect_runner(NULL, 0x21, 10);
  record_reflect_runner(&metrics, 0x21, 10);
  assert(metrics.kvm_rm_procedure_reflect_runner_calls == 0);
  metrics.enabled = 1;
  record_reflect_runner(&metrics, 0x21, 10);
  record_reflect_runner(&metrics, 0x31, 20);
  record_reflect_runner(&metrics, 0x21, 30);
  for (size_t i = 2; i < DAZE_RUN_METRICS_RM_REFLECT_VECTOR_CAPACITY; ++i)
    record_reflect_runner(&metrics, (uint8_t)i, 1);
  record_reflect_runner(&metrics, 0xff, 40);
  assert(metrics.kvm_rm_procedure_reflect_vector_count ==
           DAZE_RUN_METRICS_RM_REFLECT_VECTOR_CAPACITY &&
         metrics.kvm_rm_procedure_reflect_vectors[0].calls == 2 &&
         metrics.kvm_rm_procedure_reflect_vectors[0].nanoseconds == 40 &&
         metrics.kvm_rm_procedure_reflect_vector_overflow_calls == 1);
  assert(elapsed_nanoseconds(20, 10) == 0 && elapsed_nanoseconds(10, 20) == 10);
  const DazeRunMetricsRmProcedureCost cost = {.total_nanoseconds = 100,
                                              .setup_nanoseconds = 10,
                                              .reflect_nanoseconds = 60,
                                              .cleanup_nanoseconds = 5,
                                              .resume_nanoseconds = 25,
                                              .reflect_run_nanoseconds = 40,
                                              .resume_run_nanoseconds = 20,
                                              .service_nanoseconds = 3};
  record_procedure_cost(&metrics, 1, 1, 0, &cost);
  record_procedure_cost(&metrics, 1, 1, 0, &cost);
  record_procedure_cost(&metrics, 1, 0, 1, &cost);
  record_procedure_cost(&metrics, 2, 1, 1, &cost);
  record_procedure_cost(&metrics, 0, 0, 0, &cost);
  record_procedure_cost(&metrics, 1, 0, 0, &cost);
  const DazeRunMetricsRmProcedureCost *date =
    &metrics.kvm_rm_procedure_costs[DAZE_RUN_METRICS_RM_DATE];
  assert(date->calls == 2 && date->total_nanoseconds == 200 && date->setup_nanoseconds == 20 &&
         date->reflect_nanoseconds == 120 && date->cleanup_nanoseconds == 10 &&
         date->resume_nanoseconds == 50 && date->reflect_run_nanoseconds == 80 &&
         date->resume_run_nanoseconds == 40 && date->service_nanoseconds == 6);
  assert(metrics.kvm_rm_procedure_costs[DAZE_RUN_METRICS_RM_TIME].calls == 1 &&
         metrics.kvm_rm_procedure_costs[DAZE_RUN_METRICS_RM_OTHER].calls == 3);
}

static void native_binding_contract(void) {
  uint8_t *guest = calloc(1, k_memory_size);
  assert(guest);
  struct {
    struct kvm_run run;
    uint8_t port_data[16];
  } state = {0};
  DazeKvmMachine machine = {.guest = guest,
                            .guest_size = k_memory_size,
                            .vcpu = INT32_MAX,
                            .run = &state.run,
                            .run_size = sizeof(state),
                            .sync_regs_mask = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS};
  ParkedState parked = {
    .regs = {.rax = 0x12345678, .rip = 0xfde87e, .rsp = 0x100, .rflags = 2},
    .sregs = {.cr0 = 0x11,
              .gdt = {.base = k_dpmi_gdt_address, .limit = 0xffff},
              .ldt = {.base = k_dpmi_ldt_address, .limit = 0xffff, .selector = 0x18, .present = 1},
              .idt = {.base = 0xfdf800, .limit = 0x7ff}}};
  parked.sregs.cs = (struct kvm_segment){.selector = 0x50,
                                         .base = 0,
                                         .limit = UINT32_MAX,
                                         .type = 11,
                                         .present = 1,
                                         .s = 1,
                                         .db = 1,
                                         .g = 1};
  parked.sregs.ss = (struct kvm_segment){
    .selector = 0x10, .base = 0x10000, .limit = 0xffff, .type = 3, .present = 1, .s = 1};
  parked.sregs.ds = parked.sregs.es = parked.sregs.ss;
  parked.sregs.fs = (struct kvm_segment){
    .selector = 0x58, .limit = UINT32_MAX, .type = 3, .present = 1, .s = 1, .db = 1, .g = 1};
  parked.sregs.gs.unusable = 1;
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 8, 0x10000, 0xffff, 0x9b, 0);
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 0x10, 0x10000, 0xffff, 0x93, 0);
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 0x28, 0x2000, 0xffff, 0x9b, 0);
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 0x50, 0, 0xfffff, 0x9b, 12);
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 0x58, 0, 0xfffff, 0x93, 12);
  assert(!daze_kvm_rm_entry_install(NULL, 1, 0, 16));
  const size_t bad_ldt_sizes[] = {8, 0x10008, 17};
  for (size_t i = 0; i < sizeof(bad_ldt_sizes) / sizeof(bad_ldt_sizes[0]); ++i)
    assert(!daze_kvm_rm_entry_install(&machine, 1, 0, bad_ldt_sizes[i]));
  assert(!daze_kvm_rm_entry_install(&machine, 1, k_memory_size - 8, 16));
  assert(setenv("DAZE_KVM_GUEST_DESCRIPTORS", "0", 1) == 0);
  assert(daze_kvm_rm_entry_install(&machine, 1, k_dpmi_ldt_address, 0x10000));
  assert(daze_read_u32(guest + 0x5870) == 0);
  assert(setenv("DAZE_KVM_GUEST_DESCRIPTORS", "1", 1) == 0);
  assert(daze_kvm_rm_entry_install(&machine, 1, k_dpmi_ldt_address, 0x10000));
  assert(daze_read_u32(guest + 0x586c) == k_dpmi_ldt_address &&
         daze_read_u32(guest + 0x5870) == 0xfff8);
  assert(unsetenv("DAZE_KVM_GUEST_DESCRIPTORS") == 0);
  assert(daze_kvm_rm_entry_install(&machine, 0, 0, 0) &&
         daze_kvm_rm_entry_install(&machine, 0xfde87e, k_dpmi_ldt_address, 0x10000));
  DazeRunMetrics metrics = {.enabled = 1};
  machine.run_metrics = &metrics;
  for (unsigned i = 0; i < 3; ++i)
    daze_write_u32(guest + 0x5874 + i * 4, i + 1);
  daze_kvm_rm_entry_sync_metrics(&machine);
  daze_kvm_rm_entry_sync_metrics(&machine);
  for (unsigned i = 0; i < 3; ++i)
    assert(metrics.kvm_guest_descriptor_calls[i] == i + 1);
  uint8_t *control = guest + DAZE_KVM_RM_ENTRY_CONTROL;
  DazeKvmDpmiMediator descriptors = {.guest = guest,
                                     .guest_size = machine.guest_size,
                                     .record_address = 0xfdea00,
                                     .mailbox_address = 0xfdea40,
                                     .gdt_address = k_dpmi_gdt_address,
                                     .gdt_size = 0x10000,
                                     .ldt_address = k_dpmi_ldt_address,
                                     .ldt_size = 0x10000};
  daze_kvm_rm_entry_publish_descriptors(NULL);
  for (unsigned kind = 0; kind < 17; ++kind) {
    DazeKvmDpmiMediator bad = descriptors;
    daze_kvm_rm_entry_publish_descriptors(&descriptors);
    assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET) ==
           DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_SIGNATURE);
    if (kind == 0) bad.guest = NULL;
    if (kind == 1) bad.guest_size = 1;
    if (kind == 2) {
      daze_write_u32(control + DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET, 0);
      daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET, 0);
    }
    if (kind == 3) bad.record_address++;
    if (kind == 4) bad.mailbox_address++;
    if (kind == 5) bad.gdt_size = 0;
    if (kind == 6) bad.gdt_size = 0x10008;
    if (kind == 7) bad.gdt_size = 9;
    if (kind == 8) bad.ldt_size = 8;
    if (kind == 9) bad.ldt_size = 0x10008;
    if (kind == 10) bad.ldt_size = 17;
    if (kind == 11) bad.gdt_address = UINT32_MAX;
    if (kind == 12) bad.ldt_address = UINT32_MAX;
    if (kind == 13) bad.ldt_address -= 8;
    if (kind == 14) bad.ldt_size -= 8;
    if (kind == 15) daze_write_u32(control + DAZE_KVM_RM_ENTRY_LDT_LAST_OFFSET, 0);
    if (kind == 16) {
#if SIZE_MAX > UINT32_MAX
      bad.guest_size = (size_t)UINT32_MAX + 1;
#else
      bad.gdt_size = 0;
#endif
    }
    daze_kvm_rm_entry_publish_descriptors(&bad);
    if (kind != 0 && kind != 1) {
      if (daze_read_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET) != 0)
        fprintf(stderr, "descriptor metadata accepted invalid case %u\n", kind);
      assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET) == 0);
    }
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET, DAZE_KVM_RM_ENTRY_SIGNATURE);
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_LDT_LAST_OFFSET, 0xfff8);
  }
  daze_kvm_rm_entry_publish_descriptors(&descriptors);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_GDT_OFFSET) ==
         k_dpmi_gdt_address);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_RAM_LAST_OFFSET) ==
         machine.guest_size - 8);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_COUNT_OFFSET, 7);
  daze_kvm_rm_entry_sync_metrics(&machine);
  daze_kvm_rm_entry_sync_metrics(&machine);
  assert(metrics.kvm_guest_descriptor_calls[3] == 7);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_GET_BASE_COUNT_OFFSET, 11);
  daze_kvm_rm_entry_sync_metrics(&machine);
  daze_kvm_rm_entry_sync_metrics(&machine);
  assert(metrics.kvm_guest_descriptor_calls[4] == 11);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_GET_BASE_COUNT_OFFSET) == 0);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_GET_BASE_COUNT_OFFSET, 5);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_COUNT_OFFSET, 3);
  assert(daze_kvm_rm_entry_install(&machine, 1, k_dpmi_ldt_address, 0x10000));
  assert(metrics.kvm_guest_descriptor_calls[3] == 10);
  assert(metrics.kvm_guest_descriptor_calls[4] == 16);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_GET_BASE_COUNT_OFFSET) == 0);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET) == 0);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_COUNT_OFFSET) == 0);
  DazeKvmDpmiMediator vectors = {.guest = guest,
                                 .guest_size = machine.guest_size,
                                 .record_address = 0xfdea00,
                                 .mailbox_address = 0xfdea40};
  vectors.default_interrupt_vectors[0x21] =
    (DazeDpmiInterruptVector){.segment = 0x50, .offset = 0x1c8};
  vectors.interrupt_vectors[1].segment = 0x84;
  vectors.interrupt_vectors[2].offset = 0xdeadbeef;
  vectors.default_interrupt_vectors[1] = vectors.default_interrupt_vectors[0x21];
  vectors.default_interrupt_vectors[2] = vectors.default_interrupt_vectors[0x21];
  daze_kvm_rm_entry_publish_vectors(NULL);
  for (unsigned kind = 0; kind < 7; ++kind) {
    DazeKvmDpmiMediator bad = vectors;
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET, 0);
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET, DAZE_KVM_RM_ENTRY_SIGNATURE);
    daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET, 1);
    if (kind == 0) bad.guest = NULL;
    if (kind == 1) bad.record_address++;
    if (kind == 2) bad.mailbox_address++;
    if (kind == 3) bad.guest_size = DAZE_KVM_RM_ENTRY_CONTROL + DAZE_KVM_RM_ENTRY_CONTROL_SIZE - 1;
    if (kind == 4) daze_write_u32(control + DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET, 0);
    if (kind == 5) daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET, 0);
    if (kind == 6) daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET, 2);
    daze_kvm_rm_entry_publish_vectors(&bad);
    assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET) == 0);
  }
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET, 1);
  daze_kvm_rm_entry_publish_vectors(&vectors);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET) ==
         DAZE_KVM_RM_ENTRY_VECTOR_SIGNATURE);
  uint8_t *table = control + DAZE_KVM_RM_ENTRY_VECTOR_TABLE_OFFSET;
  assert(daze_read_u16(table) == 0 && daze_read_u32(table + 2) == 0);
  assert(daze_read_u16(table + 6) == 0x84 && daze_read_u32(table + 8) == 0);
  assert(daze_read_u16(table + 12) == 0 && daze_read_u32(table + 14) == 0xdeadbeef);
  assert(daze_read_u16(table + 6 * 0x21) == 0x50 && daze_read_u32(table + 6 * 0x21 + 2) == 0x1c8);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_COUNT_OFFSET, 5);
  daze_kvm_rm_entry_sync_metrics(&machine);
  daze_kvm_rm_entry_sync_metrics(&machine);
  assert(metrics.kvm_guest_vector_queries == 5);
  assert(setenv("DAZE_KVM_GUEST_VECTORS", "0", 1) == 0);
  assert(daze_kvm_rm_entry_install(&machine, 1, k_dpmi_ldt_address, 0x10000));
  daze_kvm_rm_entry_publish_vectors(&vectors);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET) == 0);
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET) == 0);
  assert(unsetenv("DAZE_KVM_GUEST_VECTORS") == 0);
  assert(daze_kvm_rm_entry_install(&machine, 1, k_dpmi_ldt_address, 0x10000));
  assert(daze_read_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET) == 1);
  machine.run_metrics = NULL;
  daze_write_u16(guest + 0xfdea20, 8);
  for (unsigned kind = 0; kind < 25; ++kind) {
    ParkedState candidate = parked;
    daze_write_u32(guest + 0x5800, 0);
    switch (kind) {
    case 0:
      break;
    case 1:
      machine.guest_size = 1;
      break;
    case 2:
      daze_write_u32(guest + 0x5830, 0);
      break;
    case 3:
      candidate.sregs.cs.base = 1;
      break;
    case 4:
      candidate.sregs.cs.db = 0;
      break;
    case 5:
      candidate.sregs.gdt.base++;
      break;
    case 6:
      candidate.sregs.gdt.limit--;
      break;
    case 7:
      candidate.sregs.ldt.base++;
      break;
    case 8:
      candidate.sregs.ldt.limit--;
      break;
    case 9:
      candidate.sregs.ss.selector = 0x18;
      break;
    case 10:
      candidate.sregs.ss.db = 1;
      break;
    case 11:
      candidate.sregs.ss.limit--;
      break;
    case 12:
      candidate.sregs.ds.selector = 0x18;
      break;
    case 13:
      candidate.sregs.es.selector = 0x18;
      break;
    case 14:
      candidate.sregs.fs.selector = 0x10;
      break;
    case 15:
      candidate.sregs.gs.unusable = 0;
      break;
    case 16:
      candidate.sregs.ds.present = 0;
      break;
    case 17:
      candidate.sregs.es.present = 0;
      break;
    case 18:
      daze_write_u16(guest + 0xfdea20, 9);
      break;
    case 19:
      guest[k_dpmi_gdt_address + 14] |= 0x40;
      break;
    case 20:
      candidate.regs.r8 = 1;
      break;
    case 21:
      daze_write_u32(guest + 0x5850, 0);
      memset(guest + k_dpmi_gdt_address + 0x70, 0, 0x30);
      guest[k_dpmi_gdt_address + 0x70] = 1;
      break;
    case 22:
      candidate.sregs.gs = candidate.sregs.ds;
      candidate.sregs.gs.selector = 0x9c;
      daze_dpmi_descriptor_encode(guest + k_dpmi_ldt_address + 0x98, 0x10000, 0xffff, 0x93, 0);
      break;
    case 23:
      candidate.sregs.gs = candidate.sregs.ds;
      candidate.sregs.gs.selector = 0x100;
      daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 0x100, 0x10000, 0xffff, 0x93, 0);
      break;
    case 24:
      candidate.regs.rsp = 3;
      break;
    }
    native_arm(&machine, &candidate, 0x11000);
    assert((daze_read_u32(guest + 0x5800) == 1) == (kind == 0 || kind == 22 || kind == 23));
    if (kind == 22) assert(daze_read_u32(guest + 0x5838) == k_dpmi_ldt_address + 0x98);
    if (kind == 23) assert(daze_read_u32(guest + 0x5838) == k_dpmi_gdt_address + 0x100);
    machine.guest_size = k_memory_size;
    daze_write_u32(guest + 0x5830, 0xfde87e);
    daze_write_u16(guest + 0xfdea20, 8);
    guest[k_dpmi_gdt_address + 14] &= ~0x40;
    if (kind == 21) {
      memset(guest + k_dpmi_gdt_address + 0x70, 0, 0x30);
      daze_write_u32(guest + 0x5850, 0);
    }
  }
  daze_kvm_rm_entry_publish_vectors(&vectors);
  uint8_t saved_vectors[DAZE_KVM_RM_ENTRY_VECTOR_COUNT * DAZE_KVM_RM_ENTRY_VECTOR_STRIDE];
  memcpy(saved_vectors, table, sizeof(saved_vectors));
  native_arm(&machine, &parked, 0x11000);
  assert(memcmp(saved_vectors, table, sizeof(saved_vectors)) == 0);
  assert(install_return_bridge(&machine, &parked, 0x11000) == 1);
  daze_kvm_rm_entry_publish_vectors(&vectors);
  state.run.s.regs.regs = (struct kvm_regs){.rax = 0x98765432};
  state.run.s.regs.sregs = parked.sregs;
  state.run.s.regs.sregs.cr0 &= ~UINT64_C(1);
  ParkedState restored;
  assert(native_parked(&machine, &restored) && restored.regs.rax == parked.regs.rax &&
         restored.regs.rip == parked.regs.rip &&
         memcmp(&restored.sregs, &parked.sregs, sizeof(parked.sregs)) == 0);
  machine.guest_size = 1;
  assert(!native_parked(&machine, &restored));
  machine.guest_size = k_memory_size;
  machine.sync_regs_mask = 0;
  assert(!native_parked(&machine, &restored));
  machine.sync_regs_mask = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS;
  DazeKvmDpmiEntryResult successor;
  daze_write_u32(guest + 0x5840, 1);
  assert(!native_host_return(&machine, &successor));
  assert(daze_read_u32(guest + 0x5840) == 0 && daze_read_u32(guest + 0x2200) == parked.regs.rax);
  DazeDosfsFileService files = {0};
  DazeDosProcessState process = {0};
  DazeKvmDpmiMediator mediator = {0};
  const DazeKvmRmProcedureInput input = {
    .machine = &machine, .files = &files, .process_state = &process, .mediator = &mediator};
  mediator.guest = guest;
  mediator.guest_size = k_memory_size;
  mediator.rm_procedure_present = 1;
  mediator.rm_procedure.frame_address = k_dpmi_rm_entry_linear;
  assert(!daze_kvm_rm_procedure_reflect(&input, &successor));
  mediator.rm_procedure.frame_address = 0x11000;
  mediator.rm_procedure.stack_address = k_dpmi_rm_entry_linear;
  assert(!daze_kvm_rm_procedure_reflect(&input, &successor));
  mediator.rm_procedure.stack_address = 0x12000;
  mediator.rm_procedure.frame_address = k_dpmi_rm_entry_reserved_linear;
  assert(!daze_kvm_rm_procedure_reflect(&input, &successor));
  mediator.rm_procedure.frame_address = 0x11000;
  mediator.rm_procedure.stack_address = k_dpmi_rm_entry_reserved_linear;
  assert(!daze_kvm_rm_procedure_reflect(&input, &successor));
  mediator.rm_procedure_present = 0;
  for (unsigned kind = 0; kind < 8; ++kind) {
    DazeKvmRmProcedureInput bad = input;
    daze_write_u32(guest + 0x5840, 1);
    switch (kind) {
    case 0:
      assert(!daze_kvm_rm_entry_continue(NULL, &successor));
      continue;
    case 1:
      assert(!daze_kvm_rm_entry_continue(&bad, NULL));
      continue;
    case 2:
      bad.mediator = NULL;
      break;
    case 3:
      bad.files = NULL;
      break;
    case 4:
      bad.process_state = NULL;
      break;
    case 5:
      daze_write_u32(guest + 0x5840, 0);
      break;
    case 6:
      machine.run = NULL;
      break;
    case 7:
      machine.vcpu = -1;
      break;
    }
    assert(!daze_kvm_rm_entry_continue(&bad, &successor));
    machine.run = &state.run;
    machine.vcpu = INT32_MAX;
  }
  daze_write_u32(guest + 0x5840, 1);
  daze_write_u16(guest + 0x2a42, 1);
  state.run.exit_reason = KVM_EXIT_IO;
  state.run.io.direction = KVM_EXIT_IO_OUT;
  state.run.io.port = 0xf4;
  state.run.io.size = 1;
  state.run.io.count = 1;
  state.run.io.data_offset = sizeof(state.run);
  state.port_data[0] = 0x31;
  assert(daze_kvm_rm_entry_continue(&input, &successor) &&
         successor.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO);
  daze_write_u16(guest + 0x2a42, 0);
  state.run.exit_reason = KVM_EXIT_HLT;
  state.run.s.regs.regs.rip = 1;
  state.run.s.regs.sregs.cs.selector = 0x230;
  state.run.s.regs.sregs.cs.base = 0x2300;
  state.run.s.regs.sregs.cr0 = 0x10;
  assert(!daze_kvm_rm_entry_continue(&input, &successor));
  free(guest);
}

int main(void) {
  return_bridge_contract();
  protected_return_contract();
  descriptor_reply_contract();
  input_and_metrics_contract();
  native_binding_contract();
  return 0;
}
#else
int main(void) {
  DazeKvmDpmiEntryResult successor;
  memset(&successor, 0xa5, sizeof(successor));
  assert(!daze_kvm_rm_procedure_reflect(NULL, &successor));
  const DazeKvmDpmiEntryResult empty = {0};
  assert(memcmp(&successor, &empty, sizeof(empty)) == 0);
  return 0;
}
#endif
