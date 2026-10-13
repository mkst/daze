/* Exercise the real-mode reply codec without publishing private transport APIs. */
#include "rm_procedure.c"

#include "descriptor.h"
#include <assert.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
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
  assert(!write_back_frame(&machine, 0x100));
  assert(reflect_run(&machine, &files, NULL, &mediator, 0x200) == RMRUN_STOP);
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

int main(void) {
  descriptor_reply_contract();
  input_and_metrics_contract();
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
