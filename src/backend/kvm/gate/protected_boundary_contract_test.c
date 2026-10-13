/* Buffer-backed vector and mailbox contracts keep private metrics helpers private. */
#include "protected.c"

#include <assert.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

static DazeKvmProtectedGateLayout gate_layout(void) {
  return (DazeKvmProtectedGateLayout){.idt_address = 0x1000,
                                      .idt_limit = 0x7ff,
                                      .handler_address = 0x2000,
                                      .dos_handler_address = 0x2100,
                                      .default_dos_stub_address = 0x2200,
                                      .record_address = 0x2300,
                                      .mailbox_address = 0x2400,
                                      .handler_selector = 0x50,
                                      .handler_data_selector = 0x58,
                                      .interrupt_gate_type = 0x8e,
                                      .exchange_limit = 2,
                                      .exception_gate_vector = 0x0d,
                                      .exception_gate_type = 0x8e};
}

static void artifact_contract(void) {
  DazeKvmProtectedGateLayout valid = gate_layout();
  DazeKvmProtectedGateArtifacts output;
  memset(&output, 0xa5, sizeof(output));
  DazeKvmProtectedGateArtifacts before = output;
  assert(!daze_kvm_protected_gate_build(NULL, &output));
  assert(!daze_kvm_protected_gate_build(&valid, NULL));
  for (int kind = 0; kind < 26; ++kind) {
    DazeKvmProtectedGateLayout bad = valid;
    switch (kind) {
    case 0:
      bad.idt_address = UINT32_MAX;
      break;
    case 1:
      bad.idt_limit = 0x18e;
      break;
    case 2:
      bad.handler_address = 0;
      break;
    case 3:
      bad.default_dos_stub_address = 0;
      break;
    case 4:
      bad.record_address = 0;
      break;
    case 5:
      bad.mailbox_address = 0;
      break;
    case 6:
      bad.handler_selector |= 4;
      break;
    case 7:
      bad.handler_data_selector |= 3;
      break;
    case 8:
      bad.handler_selector = 0;
      break;
    case 9:
      bad.handler_data_selector = 0;
      break;
    case 10:
      bad.interrupt_gate_type = 0x85;
      break;
    case 11:
      bad.exchange_limit = 0;
      break;
    case 12:
      bad.exchange_limit = DAZE_KVM_PROTECTED_GATE_MAX_EXCHANGES + 1;
      break;
    case 13:
      bad.exception_gate_type = 0x86;
      break;
    case 14:
      bad.record_address = bad.handler_address;
      break;
    case 15:
      bad.dos_handler_address = bad.handler_address;
      break;
    case 16:
      bad.dos_handler_address = bad.record_address;
      break;
    case 17:
      bad.dos_handler_address = bad.mailbox_address;
      break;
    case 18:
      bad.default_dos_stub_address = bad.handler_address;
      break;
    case 19:
      bad.default_dos_stub_address = bad.dos_handler_address;
      break;
    case 20:
      bad.default_dos_stub_address = bad.record_address;
      break;
    case 21:
      bad.default_dos_stub_address = bad.mailbox_address;
      break;
    case 22:
      bad.mailbox_address = bad.handler_address;
      break;
    case 23:
      bad.mailbox_address = bad.record_address;
      break;
    case 24:
      bad.exception_gate_vector = 0xff;
      bad.idt_limit = 0x18f;
      break;
    case 25:
      bad.handler_address = bad.record_address - 1;
      break;
    }
    assert(!daze_kvm_protected_gate_build(&bad, &output));
    assert(memcmp(&before, &output, sizeof(output)) == 0);
  }
  valid.interrupt_gate_type = 0x86;
  assert(daze_kvm_protected_gate_build(&valid, &output));
  assert(output.idt_entry[5] == 0x86 && output.dos_idt_entry[5] == 0x86 &&
         output.handler_size <= sizeof(output.handler) && output.handler_size >= 2 &&
         output.handler[output.handler_size - 2] == 0x66 &&
         output.handler[output.handler_size - 1] == 0xcf);
  valid.exception_gate_type = 0;
  valid.dos_handler_address = 0;
  assert(daze_kvm_protected_gate_build(&valid, &output));
  valid = gate_layout();
  valid.exception_gate_vector = 0xff;
  assert(daze_kvm_protected_gate_build(&valid, &output));
}

static void virtual_interrupt_contract(void) {
  DazeKvmProtectedGateLayout layout = gate_layout();
  layout.virtual_handler_address = 0x2800;
  layout.virtual_control_address = 0x2600;
  layout.legacy_np_capture_address = 0x2900;
  DazeKvmProtectedGateArtifacts output;
  assert(daze_kvm_protected_gate_build(&layout, &output));
  assert(output.virtual_control[0] == 1 &&
         output.virtual_handler_size <= sizeof(output.virtual_handler));
  const uint32_t occupied[] = {layout.idt_address,
                               layout.handler_address,
                               layout.dos_handler_address,
                               layout.default_dos_stub_address,
                               layout.record_address,
                               layout.mailbox_address,
                               layout.legacy_np_capture_address,
                               layout.virtual_handler_address};
  for (size_t i = 0; i < sizeof(occupied) / sizeof(occupied[0]); i++) {
    DazeKvmProtectedGateLayout bad = layout;
    bad.virtual_control_address = occupied[i];
    const DazeKvmProtectedGateArtifacts before = output;
    assert(!daze_kvm_protected_gate_build(&bad, &output));
    assert(memcmp(&before, &output, sizeof(output)) == 0);
    if (i < 7) {
      bad = layout;
      bad.virtual_handler_address = occupied[i];
      assert(!daze_kvm_protected_gate_build(&bad, &output));
    }
  }
  for (unsigned i = 0; i < 5; i++) {
    DazeKvmProtectedGateLayout bad = layout;
    if (i == 0) bad.virtual_handler_address = 0;
    if (i == 1) bad.virtual_control_address = 0;
    if (i == 2) bad.virtual_handler_address = UINT32_MAX;
    if (i == 3) bad.virtual_control_address = UINT32_MAX;
    if (i == 4) bad.record_address = bad.handler_address + DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE;
    assert(!daze_kvm_protected_gate_build(&bad, &output));
  }
  layout.dos_handler_address = layout.legacy_np_capture_address = 0;
  assert(daze_kvm_protected_gate_build(&layout, &output));
  uint8_t guest[0x4000] = {0};
  DazeRunMetrics metrics = {.enabled = 1};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .run_metrics = &metrics};
  int enabled = 1;
  assert(!daze_kvm_protected_gate_sync_virtual_interrupts(NULL, &layout, &enabled));
  assert(!daze_kvm_protected_gate_sync_virtual_interrupts(&machine, NULL, &enabled));
  assert(!daze_kvm_protected_gate_sync_virtual_interrupts(&machine, &layout, NULL));
  for (unsigned i = 0; i < 5; i++) {
    DazeKvmMachine bad = machine;
    DazeKvmProtectedGateLayout bad_layout = layout;
    if (i == 0) bad.guest = NULL;
    if (i == 1) bad.guest_size = layout.virtual_control_address;
    if (i == 2) bad_layout.virtual_handler_address = 0;
    if (i == 3) bad_layout.virtual_control_address = 0;
    if (i == 4) guest[layout.virtual_control_address] = 2;
    assert(!daze_kvm_protected_gate_sync_virtual_interrupts(&bad, &bad_layout, &enabled));
  }
  uint8_t *control = guest + layout.virtual_control_address;
  control[0] = 0;
  daze_write_u32(control + 4, 3);
  daze_write_u32(control + 8, 1);
  daze_write_u32(control + 12, 4);
  assert(daze_kvm_protected_gate_sync_virtual_interrupts(&machine, &layout, &enabled));
  assert(enabled == 0 && metrics.kvm_guest_virtual_interrupt_calls[0] == UINT64_C(0x100000003) &&
         metrics.kvm_guest_virtual_interrupt_calls[1] == 4 && daze_read_u32(control + 4) == 0);
  assert(daze_kvm_protected_gate_sync_virtual_interrupts(&machine, &layout, &enabled));
  assert(metrics.kvm_guest_virtual_interrupt_calls[1] == 4);
  metrics.enabled = 0;
  control[0] = 1;
  daze_write_u32(control + 4, 2);
  assert(daze_kvm_protected_gate_sync_virtual_interrupts(&machine, &layout, &enabled));
  assert(enabled == 1 && metrics.kvm_guest_virtual_interrupt_calls[1] == 4);
  machine.run_metrics = NULL;
  assert(daze_kvm_protected_gate_sync_virtual_interrupts(&machine, &layout, &enabled));
  control[0] = 2;
  DazeKvmDpmiMediator mediator = {
    .guest = guest, .guest_size = sizeof(guest), .virtual_interrupts_enabled = &enabled};
  DazeKvmDpmiEntryResult boundary = {.observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                                     .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                                                     .pio_size = 1,
                                                     .pio_count = 1,
                                                     .pio_port = DAZE_KVM_DPMI_MEDIATOR_PORT,
                                                     .pio_value_present = 1,
                                                     .pio_value = DAZE_KVM_DPMI_MEDIATOR_MARKER}};
  DazeKvmProtectedGateExchange exchange;
  assert(!process_mediator_boundary_impl(&machine, &mediator, &layout, &boundary, &exchange));
  DazeKvmProtectedGateResult result;
  assert(run_from_boundary(&machine, &mediator, &layout, &boundary, &result) ==
         DAZE_KVM_PROTECTED_GATE_INVALID);
  layout.exchange_limit = 0;
  assert(run_from_boundary(&machine, &mediator, &layout, &boundary, &result) ==
         DAZE_KVM_PROTECTED_GATE_INVALID);
  layout.virtual_handler_address = layout.virtual_control_address = 0;
  assert(daze_kvm_protected_gate_sync_virtual_interrupts(&machine, &layout, NULL));
}

static void projection_contract(void) {
  uint8_t guest[0x4000] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .vcpu = -1};
  DazeKvmDpmiMediator mediator = {.guest = guest,
                                  .guest_size = sizeof(guest),
                                  .gdt_address = 0x3000,
                                  .gdt_size = 0x100,
                                  .ldt_address = 0x3200,
                                  .ldt_size = 0x100};
  DazeKvmProtectedGateLayout layout = gate_layout();
  const uint8_t code16[8] = {0xff, 0xff, 0, 0, 0, 0x9a, 0, 0};
  memcpy(guest + 0x3008, code16, 8);
  memcpy(guest + 0x3208, code16, 8);
  for (int kind = 0; kind < 3; ++kind) {
    assert(!daze_kvm_protected_gate_project_exception_vector(
      kind == 0 ? NULL : &machine, kind == 1 ? NULL : &mediator, kind == 2 ? NULL : &layout));
    assert(!daze_kvm_protected_gate_project_interrupt_vector(
      kind == 0 ? NULL : &machine, kind == 1 ? NULL : &mediator, kind == 2 ? NULL : &layout, 0x21));
  }
  uint8_t *entry = guest + layout.idt_address + 0x21 * 8;
  assert(daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x21));
  assert(daze_read_u16(entry) == layout.dos_handler_address && daze_read_u16(entry + 2) == 0x50 &&
         entry[5] == 0x8e);
  memset(entry, 0xa5, 8);
  mediator.interrupt_vectors[0x21] = (DazeDpmiInterruptVector){.segment = 8, .offset = 0x1234};
  assert(daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x21));
  assert(daze_read_u16(entry) == 0x1234 && entry[5] == 0x8e);
  mediator.interrupt_vectors[0x21].offset = 0x12345678;
  assert(daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x21));
  assert(daze_read_u16(entry) == 0x5678 && daze_read_u16(entry + 6) == 0x1234 && entry[5] == 0x86);
  mediator.interrupt_vectors[0x2f] = (DazeDpmiInterruptVector){.segment = 0x0c, .offset = 0x4321};
  assert(daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x2f));
  entry = guest + layout.idt_address + 0x2f * 8;
  assert(daze_read_u16(entry) == 0x4321 && daze_read_u16(entry + 2) == 0x0c && entry[5] == 0x86);
  mediator.interrupt_vectors[0x2f].segment = 0x10;
  uint8_t before[8];
  memcpy(before, entry, 8);
  assert(!daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x2f));
  assert(memcmp(entry, before, 8) == 0);
  mediator.exception_vectors[0x0d] = (DazeDpmiExceptionVector){.segment = 0x10, .offset = 0x1234};
  assert(!daze_kvm_protected_gate_project_exception_vector(&machine, &mediator, &layout));
  layout.idt_address = sizeof(guest) - 1;
  assert(!daze_kvm_protected_gate_project_exception_vector(&machine, &mediator, &layout));
  assert(!daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x21));
  layout.idt_address = UINT32_MAX - 0x190;
  layout.exception_gate_type = 0;
  assert(!daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0xff));
  layout = gate_layout();
  layout.exception_gate_type = 0;
  assert(daze_kvm_protected_gate_project_exception_vector(&machine, &mediator, &layout));
  uint8_t output[8];
  memset(output, 0xa5, sizeof(output));
  DazeDpmiInterruptVector target = {.segment = 8};
  for (int kind = 0; kind < 3; ++kind)
    assert(!daze_kvm_protected_gate_client_entry(kind == 0 ? NULL : guest, sizeof(guest), 0x3000,
                                                 0xff, 0x3200, 0xff, kind == 1 ? NULL : &target,
                                                 kind == 2 ? NULL : output));
  assert(!daze_kvm_protected_gate_client_entry(guest, sizeof(guest), UINT32_MAX - 4, 0xff, 0x3200,
                                               0xff, &target, output));
  assert(!daze_kvm_protected_gate_client_entry(guest, sizeof(guest), sizeof(guest) - 8, 0xff,
                                               0x3200, 0xff, &target, output));
  assert(!daze_kvm_protected_gate_client_entry(guest, sizeof(guest), 0x3000, 8, 0x3200, 0xff,
                                               &target, output));
  for (size_t i = 0; i < sizeof(output); ++i)
    assert(output[i] == 0xa5);
}

static void metrics_contract(void) {
  DazeRunMetrics metrics = {0};
  record_dpmi_function(&metrics, 0x900, 10);
  record_dpmi_function(&metrics, 0x901, 20);
  record_dpmi_function(&metrics, 0x900, 30);
  assert(metrics.kvm_dpmi_function_count == 2 && metrics.kvm_dpmi_functions[0].calls == 2 &&
         metrics.kvm_dpmi_functions[0].mediator_nanoseconds == 40 &&
         metrics.kvm_dpmi_functions[1].calls == 1);
  for (uint16_t i = 2; i < DAZE_RUN_METRICS_DPMI_FUNCTION_CAPACITY; ++i)
    record_dpmi_function(&metrics, i, 1);
  record_dpmi_function(&metrics, 0xffff, 50);
  record_dpmi_function(&metrics, 0x900, 60);
  assert(metrics.kvm_dpmi_function_count == DAZE_RUN_METRICS_DPMI_FUNCTION_CAPACITY &&
         metrics.kvm_dpmi_function_overflow_calls == 1 &&
         metrics.kvm_dpmi_functions[0].calls == 3 &&
         metrics.kvm_dpmi_functions[0].mediator_nanoseconds == 100);
  DazeKvmProtectedGateExchange exchange = {.function = 0x501};
  record_virtual_interrupt_site(&metrics, &exchange);
  assert(metrics.kvm_virtual_interrupt_site_count == 0);
  exchange.function = 0x900;
  record_virtual_interrupt_site(&metrics, &exchange);
  record_virtual_interrupt_site(&metrics, &exchange);
  exchange.function = 0x901;
  record_virtual_interrupt_site(&metrics, &exchange);
  exchange.client_cs = 8;
  record_virtual_interrupt_site(&metrics, &exchange);
  for (uint16_t i = 3; i < DAZE_RUN_METRICS_VIRTUAL_INTERRUPT_SITE_CAPACITY; ++i) {
    exchange.client_ip = i;
    record_virtual_interrupt_site(&metrics, &exchange);
  }
  exchange.client_ip = 0xffff;
  record_virtual_interrupt_site(&metrics, &exchange);
  assert(metrics.kvm_virtual_interrupt_site_count ==
           DAZE_RUN_METRICS_VIRTUAL_INTERRUPT_SITE_CAPACITY &&
         metrics.kvm_virtual_interrupt_sites[0].calls == 2 &&
         metrics.kvm_virtual_interrupt_site_overflow_calls == 1);
}

static void boundary_contract(void) {
  uint8_t guest[0x4000] = {0};
  DazeRunMetrics metrics = {.enabled = 1};
  DazeKvmMachine machine = {
    .guest = guest, .guest_size = sizeof(guest), .vcpu = -1, .run_metrics = &metrics};
  DazeDpmiLinearMemory linear;
  int virtual_interrupts = 1;
  daze_dpmi_linear_memory_init(&linear, 0, 0x1000);
  DazeKvmDpmiMediator mediator = {.guest = guest,
                                  .guest_size = sizeof(guest),
                                  .record_address = 0x2300,
                                  .mailbox_address = 0x2400,
                                  .ldt_address = 0x3200,
                                  .ldt_size = 0x100,
                                  .linear_memory = &linear,
                                  .virtual_interrupts_enabled = &virtual_interrupts};
  DazeKvmProtectedGateLayout layout = gate_layout();
  DazeKvmDpmiEntryResult boundary = {.observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                                     .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                                                     .pio_size = 1,
                                                     .pio_count = 1,
                                                     .pio_value_present = 1,
                                                     .pio_port = DAZE_KVM_DPMI_MEDIATOR_PORT,
                                                     .pio_value = DAZE_KVM_DPMI_MEDIATOR_MARKER}};
  DazeKvmProtectedGateExchange exchange;
  DazeKvmDpmiEntryResult successor;
  for (int kind = 0; kind < 9; ++kind) {
    DazeKvmDpmiMediator bad_mediator = mediator;
    DazeKvmProtectedGateLayout bad_layout = layout;
    if (kind == 6) bad_mediator.guest = guest + 1;
    if (kind == 7) --bad_mediator.guest_size;
    if (kind == 8) bad_layout.exchange_limit = 0;
    assert(daze_kvm_protected_gate_resume_mediator_boundary(
             kind == 0 ? NULL : &machine, kind == 1 ? NULL : &bad_mediator,
             kind == 2 ? NULL : &bad_layout, kind == 3 ? NULL : &boundary,
             kind == 4 ? NULL : &exchange,
             kind == 5 ? NULL : &successor) == DAZE_KVM_PROTECTED_GATE_INVALID);
  }
  for (int kind = 0; kind < 7; ++kind) {
    DazeKvmDpmiEntryResult bad = boundary;
    switch (kind) {
    case 0:
      bad.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
      break;
    case 1:
      bad.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_IN;
      break;
    case 2:
      bad.observation.pio_size = 2;
      break;
    case 3:
      bad.observation.pio_count = 2;
      break;
    case 4:
      bad.observation.pio_value_present = 0;
      break;
    case 5:
      bad.observation.pio_port++;
      break;
    case 6:
      bad.observation.pio_value++;
      break;
    }
    assert(daze_kvm_protected_gate_resume_mediator_boundary(&machine, &mediator, &layout, &bad,
                                                            &exchange, &successor) ==
           DAZE_KVM_PROTECTED_GATE_INVALID);
    assert(metrics.kvm_dpmi_mediator_calls == 0);
  }
  daze_write_u16(guest + 0x2300, 0x900);
  daze_write_u32(guest + 0x2300 + 32, 0x28);
  daze_write_u32(guest + 0x2300 + 36, 2);
  daze_write_u16(guest + 0x2300 + 40, 0x1234);
  assert(daze_kvm_protected_gate_resume_mediator_boundary(&machine, &mediator, &layout, &boundary,
                                                          &exchange, &successor) ==
         DAZE_KVM_PROTECTED_GATE_FAILED);
  assert(exchange.function == 0x900 && daze_read_u32(guest + 0x2400 + 20) >> 16 == 0x1234 &&
         metrics.kvm_dpmi_mediator_calls == 1 && metrics.kvm_virtual_interrupt_site_count == 1);
  metrics.enabled = 0;
  (void)daze_kvm_protected_gate_resume_mediator_boundary(&machine, &mediator, &layout, &boundary,
                                                         &exchange, &successor);
  assert(metrics.kvm_dpmi_mediator_calls == 1);
  DazeKvmProtectedGateResult result;
  for (int kind = 0; kind < 6; ++kind) {
    DazeKvmDpmiMediator bad = mediator;
    DazeKvmProtectedGateLayout bad_layout = layout;
    if (kind == 3) bad.guest = guest + 1;
    if (kind == 4) bad.guest_size--;
    if (kind == 5) bad_layout.exchange_limit = 0;
    assert(daze_kvm_protected_gate_run(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &bad,
                                       &bad_layout, kind == 2 ? NULL : &result) ==
           DAZE_KVM_PROTECTED_GATE_INVALID);
  }
  assert(daze_kvm_protected_gate_run(&machine, &mediator, &layout, &result) ==
         DAZE_KVM_PROTECTED_GATE_FAILED);
}

int main(void) {
  virtual_interrupt_contract();
  artifact_contract();
  projection_contract();
  metrics_contract();
  boundary_contract();
  return 0;
}
