/* Keep boundary codecs private while testing the same source used by the live owner. */
#include "owner.c"

#include <assert.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

static void request_capture_contract(void) {
  uint8_t guest[0x1000] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  const DazeKvmProtectedGateLayout gate = {.record_address = 0x100, .handler_selector = 0x50};
  DazeKvmDpmiEntryResult boundary = {.cs = 0x50,
                                     .ds = 0x14,
                                     .ss_base = 0x200,
                                     .esp = 0x80,
                                     .bx = 0x1111,
                                     .cx = 0x2222,
                                     .dx = 0x3333,
                                     .es = 0x24,
                                     .si = 0x4444,
                                     .di = 0x5555,
                                     .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                                     .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                                                     .pio_port = DAZE_KVM_DPMI_MEDIATOR_PORT,
                                                     .pio_size = 1,
                                                     .pio_count = 1,
                                                     .pio_value_present = 1,
                                                     .pio_value = DAZE_KVM_DPMI_MEDIATOR_MARKER}};
  for (size_t i = 0; i < 11; ++i)
    daze_write_u32(guest + 0x100 + 4 * i, 0xa5a50000u + i);
  uint16_t function, selector;
  uint32_t operand;
  assert(capture_mediator_request(&machine, &gate, &boundary, &function, &selector, &operand));
  assert(function == 0 && selector == 1 && operand == 0x20003);
  for (int kind = 0; kind < 16; ++kind) {
    DazeKvmDpmiEntryResult invalid = boundary;
    DazeKvmProtectedGateLayout invalid_gate = gate;
    DazeKvmMachine invalid_machine = machine;
    if (kind == 6) invalid.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
    if (kind == 7) invalid.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_IN;
    if (kind == 8) invalid.observation.pio_size = 2;
    if (kind == 9) invalid.observation.pio_count = 2;
    if (kind == 10) invalid.observation.pio_value_present = 0;
    if (kind == 11) invalid.observation.pio_port++;
    if (kind == 12) invalid.observation.pio_value++;
    if (kind == 13) invalid_gate.record_address = sizeof(guest) - DAZE_KVM_DPMI_RECORD_SIZE + 1;
    if (kind == 14) invalid_gate.record_address = UINT32_MAX;
    if (kind == 15) invalid_machine.guest_size = 0;
    function = 0xaaaa;
    selector = 0xbbbb;
    operand = 0xccccdddd;
    assert(!capture_mediator_request(kind == 0 ? NULL : &invalid_machine,
                                     kind == 1 ? NULL : &invalid_gate, kind == 2 ? NULL : &invalid,
                                     kind == 3 ? NULL : &function, kind == 4 ? NULL : &selector,
                                     kind == 5 ? NULL : &operand));
    assert(function == 0xaaaa && selector == 0xbbbb && operand == 0xccccdddd);
  }
  boundary.observation.pio_value = DAZE_KVM_PROTECTED_DOS_MARKER;
  DazeKvmRunnerRequestImage request;
  assert(capture_protected_dos_request(&machine, &gate, &boundary, &request));
  assert(request.vector == 0x21 && request.ax == 0 && request.bx == 1 && request.cx == 2 &&
         request.dx == 3 && request.ds == 0x14 && request.es == 5 && request.si == 6 &&
         request.di == 4 && request.return_ip == 7 && request.return_cs == 8 && request.flags == 9);
  for (int kind = 0; kind < 12; ++kind) {
    DazeKvmDpmiEntryResult invalid = boundary;
    DazeKvmProtectedGateLayout invalid_gate = gate;
    if (kind == 4) invalid.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
    if (kind == 5) invalid.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_IN;
    if (kind == 6) invalid.observation.pio_port++;
    if (kind == 7) invalid.observation.pio_value_present = 0;
    if (kind == 8) invalid.observation.pio_value++;
    if (kind == 9) invalid.cs++;
    if (kind == 10) invalid_gate.record_address = sizeof(guest) - 1;
    if (kind == 11) invalid_gate.record_address = UINT32_MAX;
    memset(&request, 0xa5, sizeof(request));
    const DazeKvmRunnerRequestImage before = request;
    assert(
      !capture_protected_dos_request(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &invalid_gate,
                                     kind == 2 ? NULL : &invalid, kind == 3 ? NULL : &request));
    assert(memcmp(&before, &request, sizeof(request)) == 0);
  }
  boundary.observation.pio_port = DAZE_PORT_GATE;
  const uint8_t vectors[] = {0x10, 0x11, 0x1a, 0x21, 0x2f, 0x31, 0xfe};
  const uint16_t stack[] = {0x3000, 0x1234, 0x4321, 0x202};
  for (size_t i = 0; i < 4; ++i)
    daze_write_u16(guest + 0x280 + 2 * i, stack[i]);
  for (size_t i = 0; i < sizeof(vectors); ++i) {
    boundary.observation.pio_value = vectors[i];
    assert(capture_runner_request(&machine, &boundary, &request));
    assert(request.vector == vectors[i] && request.ax == 0x3000 && request.bx == 0x1111 &&
           request.cx == 0x2222 && request.dx == 0x3333 && request.ds == 0x14 &&
           request.es == 0x24 && request.si == 0x4444 && request.di == 0x5555 &&
           request.return_ip == 0x1234 && request.return_cs == 0x4321 && request.flags == 0x202);
  }
  for (int kind = 0; kind < 10; ++kind) {
    DazeKvmDpmiEntryResult invalid = boundary;
    if (kind == 3) invalid.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
    if (kind == 4) invalid.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_IN;
    if (kind == 5) invalid.observation.pio_port++;
    if (kind == 6) invalid.observation.pio_value_present = 0;
    if (kind == 7) invalid.esp = sizeof(guest);
    if (kind == 8) invalid.observation.pio_value = 0x12;
    if (kind == 9) invalid.ss_base = UINT32_MAX - invalid.esp - 1;
    const DazeKvmRunnerRequestImage before = request;
    assert(!capture_runner_request(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &invalid,
                                   kind == 2 ? NULL : &request));
    assert(memcmp(&before, &request, sizeof(request)) == 0);
  }
}

static void state_capture_contract(void) {
  uint8_t guest[0x1000] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  DazeKvmDpmiEntryResult boundary = {.ss_base = 0x100,
                                     .esp = 0x80,
                                     .es_base = 0x200,
                                     .di = 0x90,
                                     .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                                     .pio_port = DAZE_PORT_GATE,
                                                     .pio_value_present = 1,
                                                     .pio_value = DAZE_KVM_STATE_SAVE_GATE_MARKER}};
  const DpmiAlternateState saved = {.cs = 0x1234,
                                    .ds = 0x4567,
                                    .ss = 0x2345,
                                    .eip = 0x3456,
                                    .esp = 0x4567,
                                    .eflags = 0x202,
                                    .eax = 0x12345678};
  assert(daze_dpmi_alternate_state_pack(&saved, guest + 0x290));
  daze_write_u16(guest + 0x180, 1);
  DpmiAlternateState output;
  uint32_t address;
  assert(capture_state_restore_request(&machine, &boundary, &output, &address));
  assert(address == 0x290 && memcmp(&saved, &output, sizeof(saved)) == 0);
  for (int kind = 0; kind < 14; ++kind) {
    DazeKvmDpmiEntryResult invalid = boundary;
    if (kind == 4) invalid.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
    if (kind == 5) invalid.observation.pio_port++;
    if (kind == 6) invalid.observation.pio_value_present = 0;
    if (kind == 7) invalid.observation.pio_value++;
    if (kind == 8) invalid.ss_base = UINT32_MAX;
    if (kind == 9) invalid.es_base = UINT32_MAX;
    if (kind == 10) invalid.esp = sizeof(guest);
    if (kind == 11) invalid.es_base = sizeof(guest) - DAZE_DPMI_ALTERNATE_STATE_SIZE;
    if (kind == 12) daze_write_u16(guest + 0x180, 0);
    if (kind == 13) memset(guest + 0x290, 0, DAZE_DPMI_ALTERNATE_STATE_SIZE);
    address = 0xaabbccdd;
    assert(!capture_state_restore_request(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &invalid,
                                          kind == 2 ? NULL : &output, kind == 3 ? NULL : &address));
    assert(address == 0xaabbccdd);
    daze_write_u16(guest + 0x180, 1);
  }
}

static void protected_reply_contract(void) {
  uint8_t guest[0x400] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  DazeKvmProtectedGateLayout gate = {.record_address = 0x100, .mailbox_address = 0x200};
  uint8_t reply[16];
  for (size_t i = 0; i < 11; ++i)
    daze_write_u32(guest + 0x100 + 4 * i, 0x12340000u + i);
  for (size_t i = 0; i < 8; ++i)
    daze_write_u16(reply + 2 * i, 0x500 + i);
  assert(reply_protected_dos_request(&machine, &gate, reply));
  const uint32_t expected[] = {0x12340500, 0x12340501, 0x12340502, 0x12340504,
                               0x12340505, 0x000a0506, 0x12340503, 0x12340507};
  for (size_t i = 0; i < 8; ++i)
    assert(daze_read_u32(guest + 0x200 + 4 * i) == expected[i]);
  daze_write_u16(guest + 0x100, 0x5d06);
  assert(reply_protected_dos_request(&machine, &gate, reply));
  assert(daze_read_u32(guest + 0x214) == 0x03000506);
  for (int kind = 0; kind < 5; ++kind) {
    DazeKvmProtectedGateLayout invalid = gate;
    if (kind == 3) invalid.record_address = sizeof(guest) - 1;
    if (kind == 4) invalid.mailbox_address = sizeof(guest) - 1;
    uint8_t before[sizeof(guest)];
    memcpy(before, guest, sizeof(before));
    assert(!reply_protected_dos_request(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &invalid,
                                        kind == 2 ? NULL : reply));
    assert(memcmp(before, guest, sizeof(guest)) == 0);
  }
}

static void handoff_contract(void) {
  const DazeKvmRunnerRequestCommon process = {.dpmi_entry_segment = 0x200};
  const DazeKvmRunnerDpmiHandoff handoff = {
    .valid = 1,
    .return_cs = 0x200,
    .return_ip = 2,
    .ds = 0x1234,
    .caller_return_cs = 0x300,
    .entry_snapshot = {.valid = 1, .cs = 0x200, .ip = 2, .ds = 0x1234}};
  assert(handoff_agrees_with_request(&process, &handoff));
  for (int kind = 0; kind < 10; ++kind) {
    DazeKvmRunnerDpmiHandoff invalid = handoff;
    if (kind == 2) invalid.valid = 0;
    if (kind == 3) invalid.return_cs++;
    if (kind == 4) invalid.return_ip++;
    if (kind == 5) invalid.entry_snapshot.valid = 0;
    if (kind == 6) invalid.entry_snapshot.cs++;
    if (kind == 7) invalid.entry_snapshot.ip++;
    if (kind == 8) invalid.entry_snapshot.ds++;
    if (kind == 9) invalid.caller_return_cs = 0;
    assert(!handoff_agrees_with_request(kind == 0 ? NULL : &process, kind == 1 ? NULL : &invalid));
  }
  DazeKvmRunnerDpmiHandoff alias = handoff;
  alias.return_cs = alias.entry_snapshot.cs = 0;
  alias.return_ip = alias.entry_snapshot.ip = 0x2002;
  assert(handoff_agrees_with_request(&process, &alias));
  alias.return_ip = alias.entry_snapshot.ip = 0x2003;
  assert(!handoff_agrees_with_request(&process, &alias));
}

static void transition_write_contract(void) {
  DazeKvmTransitionPlan plan = {0};
  const DazeKvmProtectedGateLayout gate = {.handler_address = 0x100,
                                           .dos_handler_address = 0x200,
                                           .default_dos_stub_address = 0x300,
                                           .idt_address = 0x400};
  const DazeKvmProtectedGateArtifacts artifacts = {
    .handler_size = 8, .dos_handler_size = 8, .default_dos_stub_size = 8};
  assert(gate_writes_valid(&plan, &gate, &artifacts, 0x1000));
  assert(gate_writes_valid(&plan, NULL, NULL, 0x1000));
  for (int kind = 0; kind < 6; ++kind) {
    DazeKvmProtectedGateLayout invalid = gate;
    DazeKvmProtectedGateArtifacts invalid_artifacts = artifacts;
    if (kind == 1) invalid_artifacts.handler_size = 0;
    if (kind == 2) invalid_artifacts.dos_handler_size = 0;
    if (kind == 3) invalid_artifacts.default_dos_stub_size = 0;
    if (kind == 4) invalid.dos_handler_address = 0;
    if (kind == 5) invalid.default_dos_stub_address = 0;
    assert(!gate_writes_valid(&plan, &invalid, kind == 0 ? NULL : &invalid_artifacts, 0x1000));
  }
  const uint32_t addresses[] = {0x100, 0x200, 0x300, 0x400 + 0x31 * 8, 0x400 + 0x21 * 8};
  for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); ++i) {
    plan.write_count = 1;
    plan.writes[0] = (DazeKvmTransitionWrite){.address = addresses[i], .size = 1};
    const DazeKvmTransitionPlan before = plan;
    assert(!gate_writes_valid(&plan, &gate, &artifacts, 0x1000));
    assert(memcmp(&plan, &before, sizeof(plan)) == 0);
    plan.write_count = 0;
    plan.reserved_range_count = 1;
    plan.reserved_ranges[0] = (DazeKvmTransitionReservedRange){.address = addresses[i], .size = 1};
    assert(!gate_writes_valid(&plan, &gate, &artifacts, 0x1000));
    plan.reserved_range_count = 0;
  }
  DazeKvmStateSaveGateLayout state_gate = {.handler_address = 0x100, .idt_address = 0x400};
  const DazeKvmStateSaveGateArtifacts state_artifacts = {0};
  DazeKvmRawSwitchGateLayout raw_gate = {
    .handler_address = 0x100, .real_handler_address = 0x1000, .idt_address = 0x400};
  const DazeKvmRawSwitchGateArtifacts raw_artifacts = {0};
  assert(!state_gate_writes_valid(&plan, &state_gate, NULL, 0x4000));
  state_gate.idt_address = UINT32_MAX;
  assert(!state_gate_writes_valid(&plan, &state_gate, &state_artifacts, 0x4000));
  assert(!raw_gate_writes_valid(&plan, &raw_gate, NULL, 0x4000));
  raw_gate.idt_address = UINT32_MAX;
  assert(!raw_gate_writes_valid(&plan, &raw_gate, &raw_artifacts, 0x4000));
  raw_gate.idt_address = 0x400;
  assert(!raw_gate_writes_valid(&plan, &raw_gate, &raw_artifacts, 0));

  DazeKvmRunnerDpmiHandoff handoff = {.entry_snapshot = {.valid = 1, .ss = 0x10, .sp = 0x80}};
  assert(plan_preserves_handoff_frame(&plan, &handoff, 0x1000));
  assert(!plan_preserves_handoff_frame(NULL, &handoff, 0x1000));
  assert(!plan_preserves_handoff_frame(&plan, NULL, 0x1000));
  handoff.entry_snapshot.valid = 0;
  assert(!plan_preserves_handoff_frame(&plan, &handoff, 0x1000));
  handoff.entry_snapshot.valid = 1;
  assert(!plan_preserves_handoff_frame(&plan, &handoff, 0x180));
  handoff.entry_snapshot.sp = 1;
  assert(!plan_preserves_handoff_frame(&plan, &handoff, 0x1000));

  DazeKvmGuestWrite writes[DAZE_KVM_TRANSITION_PLAN_WRITE_COUNT + 13];
  DazeKvmDpmiEntryLayout output;
  plan.write_count = DAZE_KVM_TRANSITION_PLAN_WRITE_COUNT + 1;
  memset(&output, 0xa5, sizeof(output));
  const DazeKvmDpmiEntryLayout before = output;
  assert(!plan_entry_layout(&plan, NULL, NULL, NULL, NULL, NULL, NULL, writes, &output, 0, 0x1000));
  assert(memcmp(&before, &output, sizeof(output)) == 0);
  plan.write_count = 0;
  assert(!plan_entry_layout(NULL, NULL, NULL, NULL, NULL, NULL, NULL, writes, &output, 0, 0x1000));
  assert(!plan_entry_layout(&plan, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &output, 0, 0x1000));
  assert(!plan_entry_layout(&plan, NULL, NULL, NULL, NULL, NULL, NULL, writes, NULL, 0, 0x1000));
  DazeKvmProtectedGateLayout virtual_gate = {.virtual_handler_address = 0x800,
                                             .virtual_control_address = 0x880,
                                             .handler_address = 0x200,
                                             .dos_handler_address = 0x300,
                                             .default_dos_stub_address = 0x400,
                                             .idt_address = 0x500};
  DazeKvmProtectedGateArtifacts virtual_artifacts = {.virtual_handler_size = 32,
                                                     .handler_size = 16,
                                                     .dos_handler_size = 16,
                                                     .default_dos_stub_size = 16};
  assert(plan_entry_layout(&plan, &virtual_gate, &virtual_artifacts, NULL, NULL, NULL, NULL, writes,
                           &output, 0, 0x1000));
  for (unsigned i = 0; i < 5; i++) {
    DazeKvmProtectedGateLayout bad = virtual_gate;
    if (i == 0) bad.virtual_handler_address = 0xff0;
    if (i == 1) bad.virtual_control_address = 0xff0;
    if (i == 2) bad.virtual_handler_address = bad.dos_handler_address;
    if (i == 3) bad.virtual_control_address = bad.handler_address;
    DazeKvmTransitionReservedRange reserved = {.address = 0x800, .size = 32};
    if (i == 4) {
      plan.reserved_ranges[0] = reserved;
      plan.reserved_range_count = 1;
    }
    assert(!plan_entry_layout(&plan, &bad, &virtual_artifacts, NULL, NULL, NULL, NULL, writes,
                              &output, 0, 0x1000));
    plan.reserved_range_count = 0;
  }
  uint8_t guest[0x1000] = {0};
  guest[virtual_gate.virtual_control_address] = 2;
  DazeKvmCommandOwnerHandoff owner = {.machine = {.guest = guest, .guest_size = sizeof(guest)}};
  DazeDpmiProcessState dpmi = {0};
  DazeKvmCommandOwnerInput input = {.state = &dpmi};
  DazeKvmDpmiEntryResult boundary = {0};
  DazeKvmCommandOwnerResult result = {0};
  assert(dispatch_boundaries(&owner, &input, NULL, NULL, NULL, &virtual_gate, NULL, NULL, NULL,
                             NULL, &boundary, &result) == DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED);
}

int main(void) {
  request_capture_contract();
  state_capture_contract();
  protected_reply_contract();
  handoff_contract();
  transition_write_contract();
  puts("KVM owner boundary codecs: passed");
  return 0;
}
