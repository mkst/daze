#include "legacy_exception.c"

#include <limits.h>
#include <stdio.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "legacy boundary failed at %d\n", __LINE__);                                 \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static void instruction_inputs(void) {
  uint8_t guest[0x8000] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .vcpu = INT_MAX};
  struct kvm_sregs s = {.gdt = {.base = 0x1000, .limit = 0x100},
                        .ldt = {.base = 0x2000, .limit = 0x100, .present = 1},
                        .ds = {.base = 0x5000, .limit = 0xff}};
  daze_dpmi_descriptor_encode(guest + 0x1008, 0x3000, 0xff, 0x9a, 0);
  daze_dpmi_descriptor_encode(guest + 0x2010, 0x4000, 0xff, 0x1a, 0);
  const uint8_t call[] = {0x9a, 0, 0, 0x14, 0}; /* call far 0014h:0000 */
  memcpy(guest + 0x3000, call, sizeof(call));
  uint16_t length = 0;
  CHECK(instruction(&machine, &s, 8, 0, 0x14, &length) && length == 5);
  for (int kind = 0; kind < 13; ++kind) {
    struct kvm_sregs bad = s;
    uint8_t saved_code[8], saved_target[8];
    memcpy(saved_code, guest + 0x1008, 8);
    memcpy(saved_target, guest + 0x2010, 8);
    uint16_t cs = 8, ip = 0, error = 0x14;
    size_t saved_size = machine.guest_size;
    switch (kind) {
    case 0:
      cs = 0;
      break;
    case 1:
      bad.gdt.limit = 14;
      break;
    case 2:
      guest[0x100d] &= 0x7f;
      break;
    case 3:
      guest[0x100d] &= 0xef;
      break;
    case 4:
      guest[0x100d] = 0x92;
      break;
    case 5:
      guest[0x100e] |= 0x40;
      break;
    case 6:
      ip = 0x100;
      break;
    case 7:
      machine.guest_size = 0x3004;
      break;
    case 8:
      bad.ldt.present = 0;
      break;
    case 9:
      guest[0x2015] |= 0x80;
      break;
    case 10:
      guest[0x2015] &= 0xef;
      break;
    case 11:
      error = 0x1c;
      break;
    case 12:
      guest[0x1008] = 4;
      guest[0x1009] = 0;
      break;
    }
    CHECK(!instruction(&machine, &bad, cs, ip, error, &length));
    memcpy(guest + 0x1008, saved_code, 8);
    memcpy(guest + 0x2010, saved_target, 8);
    machine.guest_size = saved_size;
  }
  struct kvm_segment decoded = {.base = 0xabcdef};
  struct kvm_sregs bad = s;
  bad.gdt.base = UINT64_C(0x100000000);
  CHECK(!read_segment(&machine, &bad, 8, &decoded) && decoded.base == 0xabcdef);
  bad.gdt.base = sizeof(guest) - 8;
  CHECK(!read_segment(&machine, &bad, 8, &decoded));
  daze_dpmi_descriptor_encode(guest + 0x1008, 0x12345000, 0xfffff, 0x9a, 0x08);
  CHECK(read_segment(&machine, &s, 8, &decoded));
  CHECK(decoded.base == 0x12345000 && decoded.limit == UINT32_MAX && decoded.g == 1);
  daze_dpmi_descriptor_encode(guest + 0x1008, 0x3000, 0xff, 0x9a, 0);
  const uint8_t indirect[] = {0xff, 0x1e, 0x20, 0}; /* call far [0020h] */
  memcpy(guest + 0x3000, indirect, sizeof(indirect));
  daze_write_u16(guest + 0x5022, 0x14);
  CHECK(instruction(&machine, &s, 8, 0, 0x14, &length) && length == 4);
  bad = s;
  bad.ds.limit = 0x22;
  CHECK(!instruction(&machine, &bad, 8, 0, 0x14, &length));
  bad = s;
  bad.ds.base = sizeof(guest) - 0x22;
  CHECK(!instruction(&machine, &bad, 8, 0, 0x14, &length));
  const uint8_t rejected[][3] = {{0xff, 0x1f, 0},    {0x26, 0xc5, 0x3f}, {0x26, 0xc4, 0x3e},
                                 {0x26, 0xc4, 0x3f}, {0xcb, 0, 0},       {0xca, 0, 0},
                                 {0x90, 0, 0}};
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
    memcpy(guest + 0x3000, rejected[i], 3);
    CHECK(!instruction(&machine, &s, 8, 0, 0x14, &length));
  }
}

static void boundary_inputs(void) {
  uint8_t guest[0x2000];
  memset(guest, 0xa5, sizeof(guest));
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .vcpu = INT_MAX};
  DazeKvmProtectedGateLayout gate = {.handler_selector = 0x50,
                                     .handler_address = 0x1000,
                                     .legacy_np_capture_address = 0x1400,
                                     .idt_address = 0x800,
                                     .idt_limit = 0x7ff};
  for (int kind = 0; kind < 8; ++kind) {
    DazeKvmProtectedGateLayout bad = gate;
    if (kind == 1) machine.guest = NULL;
    if (kind == 3) bad.handler_selector = 8;
    if (kind == 4) bad.legacy_np_capture_address++;
    if (kind == 5) bad.idt_limit = 94;
    if (kind == 6) machine.guest_size = 0x1406;
    if (kind == 7) bad.idt_address = 0x1fa1;
    CHECK(!daze_kvm_legacy_exception_install(kind == 0 ? NULL : &machine, kind == 2 ? NULL : &bad));
    CHECK(guest[0x1400] == 0xa5 && guest[0x858] == 0xa5);
    machine.guest = guest;
    machine.guest_size = sizeof(guest);
  }
  CHECK(daze_kvm_legacy_exception_install(&machine, &gate));
  CHECK(guest[0x1400] == 0x66 && guest[0x1404] == 0xe6 && guest[0x1406] == 0xf4);
  CHECK(daze_read_u16(guest + 0x858) == 0x400 && daze_read_u16(guest + 0x85a) == 0x60 &&
        guest[0x85d] == 0x86);
  DazeKvmLegacyExceptionState state = {0};
  CHECK(daze_kvm_legacy_exception_rearm(&machine, &state));
  CHECK(!daze_kvm_legacy_exception_rearm(NULL, &state));
  CHECK(!daze_kvm_legacy_exception_rearm(&machine, NULL));
  state.depth = DAZE_KVM_LEGACY_MAX_DEPTH + 1;
  CHECK(!daze_kvm_legacy_exception_rearm(&machine, &state));
  state.depth = 1;
  CHECK(!daze_kvm_legacy_exception_rearm(&machine, &state));
  state.depth = 0;
  DazeDpmiProcessState process = {0};
  DazeKvmDpmiEntryResult b = {0};
  for (int kind = 0; kind < 6; ++kind) {
    if (kind == 5) state.depth = DAZE_KVM_LEGACY_MAX_DEPTH + 1;
    CHECK(daze_kvm_legacy_exception_boundary(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &gate,
                                             kind == 2 ? NULL : &process, kind == 3 ? NULL : &state,
                                             kind == 4 ? NULL : &b) == -1);
    state.depth = 0;
  }
  DazeKvmDpmiEntryResult capture = {.cs_base = 0x1000,
                                    .rip = 0x404,
                                    .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                                    .pio_port = DAZE_PORT_GATE,
                                                    .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                                                    .pio_size = 1,
                                                    .pio_count = 1,
                                                    .pio_value_present = 1,
                                                    .pio_value = DAZE_KVM_LEGACY_NP_MARKER}};
  for (int kind = 0; kind < 8; ++kind) {
    b = capture;
    switch (kind) {
    case 0:
      b.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
      break;
    case 1:
      b.observation.pio_port++;
      break;
    case 2:
      b.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_IN;
      break;
    case 3:
      b.observation.pio_size = 2;
      break;
    case 4:
      b.observation.pio_count = 2;
      break;
    case 5:
      b.observation.pio_value_present = 0;
      break;
    case 6:
      b.observation.pio_value++;
      break;
    case 7:
      b.rip++;
      break;
    }
    DazeKvmDpmiEntryResult before = b;
    CHECK(daze_kvm_legacy_exception_boundary(&machine, &gate, &process, &state, &b) == 0);
    CHECK(memcmp(&before, &b, sizeof(b)) == 0 && state.depth == 0);
  }
  b = capture;
  CHECK(daze_kvm_legacy_exception_boundary(&machine, &gate, &process, &state, &b) == -1 &&
        state.depth == 0);
  state.depth = 1;
  state.deliveries[0] =
    (DazeKvmLegacyExceptionDelivery){.return_linear = 0x3010, .frame_sp = 0xff0};
  DazeKvmDpmiEntryResult returning = {.cs_base = 0x3000,
                                      .rip = 0x10,
                                      .ss = DAZE_SEL_LOCKED_STACK,
                                      .sp = 0xff4,
                                      .observation = {.raw_exit_reason = KVM_EXIT_DEBUG}};
  for (int kind = 0; kind < 4; ++kind) {
    b = returning;
    if (kind == 0) b.observation.raw_exit_reason = KVM_EXIT_HLT;
    if (kind == 1) b.rip++;
    if (kind == 2) b.ss++;
    if (kind == 3) b.sp++;
    CHECK(daze_kvm_legacy_exception_boundary(&machine, &gate, &process, &state, &b) == 0 &&
          state.depth == 1);
  }
}

static void guest_return_inputs(void) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  static uint8_t guest[k_memory_size];
  DazeRunMetrics metrics = {.enabled = 1};
  DazeKvmMachine machine = {.guest = guest,
                            .guest_size = sizeof(guest),
                            .immediate_exit_supported = 1,
                            .run_metrics = &metrics};
  struct kvm_sregs s = {
    .gdt = {.base = k_dpmi_gdt_address, .limit = 0xffff},
    .ldt = {.base = k_dpmi_ldt_address, .limit = 0xffff, .present = 1},
    .ss = {.selector = 0x124, .base = 0x72000, .limit = 0xffff, .type = 3, .s = 1, .present = 1}};
  uint8_t *code = guest + k_dpmi_gdt_address + DAZE_SEL_EXCEPTION_RETURN;
  uint8_t *stack = guest + k_dpmi_ldt_address + 0x120;
  daze_dpmi_descriptor_encode(code, LOCKED_BASE, k_memory_size - LOCKED_BASE - 1, 0x9a, 4);
  daze_dpmi_descriptor_encode(stack, 0x72000, 0xffff, 0x92, 0);
  CHECK(prepare_guest_return(&machine, &s, 0x15f, 0xb4, 0xd4));
  for (unsigned kind = 0; kind < 25; ++kind) {
    DazeKvmMachine bad = machine;
    struct kvm_sregs registers = s;
    uint8_t saved_code[8], saved_stack[8];
    memcpy(saved_code, code, 8);
    memcpy(saved_stack, stack, 8);
    switch (kind) {
    case 0:
      bad.immediate_exit_supported = 0;
      break;
    case 1:
      --bad.guest_size;
      break;
    case 2:
      registers.gdt.base = 0;
      break;
    case 3:
      registers.ldt.base = 0;
      break;
    case 4:
      registers.efer = 1u << 10;
      break;
    case 5:
      registers.gdt.limit = 0x67;
      break;
    case 6:
      code[2] ^= 1;
      break;
    case 7:
      code[0] ^= 1;
      break;
    case 8:
      code[5] &= 0x7f;
      break;
    case 9:
      code[5] &= (uint8_t)~0x10;
      break;
    case 10:
      code[5] = 0x92;
      break;
    case 11:
      code[6] &= (uint8_t)~0x40;
      break;
    case 12:
      code[5] |= 0x20;
      break;
    case 13:
      registers.ldt.limit = 0x120;
      break;
    case 14:
      stack[2] ^= 1;
      break;
    case 15:
      stack[0] ^= 1;
      break;
    case 16:
      stack[6] |= 0x40;
      break;
    case 17:
      stack[5] = 0x9a;
      break;
    case 18:
      registers.ss.selector |= 3;
      break;
    case 19:
      registers.cr0 = 1u << 31;
      break;
    case 20:
      stack[5] &= 0x7f;
      break;
    case 21:
      stack[5] &= (uint8_t)~0x10;
      break;
    case 22:
      stack[5] |= 0x20;
      break;
    case 23:
      registers.ss.db = 1;
      stack[6] |= 0x40;
      break;
    case 24:
      daze_dpmi_descriptor_encode(stack, k_memory_size + 1, 0xffff, 0x92, 0);
      registers.ss.base = k_memory_size + 1;
      break;
    }
    CHECK(!prepare_guest_return(&bad, &registers, 0x15f, 0xb4, 0xd4));
    memcpy(code, saved_code, 8);
    memcpy(stack, saved_stack, 8);
  }
  CHECK(!daze_kvm_legacy_exception_guest_return(NULL));
  DazeKvmLegacyExceptionState state = {
    .depth = 1, .deliveries = {{.native_return = 1, .frame_linear = LOCKED_BASE + 0xff0}}};
  CHECK(daze_kvm_legacy_exception_rearm(&machine, &state));
  daze_kvm_legacy_exception_host_return(&machine, &state);
  CHECK(daze_read_u32(guest + k_kvm_exception_return_control + 28) == 0);
  daze_kvm_legacy_exception_host_return(NULL, &state);
  daze_kvm_legacy_exception_host_return(&machine, NULL);
  DazeKvmDpmiEntryResult b = {
    .cs = 0xb4, .ss = 0x124, .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO}};
  CHECK(!daze_kvm_legacy_exception_reconcile(NULL, &state, &b));
  CHECK(!daze_kvm_legacy_exception_reconcile(&machine, NULL, &b));
  CHECK(!daze_kvm_legacy_exception_reconcile(&machine, &state, NULL));
  CHECK(daze_kvm_legacy_exception_reconcile(&machine, &state, &b));
  CHECK(state.depth == 0 && metrics.kvm_exception_guest_returns == 1);
  state.depth = 1;
  b.cs = DAZE_SEL_EXCEPTION_RETURN;
  CHECK(!daze_kvm_legacy_exception_reconcile(&machine, &state, &b) && state.depth == 1);
  b.cs_base = LOCKED_BASE;
  b.rip = RETURN_OUT_OFFSET;
  b.observation.pio_port = DAZE_PORT_GATE;
  b.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT;
  b.observation.pio_size = b.observation.pio_count = b.observation.pio_value_present = 1;
  b.observation.pio_value = DAZE_KVM_LEGACY_RETURN_MARKER;
  CHECK(daze_kvm_legacy_exception_reconcile(&machine, &state, &b) && state.depth == 1);
  b.cs = 0x60;
  b.ss_base = 0x2000;
  b.sp = 0x80;
  b.observation.pio_value = DAZE_KVM_LEGACY_NP_MARKER;
  daze_write_u16(guest + 0x2086, DAZE_SEL_EXCEPTION_RETURN);
  CHECK(!daze_kvm_legacy_exception_reconcile(&machine, &state, &b) && state.depth == 1);
  b.ss_base = UINT32_MAX;
  CHECK(!daze_kvm_legacy_exception_reconcile(&machine, &state, &b));
  b.ss_base = 0x2000;
  daze_write_u16(guest + 0x2086, 8);
  CHECK(daze_kvm_legacy_exception_reconcile(&machine, &state, &b) && state.depth == 0);
#endif
}

static void guest_delivery_inputs(void) {
  static uint8_t guest[k_memory_size];
  DazeRunMetrics metrics = {.enabled = 1};
  DazeKvmMachine m = {.guest = guest,
                      .guest_size = sizeof(guest),
                      .immediate_exit_supported = 1,
                      .run_metrics = &metrics};
  DazeKvmProtectedGateLayout gate = {.handler_selector = DAZE_SEL_GATE_CODE,
                                     .handler_address = 0x1000,
                                     .legacy_np_capture_address = 0x1400,
                                     .idt_address = 0x800,
                                     .idt_limit = 0x7ff};
  CHECK(daze_kvm_legacy_exception_install(&m, &gate));
  uint8_t *data = delivery_control(&m);
  CHECK(data && guest[0x1400] == 0xeb && guest[0x1408] == 0xea && guest[0x1404] == 0xe6);
  CHECK(daze_read_u32(data + DELIVERY_FALLBACK) == 0x402 &&
        daze_read_u16(data + DELIVERY_FALLBACK + 4) == DAZE_SEL_GATE_ALIAS);
  daze_write_u32(data + DELIVERY_ENTERED, 3);
  daze_write_u32(data + DELIVERY_ACTIVE, 1);
  daze_write_u32(data + DELIVERY_HOST_RETURNS, 1);
  daze_write_u32(data + DELIVERY_OBSERVED, 2);
  daze_write_u32(data + DELIVERY_REPORTED, 1);
  CHECK(daze_kvm_legacy_exception_install(&m, &gate));
  CHECK(daze_read_u32(data + DELIVERY_ENTERED) == 3 && daze_read_u32(data + DELIVERY_ACTIVE) == 1);
  uint8_t *frame = guest + LOCKED_BASE + k_dpmi_exception_locked_stack_sp;
  uint8_t *control = guest + k_kvm_exception_return_control;
  daze_write_u32(frame, 0xa0ee00);
  daze_write_u16(control, 0x15f);
  daze_write_u16(control + 2, 0xb4);
  daze_write_u16(control + 4, 0xd4);
  daze_write_u32(data + DELIVERY_RETURN_LINEAR, 0x6115f);
  DazeKvmLegacyExceptionState state = {0};
  DazeKvmDpmiEntryResult b = {
    .cs = 8, .ss = DAZE_SEL_LOCKED_STACK, .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO}};
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) && state.depth == 1);
  CHECK(state.deliveries[0].guest_delivery && state.deliveries[0].return_linear == 0x6115f &&
        state.deliveries[0].return_ip == 0x15f && state.deliveries[0].selector == 0xd4 &&
        metrics.kvm_exception_guest_deliveries == 1 && !metrics.kvm_exception_guest_returns);
  daze_write_u32(frame, 0);
  b.cs = 0xb4;
  b.ss = 0x124;
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) && !state.depth &&
        metrics.kvm_exception_guest_returns == 1);
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) &&
        metrics.kvm_exception_guest_returns == 1);
  daze_write_u32(data + DELIVERY_ENTERED, 10);
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) &&
        metrics.kvm_exception_guest_deliveries == 8 && metrics.kvm_exception_guest_returns == 8);
  metrics.enabled = 0;
  daze_write_u32(data + DELIVERY_ENTERED, 11);
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  metrics.enabled = 1;
  daze_write_u32(data + DELIVERY_ENTERED, 12);
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) &&
        metrics.kvm_exception_guest_returns == 9);
  daze_write_u32(data + DELIVERY_ACTIVE, 0);
  daze_write_u32(data + DELIVERY_HOST_RETURNS, 0);
  daze_write_u32(data + DELIVERY_ENTERED, 1);
  daze_write_u32(data + DELIVERY_OBSERVED, UINT32_MAX - 1);
  daze_write_u32(data + DELIVERY_REPORTED, UINT32_MAX - 1);
  metrics = (DazeRunMetrics){.enabled = 1};
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) &&
        metrics.kvm_exception_guest_deliveries == 3 && metrics.kvm_exception_guest_returns == 3);
  b.cs = DAZE_SEL_GATE_CODE;
  b.rip = k_kvm_exception_delivery_linear;
  CHECK(!daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  b.rip = k_kvm_exception_delivery_control;
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  b.rip = k_kvm_exception_delivery_linear - 1;
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  b.cs = 0x60;
  daze_write_u32(data + DELIVERY_ACTIVE, 2);
  CHECK(!daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  daze_write_u32(data + DELIVERY_ACTIVE, 1);
  daze_write_u32(frame, 0xa0ee00);
  state.depth = 1;
  state.deliveries[0].native_return = 0;
  CHECK(!daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  state.depth = 0;
  b.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_OTHER;
  CHECK(!daze_kvm_legacy_exception_reconcile(&m, &state, &b) && state.depth == 1);
  b.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG;
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  daze_write_u32(data + DELIVERY_ACTIVE, 0);
  state.depth = 0;
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  b.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO;
  b.observation.pio_value_present = 1;
  b.observation.pio_value = DAZE_KVM_LEGACY_NP_MARKER;
  b.ss_base = 0x2000;
  b.sp = 0x80;
  daze_write_u16(guest + 0x2086, DAZE_SEL_GATE_CODE);
  CHECK(!daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  daze_write_u16(guest + 0x2086, DAZE_SEL_EXCEPTION_RETURN);
  CHECK(!daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  daze_write_u16(guest + 0x2086, 8);
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  b.ss_base = UINT32_MAX;
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b));
  daze_write_u32(data + DELIVERY_ENTERED, 5);
  daze_write_u32(data + DELIVERY_HOST_RETURNS, 0);
  daze_write_u32(data + DELIVERY_OBSERVED, 4);
  daze_write_u32(data + DELIVERY_REPORTED, 4);
  daze_write_u32(data + DELIVERY_ACTIVE, 1);
  state = (DazeKvmLegacyExceptionState){.depth = 1, .deliveries = {{.native_return = 1}}};
  metrics = (DazeRunMetrics){.enabled = 1};
  b = (DazeKvmDpmiEntryResult){
    .cs = 8, .ss = DAZE_SEL_LOCKED_STACK, .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO}};
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) &&
        metrics.kvm_exception_guest_returns == 1 && metrics.kvm_exception_guest_deliveries == 1);
  CHECK(daze_kvm_legacy_exception_reconcile(&m, &state, &b) &&
        metrics.kvm_exception_guest_returns == 1);
  struct kvm_sregs s = {
    .gdt = {.base = k_dpmi_gdt_address, .limit = 0xffff},
    .ldt = {.selector = 0x30, .base = k_dpmi_ldt_address, .limit = 0xffff, .present = 1},
    .ss = {.selector = 0x124, .base = 0x72000, .limit = 0xffff, .type = 3, .s = 1, .present = 1}};
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 8, 0x10000, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + 0x30, k_dpmi_ldt_address, 0xffff, 0x82,
                              0);
  daze_dpmi_descriptor_encode(guest + k_dpmi_gdt_address + DAZE_SEL_GATE_CODE, 0, 0xfffff, 0x9a,
                              0x0c);
  uint8_t *flat = guest + k_dpmi_gdt_address + DAZE_SEL_GATE_DATA;
  daze_dpmi_descriptor_encode(flat, 0, 0xfffff, 0x92, 0x0c);
  memcpy(control + 12, "12345678", 8);
  prepare_guest_delivery(&m, &s, 8, 0x1234, 1);
  CHECK(daze_read_u32(data + DELIVERY_ENABLED) == 1 &&
        daze_read_u32(data + DELIVERY_HANDLER) == 0x1234 &&
        memcmp(data + DELIVERY_STACK_DESCRIPTOR, control + 12, 8) == 0);
  DazeDpmiProcessState process = {0};
  state.depth = 0;
  CHECK(daze_kvm_legacy_exception_boundary(&m, &gate, &process, &state, &b) == 0 &&
        !daze_read_u32(data + DELIVERY_ENABLED));
  for (unsigned kind = 0; kind < 21; ++kind) {
    struct kvm_sregs bad = s;
    uint8_t saved[8];
    memcpy(saved, flat, 8);
    uint8_t *ldt = guest + k_dpmi_gdt_address + 0x30;
    uint8_t saved_ldt[8];
    memcpy(saved_ldt, ldt, 8);
    int native = 1;
    switch (kind) {
    case 0:
      native = 0;
      break;
    case 1:
      --bad.gdt.limit;
      break;
    case 2:
      bad.ldt.present = 0;
      break;
    case 3:
      --bad.ldt.limit;
      break;
    case 4:
      bad.ss.base = LOCKED_BASE;
      break;
    case 5:
      bad.ldt.selector |= 4;
      break;
    case 6:
      bad.ldt.selector = 0;
      break;
    case 7:
      ldt[5] |= 0x10;
      break;
    case 8:
      ldt[5] = 0x81;
      break;
    case 9:
      ldt[5] &= 0x7f;
      break;
    case 10:
      ldt[2] ^= 1;
      break;
    case 11:
      ldt[0] ^= 1;
      break;
    case 12:
      flat[2] = 1;
      break;
    case 13:
      flat[0] = 1;
      break;
    case 14:
      flat[5] &= 0x7f;
      break;
    case 15:
      flat[5] &= 0xef;
      break;
    case 16:
      flat[6] &= 0xbf;
      break;
    case 17:
      flat[5] |= 0x20;
      break;
    case 18:
      flat[5] |= 0x08;
      break;
    case 19:
      bad.gdt.limit = DAZE_SEL_GATE_CODE - 1;
      break;
    case 20:
      CHECK(setenv("DAZE_KVM_LEGACY_TRACE", "1", 1) == 0);
      break;
    }
    prepare_guest_delivery(&m, &bad, 8, 0x1234, native);
    CHECK(daze_read_u32(data + DELIVERY_ENABLED) == 0);
    memcpy(flat, saved, 8);
    memcpy(ldt, saved_ldt, 8);
    if (kind == 20) CHECK(unsetenv("DAZE_KVM_LEGACY_TRACE") == 0);
  }
  prepare_guest_delivery(NULL, NULL, 0, 0, 0);
  CHECK(!delivery_control(NULL));
  m.guest_size--;
  CHECK(!delivery_control(&m));
  m.guest_size = sizeof(guest);
  m.guest = NULL;
  CHECK(!delivery_control(&m));
}

int main(void) {
  guest_delivery_inputs();
  guest_return_inputs();
  instruction_inputs();
  boundary_inputs();
  puts("legacy exception boundary: passed");
  return 0;
}
#else
int main(void) {
  CHECK(!daze_kvm_legacy_exception_install(NULL, NULL));
  CHECK(!daze_kvm_legacy_exception_rearm(NULL, NULL));
  CHECK(daze_kvm_legacy_exception_boundary(NULL, NULL, NULL, NULL, NULL) == -1);
  return 0;
}
#endif
