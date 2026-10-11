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

int main(void) {
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
